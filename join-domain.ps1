param(
    [Parameter(Mandatory)]
    [String]$DomainName,
    
    [Parameter(Mandatory)]
    [String]$DomainController,
    
    [Parameter(Mandatory)]
    [String]$AdminUsername,
    
    [Parameter(Mandatory)]
    [String]$DomainAdminPassword
)

# Create transcript log
Start-Transcript -Path "C:\Windows\Temp\join-domain.log" -Append

try {
    Write-Output "Starting domain join process for server..."
    Write-Output "Domain: $DomainName"
    Write-Output "Domain Controller: $DomainController"

    # Create domain credentials
    $DomainSecurePassword = ConvertTo-SecureString $DomainAdminPassword -AsPlainText -Force
    $DomainCreds = New-Object System.Management.Automation.PSCredential ("$DomainName\$AdminUsername", $DomainSecurePassword)

    # Wait for domain controller to be available
    Write-Output "Waiting for domain controller to be available..."
    $timeout = 1800 # 30 minutes
    $timer = 0
    $dcReady = $false

    do {
        try {
            # Test DNS resolution
            $dcIP = Resolve-DnsName -Name $DomainName -ErrorAction SilentlyContinue
            if ($dcIP) {
                # Test LDAP connectivity
                $ldapTest = Test-NetConnection -ComputerName $DomainController -Port 389 -WarningAction SilentlyContinue
                if ($ldapTest.TcpTestSucceeded) {
                    Write-Output "Domain controller is responding on LDAP port"
                    $dcReady = $true
                } else {
                    Write-Output "Domain controller not yet responding on LDAP port, waiting..."
                }
            } else {
                Write-Output "Cannot resolve domain name, waiting..."
            }
        } catch {
            Write-Output "Error testing domain controller connectivity: $($_.Exception.Message)"
        }

        if (!$dcReady) {
            Start-Sleep -Seconds 30
            $timer += 30
        }
    } while (!$dcReady -and $timer -lt $timeout)

    if (!$dcReady) {
        throw "Timeout waiting for domain controller to become available"
    }

    # Additional wait to ensure domain is fully operational
    Write-Output "Domain controller detected, waiting additional time for full operational status..."
    Start-Sleep -Seconds 120

    # Configure DNS client settings
    Write-Output "Configuring DNS client settings..."
    $adapter = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1
    Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses $DomainController, "168.63.129.16"

    # Clear DNS cache
    Clear-DnsClientCache

    # Verify DNS resolution
    Write-Output "Verifying DNS resolution..."
    $dnsTest = Resolve-DnsName -Name $DomainName -ErrorAction SilentlyContinue
    if (!$dnsTest) {
        throw "Cannot resolve domain name after DNS configuration"
    }

    # Install AD management tools
    Write-Output "Installing Active Directory management tools..."
    try {
        Install-WindowsFeature -Name "RSAT-AD-Tools" -IncludeAllSubFeature -IncludeManagementTools
        Write-Output "AD management tools installed successfully"
    } catch {
        Write-Warning "Failed to install AD management tools: $($_.Exception.Message)"
        # Continue anyway as this is not critical for domain join
    }

    # Join the domain
    Write-Output "Joining domain: $DomainName"
    
    # Retry domain join operation
    $joinSuccess = $false
    $maxRetries = 5
    $retryCount = 0

    do {
        try {
            Add-Computer -DomainName $DomainName -Credential $DomainCreds -Force -Restart
            $joinSuccess = $true
            Write-Output "Successfully joined domain. Server will restart automatically."
        } catch {
            $retryCount++
            Write-Warning "Domain join attempt $retryCount failed: $($_.Exception.Message)"
            
            if ($retryCount -lt $maxRetries) {
                Write-Output "Retrying domain join in 60 seconds..."
                Start-Sleep -Seconds 60
                
                # Refresh network configuration
                ipconfig /flushdns
                ipconfig /registerdns
            } else {
                throw "Failed to join domain after $maxRetries attempts: $($_.Exception.Message)"
            }
        }
    } while (!$joinSuccess -and $retryCount -lt $maxRetries)

} catch {
    Write-Error "Error during domain join: $($_.Exception.Message)"
    Write-Error "Full error: $_"
    
    # Additional diagnostics
    Write-Output "=== Diagnostics ==="
    Write-Output "Network configuration:"
    Get-NetIPConfiguration | Format-Table -AutoSize
    
    Write-Output "DNS configuration:"
    Get-DnsClientServerAddress | Format-Table -AutoSize
    
    Write-Output "DNS resolution test:"
    try { Resolve-DnsName -Name $DomainName } catch { Write-Output "DNS resolution failed: $_" }
    
    Write-Output "Network connectivity test:"
    try { Test-NetConnection -ComputerName $DomainController -Port 389 } catch { Write-Output "Network test failed: $_" }
    
    exit 1
} finally {
    Stop-Transcript
}