param(
    [Parameter(Mandatory)]
    [String]$DomainName,
    
    [Parameter(Mandatory)]
    [String]$AdminUsername,
    
    [Parameter(Mandatory)]
    [String]$AdminPassword,
    
    [Parameter(Mandatory)]
    [String]$DomainAdminPassword
)

# Create transcript log
Start-Transcript -Path "C:\Windows\Temp\setup-dc.log" -Append

try {
    Write-Output "Starting Domain Controller setup for domain: $DomainName"
    
    # Create secure credentials
    $AdminSecurePassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
    $AdminCreds = New-Object System.Management.Automation.PSCredential ($AdminUsername, $AdminSecurePassword)
    
    $DomainSecurePassword = ConvertTo-SecureString $DomainAdminPassword -AsPlainText -Force
    $DomainCreds = New-Object System.Management.Automation.PSCredential ("DomainAdmin", $DomainSecurePassword)

    # Install required PowerShell modules
    Write-Output "Installing required PowerShell modules..."
    $modules = @('ActiveDirectoryDsc', 'xStorage', 'xNetworking', 'xDnsServer', 'xPendingReboot')
    
    foreach ($module in $modules) {
        if (!(Get-Module -ListAvailable -Name $module)) {
            Write-Output "Installing module: $module"
            Install-Module -Name $module -Force -SkipPublisherCheck -AllowClobber
        } else {
            Write-Output "Module $module already installed"
        }
    }

    # Import required modules
    Write-Output "Importing PowerShell modules..."
    Import-Module ActiveDirectoryDsc -Force
    Import-Module xStorage -Force
    Import-Module xNetworking -Force
    Import-Module xDnsServer -Force
    Import-Module xPendingReboot -Force

    # Create DSC Configuration
    Write-Output "Creating DSC Configuration..."
    
configuration CreateADPDC 
{ 
   param 
   ( 
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$AdminCreds,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$DomainCreds,

        [Bool]$CreateForest = $true,
        [Bool]$ComplexityEnabled = $true,
        [Int]$MinPasswordLength = 8,
        [Int]$RetryCount = 20,
        [Int]$RetryIntervalSec = 30,
        [Bool]$CreateSampleUsers = $true,
        [String[]]$DNSForwarders = @('168.63.129.16')
    ) 
    
    Import-DscResource -ModuleName ActiveDirectoryDsc, xStorage, xNetworking, xDnsServer, PSDesiredStateConfiguration, xPendingReboot
    
    # Get primary network interface
    $Interface = Get-NetAdapter | Where-Object Name -Like "Ethernet*" | Select-Object -First 1
    $InterfaceAlias = $($Interface.Name)

    # Parse domain components for distinguished name paths
    $DomainDN = ($DomainName -split '\.') | ForEach-Object { "DC=$_" } | Join-String -Separator ','
    $UsersPath = "CN=Users,$DomainDN"

    Node localhost
    {
        LocalConfigurationManager 
        {
            RebootNodeIfNeeded = $true
            ConfigurationMode = 'ApplyAndAutoCorrect'
            RefreshMode = 'Push'
        }

        # Install DNS Service
        WindowsFeature DNS 
        { 
            Ensure = "Present" 
            Name = "DNS"		
        }

        # Install DNS Management Tools
        WindowsFeature DnsTools
	    {
	        Ensure = "Present"
            Name = "RSAT-DNS-Server"
            DependsOn = "[WindowsFeature]DNS"
	    }

        # Configure DNS to use localhost
        xDnsServerAddress DnsServerAddr
        { 
            Address        = '127.0.0.1' 
            InterfaceAlias = $InterfaceAlias
            AddressFamily  = 'IPv4'
	        DependsOn = "[WindowsFeature]DNS"
        }

        # Configure DNS Forwarders (Azure DNS by default)
        xDnsServerForwarder DnsForwarder
        {
            IsSingleInstance = 'Yes'
            IPAddresses = $DNSForwarders
            DependsOn = "[WindowsFeature]DNS"
        }

        # Wait for additional data disk
        xWaitforDisk Disk2
        {
            DiskId = 2
            RetryIntervalSec = $RetryIntervalSec
            RetryCount = $RetryCount
        }

        # Configure data disk for AD database
        xDisk ADDataDisk 
        {
            DiskId = 2
            DriveLetter = "F"
            DependsOn = "[xWaitForDisk]Disk2"
        }

        # Install Active Directory Domain Services
        WindowsFeature ADDSInstall 
        { 
            Ensure = "Present" 
            Name = "AD-Domain-Services"
	        DependsOn = "[WindowsFeature]DNS" 
        } 

        # Install AD Management Tools
        WindowsFeature ADDSTools
        {
            Ensure = "Present"
            Name = "RSAT-ADDS-Tools"
            DependsOn = "[WindowsFeature]ADDSInstall"
        }

        # Install AD Admin Center
        WindowsFeature ADAdminCenter
        {
            Ensure = "Present"
            Name = "RSAT-AD-AdminCenter"
            DependsOn = "[WindowsFeature]ADDSInstall"
        }

        # Install Group Policy Management
        WindowsFeature GPMC
        {
            Ensure = "Present"
            Name = "GPMC"
            DependsOn = "[WindowsFeature]ADDSInstall"
        }

        # Create the Active Directory Domain
        ADDomain FirstDS 
        {
            DomainName = $DomainName
            Credential = $AdminCreds
            SafemodeAdministratorPassword = $AdminCreds
            DatabasePath = "F:\NTDS"
            LogPath = "F:\NTDS"
            SysvolPath = "F:\SYSVOL"
            ForestMode = '2016'
            DomainMode = '2016'
	        DependsOn = @("[xDisk]ADDataDisk", "[WindowsFeature]ADDSInstall")
        }

        # Configure Default Password Policy
        ADDomainDefaultPasswordPolicy 'DefaultPasswordPolicy'
        {
            DomainName = $DomainName
            ComplexityEnabled = $ComplexityEnabled
            MinPasswordLength = $MinPasswordLength
            MaxPasswordAge = '90.00:00:00'
            MinPasswordAge = '1.00:00:00'
            PasswordHistoryCount = 12
            DependsOn = '[ADDomain]FirstDS'
        }

        # Create sample users and groups
        if ($CreateSampleUsers) 
        {
            # Marketing Users
            ADUser 'MarketingUser1'
            {
                Ensure     = 'Present'
                UserName   = 'MarketingUser1'
                Password   = $DomainCreds
                PasswordNeverResets = $false
                PasswordNeverExpires = $false
                DomainName = $DomainName
                Path       = $UsersPath
                DisplayName = 'Marketing User 1'
                Description = 'Sample Marketing User 1'
                DependsOn = '[ADDomainDefaultPasswordPolicy]DefaultPasswordPolicy'
            }

            ADUser 'MarketingUser2'
            {
                Ensure     = 'Present'
                UserName   = 'MarketingUser2'
                Password   = $DomainCreds
                PasswordNeverResets = $false
                PasswordNeverExpires = $false
                DomainName = $DomainName
                Path       = $UsersPath
                DisplayName = 'Marketing User 2'
                Description = 'Sample Marketing User 2'
                DependsOn = '[ADDomainDefaultPasswordPolicy]DefaultPasswordPolicy'
            }

            # Marketing Group
            ADGroup 'MarketingGroup'
            {
                GroupName   = 'Marketing'
                GroupScope  = 'Global'
                Ensure      = 'Present'
                Path        = $UsersPath
                Description = 'Marketing Department Group'
                MembershipAttribute = 'DistinguishedName'
                MembersToInclude = @(
                    "CN=MarketingUser1,$UsersPath",
                    "CN=MarketingUser2,$UsersPath"
                )
                DependsOn = @('[ADUser]MarketingUser1','[ADUser]MarketingUser2')
            }

            # Sales Users
            ADUser 'SalesUser1'
            {
                Ensure     = 'Present'
                UserName   = 'SalesUser1'
                Password   = $DomainCreds
                PasswordNeverResets = $false
                PasswordNeverExpires = $false
                DomainName = $DomainName
                Path       = $UsersPath
                DisplayName = 'Sales User 1'
                Description = 'Sample Sales User 1'
                DependsOn = '[ADDomainDefaultPasswordPolicy]DefaultPasswordPolicy'
            }

            ADUser 'SalesUser2'
            {
                Ensure     = 'Present'
                UserName   = 'SalesUser2'
                Password   = $DomainCreds
                PasswordNeverResets = $false
                PasswordNeverExpires = $false
                DomainName = $DomainName
                Path       = $UsersPath
                DisplayName = 'Sales User 2'
                Description = 'Sample Sales User 2'
                DependsOn = '[ADDomainDefaultPasswordPolicy]DefaultPasswordPolicy'
            }

            # Sales Group
            ADGroup 'SalesGroup'
            {
                GroupName   = 'Sales'
                GroupScope  = 'Global'
                Ensure      = 'Present'
                Path        = $UsersPath
                Description = 'Sales Department Group'
                MembershipAttribute = 'DistinguishedName'
                MembersToInclude = @(
                    "CN=SalesUser1,$UsersPath",
                    "CN=SalesUser2,$UsersPath"
                )
                DependsOn = @('[ADUser]SalesUser1','[ADUser]SalesUser2')
            }
        }

        # Ensure pending reboot is handled
        xPendingReboot Reboot1
        { 
            Name = "RebootServer"
            DependsOn = "[ADDomain]FirstDS"
        }
    }
}

    # Compile the configuration
    Write-Output "Compiling DSC Configuration..."
    try {
        CreateADPDC -DomainName $DomainName -AdminCreds $AdminCreds -DomainCreds $DomainCreds -OutputPath "C:\DSC"

        # Apply the configuration
        Write-Output "Applying DSC Configuration..."
        Set-DscLocalConfigurationManager -Path "C:\DSC" -Verbose -Force
        Start-DscConfiguration -Path "C:\DSC" -Wait -Verbose -Force
        
        Write-Output "DSC Configuration applied successfully"
    } catch {
        Write-Warning "DSC Configuration failed: $($_.Exception.Message)"
        Write-Output "Falling back to traditional installation method..."
        
        # Fallback installation using Server Manager
        Write-Output "Installing Active Directory using Server Manager..."
        
        # Install features
        Install-WindowsFeature -Name AD-Domain-Services, DNS, RSAT-AD-Tools, RSAT-DNS-Server, GPMC -IncludeManagementTools
        
        # Initialize and format data disk
        Write-Output "Preparing data disk..."
        $disk = Get-Disk | Where-Object PartitionStyle -eq 'RAW' | Select-Object -First 1
        if ($disk) {
            Initialize-Disk -Number $disk.Number -PartitionStyle GPT
            New-Partition -DiskNumber $disk.Number -DriveLetter F -UseMaximumSize
            Format-Volume -DriveLetter F -FileSystem NTFS -NewFileSystemLabel "AD_DATA" -Confirm:$false
        }
        
        # Create AD forest
        Write-Output "Creating Active Directory forest..."
        Install-ADDSForest `
            -DomainName $DomainName `
            -DomainMode "2016" `
            -ForestMode "2016" `
            -DatabasePath "F:\NTDS" `
            -LogPath "F:\NTDS" `
            -SysvolPath "F:\SYSVOL" `
            -SafeModeAdministratorPassword $AdminCreds.Password `
            -CreateDnsDelegation:$false `
            -InstallDns:$true `
            -NoRebootOnCompletion:$false `
            -Force:$true
            
        Write-Output "Traditional installation completed"
    }

    # Wait for domain to be ready
    Write-Output "Waiting for domain to be fully configured..."
    do {
        Start-Sleep -Seconds 30
        $domain = Get-ADDomain -ErrorAction SilentlyContinue
    } while ($domain -eq $null)

    Write-Output "Domain Controller setup completed successfully!"
    Write-Output "Domain: $($domain.DNSRoot)"
    Write-Output "Domain SID: $($domain.DomainSID)"

} catch {
    Write-Error "Error during Domain Controller setup: $($_.Exception.Message)"
    Write-Error "Full error: $_"
    exit 1
} finally {
    Stop-Transcript
}
