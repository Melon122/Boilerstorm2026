@{
    # =========================================================================
    # BoilerStorm 2026 / CCDC Competition Configuration (ClosedAI)
    # 100% Offline / Local - Zero External Network Calls
    # CRITICAL: NEVER contact external internet 'closedai.com'!
    # =========================================================================
    Competition = @{
        Name               = 'BoilerStorm 2026'
        Organization       = 'ClosedAI'
        CompetitionDate    = 'November 15, 2026'
        DomainFQDN         = 'closedai.com'
        DomainNetBIOS      = 'CLOSEDAI'
        LANSubnet          = '10.42.0.0/24'
        PublicSubnetPrefix = '10.100'         # Team N owns 10.100.N.0/24
        FirewallLAN        = '10.42.0.1'
        DCServerLAN        = '10.42.0.10'
        WebServerLAN       = '10.42.0.20'
        DBServerLAN        = '10.42.0.30'
        MailServerLAN      = '10.42.0.40'
        MailWebHostname    = 'mail.closedai.com'
        TeamMailbox        = 'itops@closedai.com'
        InitialAdminUser   = 'admin'          # Unscored initial admin (Changeme2026!) - rotate immediately!
        DirectorName       = 'Tomas Whelan'
        DirectorTitle      = 'Director of IT and Security'
        EndTimeLocal       = '16:00'
        StateRoot          = 'C:\CCDC_State'
        ChangeLogPath      = 'C:\CCDC_State\ChangeLog.csv'
        ScoredUsersPath    = 'C:\CCDC_State\ScoredUsers.txt'
        BlockedIPsPath     = 'C:\CCDC_State\BlockedIPs.csv'
    }

    Topology = @{
        'cai-fw01'   = @{ Role = 'Firewall';     OS = 'OPNsense';            LAN = '10.42.0.1';  WANPattern = '10.100.N.1';  HostOctet = 1;  App = 'Edge Firewall / NAT' }
        'CAI-DC01'   = @{ Role = 'DC_DNS';       OS = 'Windows Server 2025'; LAN = '10.42.0.10'; WANPattern = '10.100.N.10'; HostOctet = 10; App = 'Active Directory DS & DNS (closedai.com)' }
        'CAI-WEB01'  = @{ Role = 'IIS_Web';      OS = 'Windows Server 2022'; LAN = '10.42.0.20'; WANPattern = '10.100.N.20'; HostOctet = 20; App = 'IIS Main Website & ClosedChat' }
        'cai-db01'   = @{ Role = 'DB_DeputyApp'; OS = 'Ubuntu 26.04';        LAN = '10.42.0.30'; WANPattern = '10.100.N.30'; HostOctet = 30; App = 'Deputy App (SQL + Redis)' }
        'cai-mail01' = @{ Role = 'Mail_Server';  OS = 'Rocky Linux 10';      LAN = '10.42.0.40'; WANPattern = '10.100.N.40'; HostOctet = 40; App = 'Postfix/Dovecot + Roundcube (mail.closedai.com)' }
    }

    # 16 Possible Scored Protocols in BoilerStorm 2026
    ScoredProtocols = @(
        'HTTP', 'HTTPS', 'DNS', 'SMTP', 'IMAP', 'POP3', 'LDAP', 'SMB',
        'FTP', 'SSH', 'RDP', 'WinRM', 'SQL', 'Redis', 'IRC', 'SNMP', 'ICMP'
    )

    # Active Directory Tier-0 & Privileged Groups to audit on CAI-DC01
    Tier0Groups = @(
        'Domain Admins',
        'Enterprise Admins',
        'Schema Admins',
        'Administrators',
        'Account Operators',
        'Backup Operators',
        'Server Operators',
        'Print Operators',
        'DnsAdmins',
        'Group Policy Creator Owners',
        'Cert Publishers',
        'Key Admins',
        'Enterprise Key Admins',
        'Remote Desktop Users',
        'Remote Management Users'
    )

    # Services that MUST NEVER be stopped, disabled, or tampered with
    ProtectedServices = @(
        # Out-of-scope competition infrastructure (PENALTY IF TOUCHED!)
        'SplunkForwarder',
        'splunkd',
        'Splunkd',

        # Core Windows OS stability
        'RpcSs',
        'RpcEptMapper',
        'DcomLaunch',
        'LSM',
        'SamSs',
        'EventLog',
        'MpsSvc',
        'BFE',
        'WinDefend',
        'WdNisSvc',
        'SecurityHealthService',
        'CryptSvc',
        'Dhcp',
        'Dnscache',
        'nsi',
        'LanmanWorkstation',
        'LanmanServer',
        'ProfSvc',
        'Schedule',
        'Winmgmt',
        'gpsvc',
        'PlugPlay',
        'Power',
        'SystemEventsBroker',
        'CoreMessagingRegistrar',
        'BrokerInfrastructure',
        'W32Time',

        # Active Directory / Domain Controller critical services
        'NTDS',
        'DNS',
        'Kdc',
        'ADWS',
        'DFSR',
        'Netlogon',
        'IsmServ',

        # IIS / Web critical services (protected when installed/running)
        'W3SVC',
        'WAS',
        'IISADMIN'
    )

    # Services safe to disable across Windows Server 2025 DC & Server 2022 Member
    # (Dynamic port-listener check skips any service actively serving a scored port!)
    UnneededServicesCommon = @(
        'TlntSvr',
        'simptcp',
        'WebClient',
        'SNMP',
        'SNMPTRAP',
        'SSDPSRV',
        'upnphost',
        'RemoteRegistry',
        'RemoteAccess',
        'RasAuto',
        'RasMan',
        'Browser',
        'lltdsvc',
        'PNRPsvc',
        'p2psvc',
        'p2pimsvc',
        'PNRPAutoReg',
        'MapsBroker',
        'lfsvc',
        'Fax',
        'irmon',
        'SharedAccess',
        'icssvc',
        'WMPNetworkSvc',
        'WerSvc',
        'wercplsupport',
        'DiagTrack',
        'dmwappushservice',
        'XblAuthManager',
        'XblGameSave',
        'XboxGipSvc',
        'XboxNetApiSvc',
        'xbgm',
        'bthserv',
        'BTAGService',
        'PhoneSvc',
        'RetailDemo',
        'WalletService',
        'Wisvc',
        'PushToInstall',
        'RpcLocator',
        'LxssManager',
        'MSiSCSI',
        'CscService'
    )

    # Optional features safe to remove/disable on both DC and IIS (with -NoRestart)
    UnneededWindowsFeatures = @(
        'SMB1Protocol',
        'SMB1Protocol-Client',
        'SMB1Protocol-Server',
        'TelnetClient',
        'TelnetServer',
        'TFTP',
        'MicrosoftWindowsPowerShellV2',
        'MicrosoftWindowsPowerShellV2Root'
    )

    # Known unauthorized RMM, tunneling, offensive, P2P, and miner keywords (Audit/Alert - Legal Hold safe!)
    SuspiciousSoftwarePatterns = @(
        'anydesk', 'teamviewer', 'rustdesk', 'screenconnect', 'connectwise',
        'meshagent', 'meshcentral', 'splashtop', 'tightvnc', 'ultravnc', 'realvnc',
        'ammyy', 'supremo', 'logmein', 'gotomypc', 'dameware', 'nomachine',
        'ngrok', 'chisel', 'ligolo', 'frpc', 'frps', 'cloudflared', 'tailscale',
        'zerotier', 'socat', 'plink', 'netcat', 'ncat', 'nc64', 'powercat',
        'mimikatz', 'rubeus', 'sharphound', 'bloodhound', 'certify', 'seatbelt',
        'whisker', 'nanodump', 'lazagne', 'procdump', 'psexec', 'paexec',
        'cain', 'ophcrack', 'hashcat', 'john', 'hydra', 'metasploit', 'meterpreter',
        'sliver', 'havoc', 'cobalt', 'bruteratel', 'covenant', 'empire',
        'xmrig', 'minerd', 'nbminer', 't-rex', 'phoenixminer',
        'bittorrent', 'utorrent', 'qbittorrent', 'deluge',
        'wireshark', 'nmap', 'zenmap', 'masscan', 'responder', 'inveigh'
    )

    # Default system accounts never to delete or blindly rotate as normal users
    SystemAccountExclusions = @(
        'Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount',
        'krbtgt', 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE',
        'IUSR', 'IWAM', 'sshd', 'SplunkForwarder'
    )
}
