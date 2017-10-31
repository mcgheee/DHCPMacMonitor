<#
Monitor DHCP Servers for leases assigned to a list of MACs
By: Erick McGhee - https://github.com/mcgheee
#>

#Initialize Vars
[System.Collections.ArrayList]$MACs = @() #Array of Mac addresses to search for
$results = $null #Variable to hold DHCPServerv4Lease objects
$findings = "MACAddress,HostName,IPAddress,AddressState,LeaseGrantedTime,LeaseExpiryTime,DHCPServer" #String variable that stores formatted results, initialized with headers.
$DHCPServers=@("DHCP1.My.Domain","DHCP2.My.Domain","192.168.100.100") #List of Authorized DHCP Servers
$Logfile = ($PSSCriptRoot + "\Findings.csv")

#Import Macs to look for from CSV
Import-Csv ($PSSCriptRoot + "\HotMACs.csv") | ForEach-Object { $MACs += $_.MAC}

if ($MACs.Count -ge 1) {
    #Query Each DCHP Server for the MACs
    foreach ($server in $DHCPServers){$results += Get-DhcpServerv4Scope -ComputerName $server | Get-DhcpServerv4Lease -ComputerName $server -ClientId $MACs -ErrorAction SilentlyContinue -WarningAction SilentlyContinue}
}

if ($results){
    #Sort Results by MAC, add formatted values to Findings in order of the headers.
    $results | sort -Property ClientId | ForEach-Object {$findings += ("`r`n" + $_.ClientId + "," + $_.HostName + "," + $_.IPAddress + "," + $_.AddressState + "," + ($_.LeaseExpiryTime - (Get-DhcpServerv4Scope -ComputerName $_.ServerIP -ScopeId $_.ScopeId).LeaseDuration).Date + "," + $_.LeaseExpiryTime + "," + ([system.net.dns]::GetHostByAddress($_.ServerIP)).hostname)}
    $findings > $Logfile #Output Findings to Log file
    #Mail Findings to Admins
    Send-MailMessage -To "admingroup@My.Domain" -cc -From "powershell@My.Domain" -Subject "DHCP MONITORING ALERT - MACs Found" -Body $findings -SmtpServer "SMTP.My.Domain" -port 587 -Attachments $Logfile
}

Write-Host $findings
