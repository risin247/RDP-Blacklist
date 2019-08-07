function addBlacklistIP{
param(
    [String]$newIP
    )
    $NewFilter = @()
    $NewFilter += (Get-NetFirewallRule -DisplayName "RDP Blacklist" | Get-NetFirewallAddressFilter).RemoteAddress
    $NewFilter += $newIP
    Get-NetFirewallRule -DisplayName "RDP Blacklist" |Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter -RemoteAddress $NewFilter

}
function createBlackList{
param([String]$newIP)
New-NetFirewallRule -DisplayName "RDP Blacklist" `
-Description "Blocks Repeat Offending IP Addresses from accesing the RDP service" `
-Enabled True -Profile Any -Direction Inbound -Action Block -EdgeTraversalPolicy Block `
-LooseSourceMapping $False -LocalOnlyMapping $False `
-Protocol "TCP" -RemotePort "Any" -LocalPort "3389" -LocalAddress "Any" -RemoteAddress $newIP | Out-Null
}
function addNewEvents{
$sortedEvents = Get-EventLog Security -EntryType FailureAudit -After (Get-Date).AddMinutes(-5) | select TimeGenerated, @{Name="Username";Expression={$_.replacementStrings[5]}}, @{Name="IP";Expression={$_.replacementStrings[19]}} | Group-Object IP | select Name, Count, @{Name="LastSeen";Expression={($_.Group | sort TimeGenerated -Descending)[0].TimeGenerated}}    
    foreach($e in $sortedEvents){
        if($ips[$e.Name] -eq $null){
            $ips.Add($e.name ,@{
            Count = $e.count
            LastSeen = $e.LastSeen
            })
        }else{
            $ips[$e.Name].Count = ($ips[$e.Name].Count + $e.Count)
            $ips[$e.Name].LastSeen = $e.LastSeen
        }
    }
}
function trimAndBL{
    $trim = @()
    foreach($key in $ips.Keys){
        #pulls entry if exists longer than 60mins
        if($ips[$key].LastSeen -lt (get-date).AddMinutes(-60) -and ($ips[$key].Count -lt 5)){
            $trim += $key
        #adds to blacklist if count is reached, creates blacklist if no rule exists.
        }elseif($ips[$key].Count -gt 5){
            if($ruleExists){
                addBlacklistIP -newIP $key
                $trim += $key
                "Adding $key to Blacklist" | Out-File $logfile -Append -Force
            }else{
                createBlackList -newIP $key
                $trim += $key
                "Adding $key to Blacklist" | Out-File $logfile -Append -Force
            }
        }
    }
    $trim | %{$ips.Remove($_)}
}

$saveFile= "C:\Users\Public\watcher.xml"
$logfile = "C:\Users\Public\blacklist.log"



#checks to see if FW Rule Exists
$ruleExists = -not ((Get-NetFirewallRule -DisplayName "RDP Blacklist" -ErrorAction SilentlyContinue) -eq $null)
#imports list if it exists
if(test-path $saveFile){
        $ips = Import-Clixml $saveFile
    }else{
        $ips=@{}
    }

addNewEvents

trimAndBL

$ips| Export-Clixml $saveFile
