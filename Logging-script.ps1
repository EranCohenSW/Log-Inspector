Write-Host "Performing New Installs Check For Services And Scheduled Tasks:" -foregroundcolor "green"
Write-Host 
Write-Host "#################################Services Check########################################" -foregroundcolor "blue"
$Events=Get-WinEvent –FilterHashtable @{logname=’Security’;id='4697'}
$FlagAny=$false
ForEach ($Event in $Events) {                      
    $Flag=$false
    $EventXML = [xml]$Event.ToXml()       
    If($EventXML.Event.EventData.Data[4].'#text' -like "0x1" -or
       $EventXML.Event.EventData.Data[6].'#text' -like "0x2" -or
       $EventXML.Event.EventData.Data[6].'#text' -like "0x8"){                   #Service Type Check
        $Flag=$true
        }            
    If($EventXML.Event.EventData.Data[7].'#text' -like "0" -or
       $EventXML.Event.EventData.Data[7].'#text' -like "1" -or
       $EventXML.Event.EventData.Data[7].'#text' -like "4"){                     #Service Start Type Check
        $Flag=$true
        }
    If(!$EventXML.Event.EventData.Data[8].'#text'.Contains("LocalSystem") -and
    !$EventXML.Event.EventData.Data[8].'#text'.Contains("LocalService") -and
    !$EventXML.Event.EventData.Data[8].'#text'.Contains("NetworkService")){        #Service Account Check    
        $Flag=$true
        }
    If($Flag){
        Write-Host 
        Write-Host "Services:         New Suspicious Service Installed:" -foregroundcolor "red"
        $Event | Format-List 
        $Flag=$false
        $FlagAny=$true
        }         
}      
If(!$FlagAny){
    Write-Host "Services:         No New Suspicious Services installed" -foregroundcolor "green"
}
Write-Host "################################End Services Check######################################" -foregroundcolor "blue"

Write-Host
Write-Host
Write-Host "#################################Scheduled tasks check##################################" -foregroundcolor "blue"
$Events=Get-WinEvent –FilterHashtable @{logname=’Security’;id='4698'}
$FlagAny=$false
ForEach ($Event in $Events) {                      
    $Flag=$false
    $EventXML = [xml]$Event.ToXml()
    If($EventXML.Event.EventData.Data[4].'#text'.StartsWith("\")){                               #Task Scheduler Library Checkc
        $Flag=$true       
        }        
    If($EventXML.Event.EventData.Data[5].'#text'.Contains("<LogonType>Password</LogonType>")){   #Task Content Check
        $Flag=$true
        }                             
    If($Flag){
        Write-Host 
        Write-Host "Schedual Tasks:   New Suspicious Scheduled Tasks Installed:" -foregroundcolor "red"
        $Event | Format-List 
        $Flag=$false
        $FlagAny=$true
        }         
}      
If(!$FlagAny){
    Write-Host "Schedual Tasks:   No New Suspicious Scheduled Tasks Installed" -foregroundcolor "green"
}
Write-Host "#################################End Scheduled tasks check################################" -foregroundcolor "blue"