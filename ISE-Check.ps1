Param(
    [switch]$Console = $false,         #--[ Set to true to enable local console result display. Defaults to false ]--
    [switch]$Debug = $False            #--[ Generates extra console output for debugging.  Defaults to false ]--
    )

<#==============================================================================
         File Name : ISE-Check.ps1
   Original Author : Kenneth C. Mazie (kcmjr AT kcmjr.com)
                   : 
       Description : Inspects interface configuration on Cisco switches to validate proper
                   : configuration for Cisco ISE.
                   : 
             Notes : Normal operation is with no command line options.  If pre-stored credentials 
                   : are desired use this: https://github.com/kcmazie/CredentialsWithKey
                   : If no stored creds are found the script will prompt for them.  Edit the XML config file to list the 
                   : location of encrypted credential files and other runtime options.  This file uses the scripts name 
                   : with a ".xml" extension.  A text file located in the script folder is used to load devices.
                   : Create a flat text file named "IPlist.txt" in the script folder.  If no device list is found a single
                   : IP is prompted for.  Devices are sorted and referenced by IP address.  A folder will be created under
                   : the script folder for each IP in the device list if it doesn't already exist.  Inspection of 
                   : interface setting results are stored as a bitmap to denote the presence of (1) or lack of (0)
                   : the specific setting being checked.  The full device running config is stored with the report.
                   : Items included in the report include individual interface ISE config, TACACS settings, and RADIUS 
                   : settings.  No option exists in this version to export detected details bayond the HMTL file.
                   : A debug mode is available to display extra data to the screen.  The external XML file is used
                   : so that nothing sensitive is contained within the script itself.  Note that the "altuser" in the XML
                   : file is used to send when executed via a script editor.
                   :
      Requirements : The PoshSSH plugin is required and will (attempt) to be auto installed on each run.                   
                   : PowerShell v5 is required.
                   : 
   Option Switches : See descriptions above.
                   :
          Warnings : Nothing in this script is destructive other than the deletion of the oldest reports if over 10 exist.
                   :   
             Legal : Public Domain. Modify and redistribute freely. No rights reserved.
                   : SCRIPT PROVIDED "AS IS" WITHOUT WARRANTIES OR GUARANTEES OF 
                   : ANY KIND. USE AT YOUR OWN RISK. NO TECHNICAL SUPPORT PROVIDED.
                   : That being said, feel free to ask if you have questions...
                   :
           Credits : Code snippets and/or ideas came from too many sources to list...
                   : 
    Last Update by : Kenneth C. Mazie                                           
   Version History : v0.90 - 01-03-25 - Original edit(s)
    Change History : v1.00 - 01-09-25 - Changed method of parsing collected data from scanning the entire running config to 
                   :                    only using targeted commands.   
                   : 
                   :                  
==============================================================================#>
Clear-Host
#Requires -version 5

#--[ Variables ]---------------------------------------------------------------
$DateTime = Get-Date -Format MM-dd-yyyy_HHmmss 
$SaveCount = 10   #--[ Number of reports & configs to retain ]--
$IntColumns = 7   #--[ Total columns in interface section of HTML report ]--
$TacColumns = 4   #--[ Total columns in TACACS section of HTML report ]--
$RadColumns = 6   #--[ Total columns in RADIUS section of HTML report ]--

#==[ RUNTIME TESTING OPTION VARIATIONS ]========================================
$Console = $true
$Debug = $True
If($Debug){
    $Console = $true
}
#==============================================================================
#--[ Load PoshSSH module if not already installed ]--
if (!(Get-Module -Name posh-ssh*)) {    
    Try{  
        import-module -name posh-ssh
    }Catch{
        Write-host "-- Error loading Posh-SSH module." -ForegroundColor Red
        Write-host "Error: " $_.Error.Message  -ForegroundColor Red
        Write-host "Exception: " $_.Exception.Message  -ForegroundColor Red
    }
}

#==[ Functions ]===============================================================
Function StatusMsg ($Msg, $Color, $ExtOption){
    If ($Msg -eq "blank"){
        Write-host ""
    }ElseIf ($ExtOption.Debug){
        Write-Host "-- Script Status: $Msg" -ForegroundColor $Color
    }
}

Function SendEmail ($MessageBody,$ExtOption) { 
    $Smtp = New-Object Net.Mail.SmtpClient($ExtOption.SmtpServer,$ExtOption.SmtpPort) 
    $Email = New-Object System.Net.Mail.MailMessage  
    $Email.IsBodyHTML = $true
    $Email.From = $ExtOption.EmailSender
    If ($ExtOption.ConsoleState){  #--[ If running out of an IDE console, send only to the user for testing ]-- 
        $Email.To.Add($ExtOption.EmailAltRecipient)  
    }Else{
        $Email.To.Add($ExtOption.EmailRecipient)  
    }

    $Email.Subject = "ISE Status Report"
    $Email.Body = $MessageBody
    If ($ExtOption.Debug){
        StatusMsg "blank" "" $ExtOption
        $Msg="-- Email Debugging --" 
        StatusMsg $Msg "yellow" $ExtOption
        $Msg="Error Msg     = "+$_.Error.Message
        StatusMsg $Msg "yellow" $ExtOption
        $Msg="Exception Msg = "+$_.Exception.Message
        StatusMsg $Msg "yellow" $ExtOption
        $Msg="Local Sender  = "+$ExtOption.EmailSender
        StatusMsg $Msg "yellow" $ExtOption
        $Msg="Recipient     = "+$ExtOption.EmailRecipient
        StatusMsg $Msg "yellow" $ExtOption
        $Msg="SMTP Server   = "+$ExtOption.SmtpServer
        StatusMsg $Msg "yellow" $ExtOption
    }
    $ErrorActionPreference = "stop"
    Try {
        $Smtp.Send($Email)
        If ($ExtOption.ConsoleState){Write-Host `n"--- Email Sent ---" -ForegroundColor red }
    }Catch{
        Write-host "-- Error sending email --" -ForegroundColor Red
        Write-host "Error Msg     = "$_.Error.Message
        StatusMsg  $_.Error.Message "red" $ExtOption
        Write-host "Exception Msg = "$_.Exception.Message
        StatusMsg  $_.Exception.Message "red" $ExtOption
        Write-host "Local Sender  = "$ThisUser
        Write-host "Recipient     = "$ExtOption.EmailRecipient
        Write-host "SMTP Server   = "$ExtOption.SmtpServer
        add-content -path $psscriptroot -value  $_.Error.Message
    }
}

Function GetSSH ($TargetIP,$Command,$Credential){
    $ErrorActionPreference = "stop"
    Try{
        Get-SSHSession | Select-Object SessionId | Remove-SSHSession | Out-Null  #--[ Remove any existing sessions ]--    
    }Catch{
        Write-host "Error: " $_.Error.Message  -ForegroundColor Red
        Write-host "Exception: " $_.Exception.Message  -ForegroundColor Red
    }
    New-SSHSession -ComputerName $TargetIP -AcceptKey -Credential $Credential | Out-Null
    $Session = Get-SSHSession -Index 0 

    If ($Session){
        #StatusMsg "SSH Session Connected." "Green" $ExtOption  #--[ Message tends to get annoying in normal use ]--
    }

    $Stream = $Session.Session.CreateShellStream("dumb", 0, 0, 0, 0, 5000)
    $Stream.Write("terminal Length 0 `n")
    Start-Sleep -Milliseconds 60
    $Stream.Read() | Out-Null
    $Stream.Write("$Command`n")
    Start-Sleep -millisec 10
    $ResponseRaw = $Stream.Read()
    $Response = $ResponseRaw -split "`r`n" | ForEach-Object{$_.trim()}
    $Count = 0
    while (($Response[$Response.Count -1]) -notlike "*#") {
        If ($Count -ge 100){
            StatusMsg "SSH Session is hung up, aborting." "Red" $ExtOption
            Break
        }
        Start-Sleep -Milliseconds 60
        $ResponseRaw = $Stream.Read()
        $Response = $ResponseRaw -split "`r`n" | ForEach-Object{$_.trim()}
        $Count++
    }
    Get-SSHSession | Select-Object SessionId | Remove-SSHSession | Out-Null  #--[ Remove the open session ]--
    Return $Response
}

Function Inspect ($IntSettings){  #--[ Inspect the Interface for correct entries ]--
    # NOTES:
    # Bitmap 11111111111111111 : 17 possible attribute entries, one for each expected line
    # - To convert binary to decimal = [Convert]::ToInt32("10011010010", 2)
    # - To convert decimal to binary = [Convert]::ToString(1234, 2)
    $Description = ""
    $Vlan = ""
    $Mode = ""
    $Code = 0
    ForEach ($Line in $IntSettings){
        Switch -Wildcard ([String]$Line){
            "*description*" {
                $Description = $Line.Substring(12)        
            }
            "*switchport access*" {
                $Vlan = $Line.Split(" ")[3]
            }
            "*switchport mode*" {
                $Mode = $Line.Substring(16)
            }
            # switchport voice vlan XYZ  (not checked)
            "*PERMIT-ISE*"{  # Attribute 1
                $Code = $Code + 1
            }
            "*next-method*"{  # Attribute 2
                $Code = $Code + 2
            }
            "*authorize vlan*"{  # Attribute 3
                $Code = $Code + 4
            }
            "*authorize voice*"{  # Attribute 4
                $Code = $Code + 8
            }
            "*reinitialize*"{  # Attribute 5
                $Code = $Code + 16
            }
            "*multi-auth*"{  # Attribute 6
                $Code = $Code + 32
            }
            "*open*"{  # Attribute 7
                $Code = $Code + 64
            }
            "*order*"{  # Attribute 8
                $Code = $Code + 128
            }
            "*authentication priority dot1x mab*"{  # Attribute 9
                $Code = $Code + 256
            }
            "*authentication port-control auto*"{  # Attribute 10
                $Code = $Code + 512
            }
            "*authentication periodic*"{  # Attribute 11
                $Code = $Code + 1024
            }
            "*authentication timer reauthenticate server*"{  # Attribute 12
                $Code = $Code + 2048
            }
            "*authentication violation restrict*"{  # Attribute 13
                $Code = $Code + 4096
            }
            "mab"{  # Attribute 14
                $Code = $Code + 8192
            }   
            # trust device cisco-phone  (not checked)
            "*dot1x pae authenticator*"{  # Attribute 15
                $Code = $Code + 16384
            }
            "*dot1x timeout tx-period 5*"{  # Attribute 16
                $Code = $Code + 32768
            }
            "*dot1x max-reauth-req 1*"{  # Attribute 17
                $Code = $Code + 65536
            }
            # auto qos voip cisco-phone  (not checked)
            # spanning-tree portfast  (not checked)
            # spanning-tree bpduguard enable  (not checked)
            # service-policy input AutoQos-4.0-CiscoPhone-Input-Policy  (not checked)
            # service-policy output AutoQos-4.0-Output-Policy  (not checked)
            # ip dhcp snooping information option allow-untrusted  (not checked)
        }
        If ($Line -eq "end"){
            break
        }
    }
    $Result = [Convert]::ToString($Code, 2)
    $Result = $Result.PadLeft(17,"0")
    $Data = @{
        "Description" = $Description
        "Vlan" = $Vlan
        "Mode" = $Mode
        "Bitmap" = $Result
    }
    Return $Data
}

Function LoadConfig ($ConfigFile, $ExtOption){ 
    If ($ConfigFile -ne "failed"){
        [xml]$Config = Get-Content $ConfigFile  #--[ Read & Load XML ]--    
        $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "BrowserEnable" -Value $Config.Settings.General.BrowserEnable        
        $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "Domain" -Value $Config.Settings.General.Domain      
        $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "CredDrive" -Value $Config.Settings.Credentials.CredDrive
        $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "PasswordFile" -Value $Config.Settings.Credentials.PasswordFile
        $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "KeyFile" -Value $Config.Settings.Credentials.KeyFile
        $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "SmtpServer" -Value $Config.Settings.Email.SmtpServer
        $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "EmailRecipient" -Value $Config.Settings.Email.EmailRecipient
        $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "EmailAltRecipient" -Value $Config.Settings.Email.EmailAltRecipient
        $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "EmailSender" -Value $Config.Settings.Email.EmailSender
        $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "Debug" -Value $False
    }Else{
        StatusMsg "MISSING XML CONFIG FILE.  File is required.  Script aborted..." " Red" $True
        $Message = (
'--[ External XML config file example ]-----------------------------------
--[ To be named the same as the script and located in the same folder as the script ]--
--[ Email settings in example are for future use.                                   ]--

<?xml version="1.0" encoding="utf-8"?>
<Settings>
    <General>
        <BrowserEnable>$true</BrowserEnable>
    </General>
    <Credentials>
        <Domain>my.org</Domain>
        <CredDrive>c:</CredDrive>
        <PasswordFile>/folder/PassFile.txt</PasswordFile>
        <KeyFile>/folder/KeyFile.txt</KeyFile>
    </Credentials>    
	<Email>
		<EmailEnable>$true</EmailEnable>
		<EmailSender>Automation@my.org</EmailSender>
        <SmtpServer>mail.my.org</SmtpServer>
        <SmtpPort>25</SmtpPort>
        <EmailRecipient>me@my.org</EmailRecipient>
    	<EmailAltRecipient>you@my.org</EmailAltRecipient>
    </Email>
</Settings> ')
Write-host $Message -ForegroundColor Yellow
    }
    Return $ExtOption
}

Function GetConsoleHost ($ExtOption){  #--[ Detect if we are using a script editor or the console ]--
    Switch ($Host.Name){
        'consolehost'{
            $ExtOption | Add-Member -MemberType NoteProperty -Name "ConsoleState" -Value $False -force
            $ExtOption | Add-Member -MemberType NoteProperty -Name "ConsoleMessage" -Value "PowerShell Console detected." -Force
        }
        'Windows PowerShell ISE Host'{
            $ExtOption | Add-Member -MemberType NoteProperty -Name "ConsoleState" -Value $True -force
            $ExtOption | Add-Member -MemberType NoteProperty -Name "ConsoleMessage" -Value "PowerShell ISE editor detected." -Force
        }
        'PrimalScriptHostImplementation'{
            $ExtOption | Add-Member -MemberType NoteProperty -Name "ConsoleState" -Value $True -force
            $ExtOption | Add-Member -MemberType NoteProperty -Name "COnsoleMessage" -Value "PrimalScript or PowerShell Studio editor detected." -Force
        }
        "Visual Studio Code Host" {
            $ExtOption | Add-Member -MemberType NoteProperty -Name "ConsoleState" -Value $True -force
            $ExtOption | Add-Member -MemberType NoteProperty -Name "ConsoleMessage" -Value "Visual Studio Code editor detected." -Force
        }
    }
    If ($ExtOption.ConsoleState){
        StatusMsg "Detected session running from an editor..." "Magenta" $ExtOption
    }
    Return $ExtOption
}

#==[ End of Functions ]=======================================================

#==[ Begin Processing ]========================================================
If ($Console){
    Write-host "--------------------------------------------------------------" -ForegroundColor yellow 
    Write-host "--[ Begin Processing ]----------------------------------------" -ForegroundColor yellow 
    Write-host "--------------------------------------------------------------" -ForegroundColor yellow 
}

$HtmlReport = ""
$LineData = ""

#--[ Load external XML options file ]--
$ConfigFile = $PSScriptRoot+"\"+($MyInvocation.MyCommand.Name).Split(".")[0]+".xml"
$ExtOption = New-Object -TypeName psobject #--[ Object to hold runtime options ]--
$ExtOption = LoadConfig $ConfigFile $ExtOption 

#--[ Detect Runspace ]--
$ExtOption = GetConsoleHost $ExtOption 
If ($ExtOption.ConsoleState){ 
    StatusMsg $ExtOption.ConsoleMessage "Cyan" $ExtOption
}
If ($Console){
    $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "ConsoleState" -Value $True 
}
If ($Debug){
    $ExtOption | Add-Member -Force -MemberType NoteProperty -Name "Debug" -Value $True 
}

#--[ Process Logon Credentials ]-------------------------------
$UN = $Env:USERNAME
$DN = $Env:USERDOMAIN
$UID = $DN+"\"+$UN
If ($Null -eq ($ExtOption.CredDrive+$ExtOption.PasswordFile)){
    $Credential = Get-Credential -Message 'Enter an appropriate Domain\User and Password to continue.'
}Else{
    $PasswordFile = ($ExtOption.CredDrive+$ExtOption.PasswordFile)
    $KeyFile = ($ExtOption.CredDrive+$ExtOption.KeyFile) 
    If (Test-Path -Path $PasswordFile){
        $Base64String = (Get-Content $KeyFile)
        $ByteArray = [System.Convert]::FromBase64String($Base64String)
        $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UID, (Get-Content $PasswordFile | ConvertTo-SecureString -Key $ByteArray)
    }
}
$ExtOption | Add-Member -Force -MemberType NoteProperty -Name "Credential" -Value $Credential

#--[ Begin HTML Email Report ]--
$HtmlHeader = '
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
</head>
'



#==[ Begin Processing of IP List ]=============================================
StatusMsg "--- Processing Switch IP List ---" "Magenta" $ExtOption
If (!(Test-Path -PathType leaf ($PSScriptRoot+"\IPlist.txt"))){
    $IPList = Read-Host -Prompt "Please enter a single IP address to process"
}Else{
    $IPList = @() 
    $IPList  = Get-Content -path "$PSScriptRoot\IPlist.txt"
}
$ErrorActionPreference = "stop"

#--[ NOTE: If a line in the text file starts with "#," that line is ignored ]--
ForEach ($Address in $IPList ){ #| Where {($_.Split(",")[0].tostring()) -NotLike "#"}){
    $IP = ($Address.Split(";")[0]) 

    If ($Console){
        Write-host "`n--[ Current Target Device: "  -ForegroundColor yellow -NoNewline
        Write-Host $IP  -ForegroundColor cyan -NoNewline
        Write-Host " ]---------------------------------------------------" -ForegroundColor yellow 
    }

   
    #--[ Test and connect to target IP to grab interface list ]--------------------------
    If ($IP -like "#*"){
        If ($ExtOption.ConsoleState){Write-Host "-- Script Status: Bypassing IP" -ForegroundColor Red}
    }Else{
        #--[ Test network connection. ]--------------------------------------------------
        If (Test-Connection -ComputerName $IP -count 1 -BufferSize 16 -Quiet){   
            $HtmlBody ='
            <body>
                <table border-collapse="collapse" border="3" cellspacing="0" cellpadding="0" width="100%" bgcolor="#E6E6E6" bordercolor="black">
                    <tr>
                        <td colspan='+$IntColumns+'><center><H2><font color=darkcyan><strong>ISE Configuration Report for Switch '+$IP+'</strong></H2></center></td>
                    </tr>
                    <tr>
                        <td><strong><center>Interface ID</center></td>
                        <td><strong><center>Interface Mode</center></td>
                        <td><strong><center>Interface Vlan</center></td>
                        <td><strong><center>Interface Status</center></td>            
                        <td><strong><center>Audit Result</center></td>            
                        <td><strong><center>Config Bitmap</center></td>   
                        <td><strong><center>Interface Description</center></td>           
                    </tr>
            '
            #--[ Check for and/or create folder for this device ]--        
            If (!(Test-Path -Path "$PsScriptRoot\$IP" -PathType container)){
                New-Item -ItemType Directory -Force -Path "$PsScriptRoot\$IP" | out-null
                StatusMsg "Creating new device folder." "Magenta" $ExtOption
            }
            
            #--[ Read and store a full copy of the switch config.  Keep last 10 ]--
            $Command = 'sh run'
            $RunningConfig = GetSSH $IP $Command $Credential
            $SaveFile = $PSscriptRoot+"\"+$IP+"\"+$IP+"_Config_"+$DateTime+".bak"
            Try{
                Add-Content -path $SaveFile -Value $RunningConfig
                StatusMsg "Device configuration successfully stored." "Green" $ExtOption
            }Catch{
                StatusMsg "Device configuration storage has failed." "Red" $ExtOption
            }
            Get-ChildItem -Path "$PsScriptRoot\$IP" | Where-Object {(-not $_.PsIsContainer) -and ($_.Name -like "*.bak")} | Sort-Object -Descending -Property LastTimeWrite | Select-Object -Skip $SaveCount | Remove-Item
            
            #--[ Get TACACS Details ]-----------------------------------------------------------
            StatusMsg "Polling TACACS" "Yellow" $ExtOption 
            $Command = 'sh tacacs'
            $TacacsDetails = GetSSH $IP $Command $Credential
            $TacacsHtml = '<table border-collapse="collapse" border="3" cellspacing="0" cellpadding="0" width="100%" bgcolor="#E6E6E6" bordercolor="black">'
            $TacacsHtml += '<tr><td colspan='+$TacColumns+'><strong><center>TACACS Configuration</td></tr><tr>'       
            $TacacsHtml += '<tr>
            <td><strong><center>Server Name</td>
            <td><strong><center>Server IP</td>
            <td><strong><center>Server Port</td>
            <td><strong><center>Server Status</td>
            </tr>'
            $Count = 0
            $TacacsObj = New-Object -TypeName psobject 
            ForEach ($Line in $TacacsDetails){
                If ($Line -like "Tacacs+ Server*"){
                    $Count++
                    $TacacsObj | Add-Member -Force -MemberType NoteProperty -Name "Count" -Value $Count                    
                }
                If ($Line -like "*Server name*"){
                    $TacacsObj | Add-Member -Force -MemberType NoteProperty -Name ("ServerName"+$Count) -Value $Line.Split(":")[1].Trim()
                }
                If ($Line -like "*Server address*"){
                    $TacacsObj | Add-Member -Force -MemberType NoteProperty -Name ("ServerAddress"+$Count) -Value $Line.Split(":")[1].Trim()
                }
                If ($Line -like "*Server port*"){
                    $TacacsObj | Add-Member -Force -MemberType NoteProperty -Name ("ServerPort"+$Count) -Value $Line.Split(":")[1].Trim()
                }
                If ($Line -like "*Server Status*"){
                    $TacacsObj | Add-Member -Force -MemberType NoteProperty -Name ("ServerStatus"+$Count) -Value $Line.Split(":")[1].Trim()
                }               
            }  
            $Count = 1
            StatusMsg "Adding TACACS Details" "Magenta" $ExtOption
            While ($Count -le  $TacacsObj.Count){
                $TacacsHtml += '<tr>'
                $Value = $TacacsObj.('ServerName'+$Count)
                $Msg = '    Server Name = '+$Value
                StatusMsg $Msg "Cyan" $ExtOption
                $TacacsHtml += '<td><center>'+$Value+'</td>'  

                $Name = 'ServerAddress'+$Count
                $Value = $TacacsObj.$Name
                $Msg = '      Server IP = '+$Value
                StatusMsg $Msg "Cyan" $ExtOption                
                $TacacsHtml += '<td><center>'+$Value+'</td>' 
    
                $Name = 'ServerPort'+$Count
                $Value = $TacacsObj.$Name
                $Msg = '    Server Port = '+$Value
                StatusMsg $Msg "Cyan" $ExtOption
                $TacacsHtml += '<td><center>'+$Value+'</td>'  

                $Name = 'ServerStatus'+$Count
                $Value = $TacacsObj.$Name
                If ($Null -eq $Value){
                    $Value = 'Unknown'
                }
                $Msg = '  Server Status = '+$Value
                StatusMsg $Msg "Cyan" $ExtOption                
                $TacacsHtml += '<td><center>'+$Value+'</td></tr>'  
                $Count++
            }
            $TacacsHtml += '</table>'

            #--[ Get RADIUS Details ]-----------------------------------------------------------
            StatusMsg "Polling RADIUS" "Yellow" $ExtOption 
            $Command = 'sh aaa servers | i RADIUS'
            $RadiusDetails = GetSSH $IP $Command $Credential
            #$RadiusHtml = '<tr><td colspan='+$Columns+'>'
            $RadiusHtml = '<table border-collapse="collapse" border="3" cellspacing="0" cellpadding="0" width="100%" bgcolor="#E6E6E6" bordercolor="black">'
            #$RadiusHtml = '<table border="1" cellspacing="0" cellpadding="0" width="100%" bgcolor="#E6E6E6" bordercolor="black">'
            $RadiusHtml += '<tr><td colspan='+$RadColumns+'><strong><center>RADIUS Configuration</td></tr>'       
            $RadiusHtml += '<tr>
            <td><strong><center>ID</td>
            <td><strong><center>Priority</td>
            <td><strong><center>Server</td>
            <td><strong><center>Auth-Port</td>
            <td><strong><center>Acct-Port</td>
            <td><strong><center>Hostname</td></tr>'
            ForEach ($Line in $RadiusDetails){
                $Line = $Line.replace(',','')
#                write-host "ID "$line.split(" ")[2]
                $RadiusHtml += '<tr><td><center>'+$line.split(" ")[2]+'</td>'
#                write-host "Priority "$line.split(" ")[3]
                $RadiusHtml += '<td><center>'+$line.split(" ")[4]+'</td>'
#                write-host "Server "$line.split(" ")[6]
                $RadiusHtml += '<td><center>'+$line.split(" ")[6]+'</td>'
#                write-host "Auth-Port "$line.split(" ")[8]
                $RadiusHtml += '<td><center>'+$line.split(" ")[8]+'</td>'                
#                write-host "Acct-Port "$line.split(" ")[9]
                $RadiusHtml += '<td><center>'+$line.split(" ")[8]+'</td>'
#                write-host "Hostname "$line.split(" ")[11]
                $RadiusHtml += '<td><center>'+$line.split(" ")[12]+'</td></tr>'
            }
            $RadiusHtml += '</table>'

            #--[ Process Each Interface ]--------------------------------------------------------   
            StatusMsg "Polling Interfaces" "Yellow" $ExtOption 
            $Command = 'sh int status'
            $InterfaceList = GetSSH $IP $Command $Credential
            ForEach ($Line in $InterfaceList){
                $Line = $Line -replace '\s+', ' '
                $Interface = $Line.Split(" ")[0]
                $InterfaceObj = New-Object -TypeName psobject 
                $InterfaceObj | Add-Member -Force -MemberType NoteProperty -Name "Interface" -Value $Interface
                #--[ Cycle through identified interfaces ]--
                If (($Interface -like "*/*") -and ($Interface -notlike "Ap*") -and ($Interface -notlike "Po*")){
                    StatusMsg "blank" "" $ExtOption
                    $Msg = "Processing Int "+$Interface
                    StatusMsg $Msg "Magenta" $ExtOption
                    Switch -Wildcard ([String]$Line){
                        "*notconnect*" {
                            $InterfaceObj | Add-Member -Force -MemberType NoteProperty -Name "Status" -Value "NotConnect"
                        }
                        "*connected*" {
                            $InterfaceObj | Add-Member -Force -MemberType NoteProperty -Name "Status" -Value "Connected"
                        }
                        "* disabled*" {
                            $InterfaceObj | Add-Member -Force -MemberType NoteProperty -Name "Status" -Value "Disabled"
                        }
                        "*err*" {
                            $InterfaceObj | Add-Member -Force -MemberType NoteProperty -Name "Status" -Value "Err-Disabled"
                        }
                    }

                    #--[ Call SSH, Grab settings for Interface ]--
                    $Command = 'sh run int '+$Interface
                    $IntSettings = GetSSH $IP $Command $Credential

                    #--[ Call Parser to Examine Interface Settings ]--
                    $Data = Inspect $IntSettings                 

                    $InterfaceObj | Add-Member -Force -MemberType NoteProperty -Name "Description" -Value $Data['Description']
                    If ($Data['Mode'] -eq ""){
                        $InterfaceObj | Add-Member -Force -MemberType NoteProperty -Name "Mode" -Value "Unconfigured"
                    }Else{
                        $InterfaceObj | Add-Member -Force -MemberType NoteProperty -Name "Mode" -Value $Data['Mode']
                    }
                    $InterfaceObj | Add-Member -Force -MemberType NoteProperty -Name "Vlan" -Value $Data['Vlan']
                    $InterfaceObj | Add-Member -Force -MemberType NoteProperty -Name "Bitmap" -Value $Data['Bitmap']
                    If ($InterfaceObj.Mode -eq "Access"){
                        If ($Data['Bitmap'].length -lt 17){
                            $InterfaceObj | Add-Member -Force -MemberType NoteProperty -Name "Result" -Value "Result Length Error"
                        }
                        If ($Data['Bitmap'] -like "*0*"){
                            $InterfaceObj | Add-Member -Force -MemberType NoteProperty -Name "Result" -Value "ISE Settings Missing"                        
                        }Else{
                            $InterfaceObj | Add-Member -Force -MemberType NoteProperty -Name "Result" -Value "ISE Config Verified"
                        } 
                    }Else{
                        $InterfaceObj | Add-Member -Force -MemberType NoteProperty -Name "Result" -Value "ISE Not Required"
                    }

                    If ($ExtOption.ConsoleState){
                        $Msg = "         Mode = "+$InterfaceObj.Mode 
                        StatusMsg $Msg "Cyan" $ExtOption
                        $Msg = "         Vlan = "+$InterfaceObj.Vlan
                        StatusMsg $Msg "Cyan" $ExtOption
                        $Msg = "       Status = "+$InterfaceObj.Status
                        StatusMsg $Msg "Cyan" $ExtOption
                        $Msg = "       Result = "+$InterfaceObj.Result
                        StatusMsg $Msg "Cyan" $ExtOption
                        $Msg = "       Bitmap = "+$InterfaceObj.Bitmap
                        StatusMsg $Msg "Cyan" $ExtOption
                        $Msg = "  Description = "+$InterfaceObj.Description
                        StatusMsg $Msg "Cyan" $ExtOption
                    }

                    #--[ Add data line to HTML report ]--
                    $LineData = '<tr>'
                    $LineData += '<td><center>'+$InterfaceObj.Interface+'</center></td>'

                    If (($InterfaceObj.Mode -eq "Trunk") -or ($InterfaceObj.Mode -ne "Access")){
                        $LineData += '<td><center>'+$InterfaceObj.Mode+'</center></td>'
                        $LineData += '<td><center>'+$InterfaceObj.Vlan+'</center></td>'
                        $LineData += '<td><center>'+$InterfaceObj.Status+'</center></td>'
                        $LineData += '<td><center>Not Required</center></td>'
                        $LineData += '<td></td>'
                        $LineData += '<td><center>'+$InterfaceObj.Description+'</center></td>'
                    }Else{
                        $LineData += '<td><center>'+$InterfaceObj.Mode+'</center></td>'
                        $LineData += '<td><center>'+$InterfaceObj.Vlan+'</center></td>'
                        $LineData += '<td><center>'+$InterfaceObj.Status+'</center></td>'
                        If ($InterfaceObj.Result -NotLike "*Verified*"){
                            $LineData += '<td><center><font color=darkred>'+$InterfaceObj.Result+'</center></td>'
                            $LineData += '<td><center><font color=darkred>'+$InterfaceObj.Bitmap+'</center></td>'
                        }Else{
                            $LineData += '<td><center><font color=green>'+$InterfaceObj.Result+'</center></td>'
                            $LineData += '<td><center><font color=green>'+$InterfaceObj.Bitmap+'</center></td>'
                        }
                        $LineData += '<td><center>'+$InterfaceObj.Description+'</center></td>'
                    }
                    $LineData += '</tr>'
                    $HtmlBody = $HtmlBody + $LineData
                }
            }
            $HtmlBody += '</table>'

            $HtmlFooter = '<table border-collapse="collapse" border="3" cellspacing="0" cellpadding="0" width="100%" bgcolor="#E6E6E6" bordercolor="black">
            <tr><td><br>
            The included bitmap column encodes the detected ISE settings <strong>in the order listed below</strong>.  A "1" indicates the line is 
            present and a "0" indicates the line is absent.  There are 17 total lines whose presence are checked for within the 
            configuration of each detected switch interface.  Note that "XYZ" below is a placeholder for the actual vlan in use. 
            <ul>
            <li>ip access-group PERMIT-ISE in</li>
            <li>authentication event fail action next-method</li>
            <li>authentication event server dead action authorize vlan XYZ</li>
            <li>authentication event server dead action authorize voice</li>
            <li>authentication event server alive action reinitialize</li>
            <li>authentication host-mode multi-auth</li>
            <li>authentication open</li>
            <li>authentication order dot1x mab</li>
            <li>authentication priority dot1x mab</li>
            <li>authentication port-control auto</li>
            <li>authentication periodic</li>
            <li>authentication timer reauthenticate server</li>
            <li>authentication violation restrict</li>
            <li>mab</li>
            <li>dot1x pae authenticator</li>
            <li>dot1x timeout tx-period 5</li>
            <li>dot1x max-reauth-req 1</li>
            </ul>
            </tr>
            <tr><td colspan='+$Columns+'><center><font color=darkcyan><strong>Audit completed at: '+$DateTime+'</strong></center></td></tr>   
            </table>
            ' 


            #--[ Construct final full report ]--
            $DateTime = Get-Date -Format MM-dd-yyyy_hh:mm:ss 
            $HtmlReport = $HtmlHeader+$HtmlBody+'<br>'+$RadiusHtml+'<br>'+$TacacsHTML+'<br>'+$HtmlFooter            
            $HtmlReport += '</body></html>'

            #--[ Only keep the last 10 of the log files ]-- 
            If (!(Test-Path -PathType container ($SourcePath+"\"+$IP))){
                New-Item -ItemType Directory -Path ($PSScriptRoot+"\"+$IP) -Force | out-null
            }
            Get-ChildItem -Path ($PSscriptRoot+"\"+$IP) | Where-Object {(-not $_.PsIsContainer) -and ($_.Name -like "*html*")} | Sort-Object -Descending -Property LastTimeWrite | Select-Object -Skip 10 | Remove-Item | Out-Null

            $DateTime = Get-Date -Format MM-dd-yyyy_hh.mm.ss 
            $Report = ($PSscriptRoot+"\"+$IP+"\ISE-Status"+$DateTime+".html")
            Add-Content -Path $Report -Value $HtmlReport #>

            SendEmail $HtmlReport $ExtOption 

            #--[ Use this to load the report in the default browser.  Adjust in XML file ]--
            If ($ExtOption.BrowserEnable){
                iex $Report
            }
        }
        If ($ExtOption.ConsoleState){
            $Msg = "End of Item "+$IP
            StatusMsg $Msg "magenta" $ExtOption
        }
    }
}
Write-host ""
Write-Host "`n--- COMPLETED ---" -ForegroundColor red
 
