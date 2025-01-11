# ISE-Check
Inspects Cisco switches for valid ISE settings on each port.

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
