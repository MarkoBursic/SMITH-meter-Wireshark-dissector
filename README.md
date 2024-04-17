The plugin should be installed in your Wireshark Lua plugin directory.
You can find your Wireshark plugin directory by opening Wireshark and going to Help > About Wireshark and clicking on the Folders tab.
The Personal Lua Plugins directory should be used to install the SMITH dissector plugin.

Usage:
In the filter window enter: SMITH 
All traffic will be filtered out, except the communication with meters will be shown.

SMITH.Addr == n  ... only communication with meter with address n will be shown

List of supported commands:

'AB' = 'Allocate Blend Recipes'
'AP' = 'Autorize Transaction To Preset'		
'AR' = 'Alarm Reset'		
'AT' = 'Request Additive Volumes by Transaction'		
'AU' = 'Authorize Transaction'		
'AV' = 'Request Additive Volumes by Batch'		
'DY' = 'Request Dynamic Display Values'				
'EA' = 'Enquire Alarms'
'EB' = 'End Batch'
'EE' = 'Enquire Status Extended'
'EQ' = 'Enquire Status'		
'ET' = 'End Transaction'		
'FL' = 'Read Flow Count'		
'GD' = 'Get Date and Time'
'PC' = 'Change Program Code Values'
'PF' = 'Request Time of Power-Fail'		
'PV' = 'Request Program Code Values'		
'RA' = 'Request Alarm Status'
'RB' = 'Request Batch Totals'
'RC' = 'Request Recipe Composition'
'RD' = 'Request Current Transducer Value'		
'RE' = 'Reset Status Conditions'
'RK' = 'Read Keypad'					
'RL' = 'Show Recipes Loaded'
'RQ' = 'Request Current Flow Rate'		
'RR' = 'Request Recipe'
'RS' = 'Request Status'						
'RT' = 'Request Transaction Totals'
'SA' = 'Remote Start'
'SB' = 'Set Batch'
'SD' = 'Set Date and Time'
'SF' = 'Authorize and Set Batch without Override'
'SP' = 'Remote Stop'
'SR' = 'Show Recipes Currently Allocated'
'ST' = 'Remote Stop on Arm'
'TA' = 'Set Transaction'	
'TI' = 'Show Prompt Data Entry'			
'TN' = 'Show Transaction Stop Date and Time'
'VT' = 'Request Meter Totalizer'
'WA' = 'Write Second Line of Message to Appear on Display'	
'WB' = 'Write Third Line of Message to Appear on Display'			
'WC' = 'Write Fourth Line of Message to Appear on Display'	
'WD' = 'Write to Display'	

