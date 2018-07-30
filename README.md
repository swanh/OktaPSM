# PowerShell
This is a collection of PowerShell modules and scripts. 

## Prerequisites

* **API Access to Okta** - [Create an API token](https://developer.okta.com/docs/api/getting_started/getting_a_token)
* **PowerShell Core**:
	* [PowerShell Core Installation Guide for MacOS](https://docs.microsoft.com/en-us/powershell/scripting/setup/installing-powershell-core-on-macos-and-linux?view=powershell-6#macos-1012)
	* [PowerShell Core Installation Guide for Linux](https://docs.microsoft.com/en-us/powershell/scripting/setup/installing-powershell-core-on-macos-and-linux?view=powershell-6#ubuntu-1404)

## Importing the Modules

After you've downloaded the desired module folder, copy it to your module directory.

The default system module path for Linux/Mac is:
* /usr/local/microsoft/powershell/6.0.2/modules

The default user module path for Linux/Mac is:
* ~/.local/share/powershell/Modules

The default system module path for Windows is: 
* C:\Program Files\powershell\6.0.2\Modules
The default user module paths for Windows is:
* C:\Users\profile\Documents\WindowsPowerShell\Modules

Then you can import the module by running: 

```
Import-Module NAME_OF_MODULE

Example:
Import-Module Okta
```

To get a list of commands within a module:

```
Get-Command -Module NAME_OF_MODULE

Example:

Get-Command -Module Okta

CommandType     Name                                               Version    Source                                                  
-----------     ----                                               -------    ------                                                  
Function        Activate-OktaUser                                  0.0        Okta                                                    
Function        Add-BulkOktaUserToGroup                            0.0        Okta                                                    
Function        Add-OktaGroup                                      0.0        Okta                                                    
Function        Add-OktaUser                                       0.0        Okta                                                    
Function        Add-OktaUserToGroup                                0.0        Okta                                                    
Function        Deactivate-OktaUser                                0.0        Okta                                                    
Function        Get-OktaApp                                        0.0        Okta                                                    
Function        Get-OktaAppUser                                    0.0        Okta                                                    
Function        Get-OktaGroup                                      0.0        Okta                                                    
Function        Get-OktaGroupApplications                          0.0        Okta                                                    
Function        Get-OktaGroupMembers                               0.0        Okta                                                    
Function        Get-OktaUser                                       0.0        Okta                                                    
Function        Get-OktaUserLogs                                   0.0        Okta                                                    
Function        Reactivate-OktaUser                                0.0        Okta                                                    
Function        Remove-OktaUserFromGroup                           0.0        Okta                                                    
Function        Set-OKTAApiKey                                     0.0        Okta                                                    
Function        Set-OktaUser                                       0.0        Okta                                                

```

To get help with using a function:

```
Get-Help NAME_OF_FUNCTION

Example:

Get-Help Get-OktaUser

NAME
    Get-OktaUser
    
SYNTAX
    Get-OktaUser [[-UserEmail] <string>] [-All]  [<CommonParameters>]
    

ALIASES
    None
    

REMARKS
    None

```

## Examples

To deactivate a single user in Okta:
```
Deactivate-OktaUser -UserEmail testany.testerson@acme.com
```

To deactivate multiple users in Okta:
```
@('test_user001@acme.com','test_user002@acme.com','test_user002@acme.com') | ForEach-Object {Deactivate-OktaUser -UserEmail $_}
```

To retrieve a quick count of application sync states from Okta to a particular application:
```
Get-OktaAppUser -ApplicationID 0oaskfkehqb3dsadyE1t6 | Group-Object syncState
```

To retrieve a list of application assignment failures for a particular application:
```
Get-OktaAppUser -ApplicationID 0oaskfrhqbdsa11t6 | Where-Object {$_.syncState -eq 'ERROR'}
```

To retrieve a list of active users who have not logged on for 3 months:
```
Get-OktaUser -All | ? {$_.lastLogin -lt (Get-Date (Get-Date).AddDays(-90) -Format 'o')}
```

To retrieve a list of active ACME users with access to Confluence:
```
(Get-OktaAppUser -ApplicationID 0oa2zan7odsadnPyW1t7).profile | ? {$_.email -like "*acme.com"}
```

