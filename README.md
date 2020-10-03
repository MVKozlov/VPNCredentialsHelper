# VPN Credentials Helper PowerShell Module
This repository contains the code used to build the PowerShell helper module: [VPNCredentialsHelper](https://www.powershellgallery.com/packages/VPNCredentialsHelper).

The module can set a username, password and presharedkey directly for a named VPN connection, so that you are not prompted to enter it the first time you connect.

To install the module enter the following PowerShell command.

 ```PowerShell
Install-Module -Name VPNCredentialsHelper
 ```

This will add the **Set-VpnConnectionCredential** as a PowerShell command.

And then you can script something like this:

 ```PowerShell
$name = "ExpressVPN Australia Sydney"
$address = "aus1-ubuntu-l2tp.expressprovider.com"
$username = "your_username"
$plainpassword = "your_password"
 
Add-VpnConnection -Name $name -ServerAddress $address -TunnelType L2tp -EncryptionLevel Required -AuthenticationMethod MSChapv2 -L2tpPsk "12345678" -Force:$true -RememberCredential:$true -SplitTunneling:$false 
 
Set-VpnConnectionCredential -ConnectionName $name -UserName $username -Password $plainpassword -Domain ''

# or
$Cred = Get-Credential
$PSK = Get-Credential
Set-VpnConnectionCredential -ConnectionName $name -Credential $Cred -PreSharedKey $PSK
 ```
### Security
Please note: you will have to set your policy to permit unsigned PowerShell scripts to execute, to run this command.

If you're nervous about doing this, the actual script source code can be found [here](https://www.powershellgallery.com/packages/VPNCredentialsHelper/1.1/Content/VPNCredentialsHelper.psm1).

## Thanks
A huge thanks to Jeff Winn for the DotRas project (https://dotras.codeplex.com/) which showed me the way, and who did all the really hard work.
___
[Paul Stancer](https://github.com/paulstancer)

### Changes
This module differs from the original module in the following changes:
 1. Added support for L2TP PreShared Key
 2. Cmdlet renamed to `Set-VpnConnectionCredential` to be more powershell style
 3. Added support for `PSCredential` object as credential source
 4. Implemented pipeline support for connections/credentials
 5. Added help
---
[Max Kozlov](https://github.com/MVKozlov)