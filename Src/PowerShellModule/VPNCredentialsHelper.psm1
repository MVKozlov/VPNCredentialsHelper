<#
	Set-VpnConnectionUsernamePassword - by Paul Stancer.
	Huge thanks to Jeff Winn for the DotRas project (https://dotras.codeplex.com/) which showed me the way, 
	and did all the really hard work.
#>
$code=@' 
    using System;
    using System.Runtime.InteropServices;

    public class VPNCredentialsHelper
    {
        private const int SUCCESS = 0;
        private const int ERROR_ACCESS_DENIED = 5;

        private const int UNLEN = 256;// Defines the maximum length of a username.
        private const int PWLEN = 256;// Defines the maximum length of a password.
        private const int DNLEN = 15;// Defines the maximum length of a domain name.

        [Flags]
        private enum RASCM
        {
            None = 0x0,
            UserName = 0x1,
            Password = 0x2,
            Domain = 0x4,
            PreSharedKey = 0x10,
        }

        [DllImport("rasapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int RasGetErrorString(
            int uErrorValue,
            [In, Out] string lpszErrorString,
            int cBufSize);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 4)]
        private struct RASCREDENTIALS
        {
            public int size;
            public RASCM options;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = UNLEN + 1)]
            public string userName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = PWLEN + 1)]
            public string password;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DNLEN + 1)]
            public string domain;
        }

        [DllImport("rasapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int RasSetCredentials(
            string lpszPhonebook,
            string lpszEntryName,
            IntPtr lpCredentials,
            [MarshalAs(UnmanagedType.Bool)] bool fClearCredentials);

        private static bool _SetRasCredentials(string entryName, RASCREDENTIALS credentials)
        {
            int size = Marshal.SizeOf(typeof(RASCREDENTIALS));

            IntPtr pCredentials = IntPtr.Zero;
            try
            {
                credentials.size = size;

                pCredentials = Marshal.AllocHGlobal(size);
                Marshal.StructureToPtr(credentials, pCredentials, true);

                int ret = RasSetCredentials(null, entryName, pCredentials, false);

                switch (ret)
                {
                    case SUCCESS:
                        return true;
                    case ERROR_ACCESS_DENIED:
                        throw new UnauthorizedAccessException();
                    default:
                        throw ProcessRASException(ret);
                }
            }
            finally
            {
                if (pCredentials != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pCredentials);
                }
            }
        }

        public static bool SetCredentials(string entryName, string domain, string username, string password)
        {
            var credentials = new RASCREDENTIALS() { userName = username, password = password, domain = domain ?? string.Empty, options = RASCM.Domain | RASCM.UserName | RASCM.Password };
            return _SetRasCredentials(entryName, credentials);
        }

        public static bool SetPreSharedKey(string entryName, string presharedkey)
        {
            var credentials = new RASCREDENTIALS() { userName = string.Empty, password = presharedkey, domain = string.Empty, options = RASCM.PreSharedKey };
            return _SetRasCredentials(entryName, credentials);
        }

        private static Exception ProcessRASException(int errorCode)
        {
            try
            {
                string buffer = new string('\x00', 512);

                int ret = RasGetErrorString(errorCode, buffer, buffer.Length);
                if (ret == SUCCESS)
                    return new RASException(errorCode, buffer.Substring(0, buffer.IndexOf('\x00')));
            }
            catch (EntryPointNotFoundException)
            {
            }

            return new RASException(errorCode, "RAS Error code: " + errorCode.ToString());
        }

        public class RASException: Exception
        {
            public RASException(int errCode, string message):base(message)
            {
                RASErrorCode = errCode;
            }

            public int RASErrorCode { get; private set; }
        }
    }
'@ 

<#
    .SYNOPSIS
        Set Credential/PresharedKey to selected VPN COnnection
    .DESCRIPTION
        Set Credential/PresharedKey to selected VPN COnnection
    .PARAMETER ConnectionName
        VPN Connection name
    .PARAMETER Domain
        Domain (if used)
    .PARAMETER UserName
        Connection UserName
    .PARAMETER Password
        Connection Password (plain text)
    .PARAMETER PreSharedKey
        Connection PreSharedKey (plain text)
    .PARAMETER Credential
        Connection Credential as [PSCredential] domain\username / password
    .PARAMETER PreSharedKeyCredential
        Connection PreSharedKey as [PSCredential] (username not used) / password
    .INPUTS
        If used in pipeline form
        awaits [PSCustomObject] with properties named as parameters
    .OUTPUTS
        Boolean result of credentials set.
        Array of booleans if set both PresharedKey and Username/Password
    .EXAMPLE
        Set-VpnConnectionCredential -ConnectionName myvpn -UserName user -Password Pa$sw0rd -PreSharedKey 'do not use these credentials in a real world'
    .EXAMPLE
        $Cred = Get-Credential
        Set-VpnConnectionCredential -ConnectionName myvpn -Credential $Cred
    .EXAMPLE
        $parameters = [PSCustomObject]@{
            ConnectionName = 'MyVPN'
            UserName = 'user'
            Password = 'Pa$sw0rd'
            PreSharedKey = 'do not use these credentials in a real world'
        }
        $parameters | Set-VpnConnectionCredential
    .NOTES
        Name: Set-VpnConnectionCredential
        Author: Paul Stancer, Max Kozlov

        Huge thanks to Jeff Winn for the DotRas project (https://dotras.codeplex.com/) which showed me the way, 
        and did all the really hard work.
    .LINK
        https://docs.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rassetcredentialsw
	    https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa376730(v=vs.85)
#>
function Set-VpnConnectionCredential {
    [CmdletBinding(DefaultParameterSetName='cred')]
	param
	( 
		[Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True, Position=0, HelpMessage='What connection name would you set the credentials?')]
		[ValidateLength(3,255)]
		[string]$ConnectionName,

        [Parameter(ParameterSetName='plain',ValueFromPipelineByPropertyName=$True)]
		[ValidateLength(0,15)]
        [string]$Domain,
        [Parameter(Mandatory=$True, ParameterSetName='plain', Position=1, ValueFromPipelineByPropertyName=$True)]
		[ValidateLength(0,255)]
		[string]$UserName,
        [Parameter(ParameterSetName='plain', Position=2, ValueFromPipelineByPropertyName=$True)]
		[ValidateLength(0,255)]
		[string]$Password,
		[ValidateLength(0,255)]
        [string]$PreSharedKey,

        [Parameter(ParameterSetName='cred', Position=1,ValueFromPipelineByPropertyName=$True)]
        [PSCredential]$Credential,
        [Parameter(ParameterSetName='cred', Position=2,ValueFromPipelineByPropertyName=$True)]
        [Alias('L2PSK', 'PSK')]
        [PSCredential]$PreSharedKeyCredential
	)
    BEGIN {
        try {
            [void][VPNCredentialsHelper]
        }
        catch {
            Add-Type -TypeDefinition $code -IgnoreWarnings
        }
    }
    PROCESS {
        Try {
            if ($PSCmdlet.ParameterSetName -eq 'cred') {
                if ($PSBoundParameters.ContainsKey('Credential') -and $null -eq $Credential) {
                    $Credential = Get-Credential -Message "Enter Domain\Username and Password for $ConnectionName connection"
                }
                if ($PSBoundParameters.ContainsKey('PreSharedKeyCredential') -and $null -eq $PreSharedKeyCredential) {
                    $PreSharedKeyCredential = Get-Credential -UserName PreSharedKey -Message "Enter Preshared Key as password for $ConnectionName connection"
                }
                if ($Credential) {
                    if ($Credential.UserName -match '\\') {
                        $Domain, $UserName = $Credential.UserName -split '\\'
                    }
                    else {
                        $UserName = $Credential.UserName
                    }
                    $Password = $Credential.GetNetworkCredential().Password
                }
                if ($PreSharedKeyCredential) {
                    $PreSharedKey = $PreSharedKeyCredential.GetNetworkCredential().Password
                }
            }
            if ($PreSharedKey) {
                Write-Verbose "Set PreSharedKey for $ConnectionName"
                [VPNCredentialsHelper]::SetPreSharedKey($ConnectionName, $PreSharedKey)
            }
            if ($UserName) {
                Write-Verbose "Set Credentials for $ConnectionName"
                [VPNCredentialsHelper]::SetCredentials($ConnectionName, $Domain, $UserName, $Password)
            }
        }
        Catch [System.UnauthorizedAccessException]
        {
            Write-Error "You do not have permissions to change the credentials"
        }
        Catch {
            Write-Error $_.Exception.Message
        }
    }
}
