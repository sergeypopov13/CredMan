#-----------------------------------------------------------------------
# Low-level Credentials Management Cmdlets
#-----------------------------------------------------------------------

<#
.SYNOPSIS
    Reads a generic credential from the user's credential set OR enumerates the generic credentials from the user's credential set.

.PARAMETER Name
    The name of the credential to read.

.PARAMETER Filter
    The filter for the returned credentials. The filter specifies a name prefix followed by an asterisk.

.EXAMPLE
    # Read a specific generic credential from user's credential set:

    Get-GenericCredential -Name 'StorageAccount:MyAccount'

    TargetName               UserName                         Secret
    ----------               --------                         ------
    StorageAccount:MyAccount AccountKey System.Security.SecureString

.EXAMPLE
    # Enumerates generic credentials from user's credential set which start with 'StorageAccount'

    C:\> Get-GenericCredential -Filter 'StorageAccount:*'

    TargetName               UserName   Secret
    ----------               --------   ------
    StorageAccount:MyAccount AccountKey
#>
function Get-GenericCredential {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Get')]
        [ValidateNotNullOrEmpty()]
        [string] $Name = $null,

        [Parameter(Mandatory = $false, ParameterSetName = 'List')]
        [ValidateNotNullOrEmpty()]
        [string] $Filter = '*'
    )

    if (-not $Name) {
        return [CredManModule.CredManUtility]::ListCredentials($Filter)
    }
    else {
        return [CredManModule.CredManUtility]::ReadCredential($Name)
    }
}

<#
.SYNOPSIS
    Creates a new generic credential or modifies an existing generic credential in the user's credential set.

.PARAMETER Name
    The name of the credential.

.PARAMETER UserName
    The user name.

.PARAMETER Secret
    Secret data for the credential.

.EXAMPLE
    # Create a new generic credential:

    $secret = ConvertTo-SecureString '...' -AsPlainText -Force
    Set-GenericCredential -Name 'StorageAccount:MyAccount' -UserName "AccountKey" -Secret $secret
#>
function Set-GenericCredential {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Name,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $UserName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [securestring] $Secret
    )

    [CredManModule.CredManUtility]::WriteCredential($Name, $UserName, $Secret)
}

<#
.SYNOPSIS
    Deletes a generic credential from the user's credential set.

.PARAMETER Name
    The name of the credential to delete.

.EXAMPLE
    # Delete a specific generic credential from user’s credential set:

    Remove-GenericCredential -Name 'StorageAccount:MyAccount'
#>
function Remove-GenericCredential {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Name
    )

    [CredManModule.CredManUtility]::DeleteCredential($Name)
}

$source = @"
namespace CredManModule
{
    using System;
    using System.ComponentModel;
    using System.Runtime.InteropServices;
    using System.Security;

    public sealed class GenericCredential
    {
        public GenericCredential(string targetName, string userName, string plainSecret)
        {
            this.TargetName = targetName;
            this.UserName = userName;
            this.Secret = CreateSecureString(plainSecret);
        }

        public string TargetName { get; private set; }

        public string UserName { get; private set; }

        public SecureString Secret { get; private set; }

        private static unsafe SecureString CreateSecureString(string s)
        {
            if (string.IsNullOrEmpty(s))
            {
                return null;
            }

            SecureString result;

            fixed (char* pch = s)
            {
                result = new SecureString(pch, s.Length);
            }

            result.MakeReadOnly();

            return result;
        }
    }

    public static class CredManUtility
    {
        // CREDENTIAL structure
        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa374788(v=vs.85).aspx
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CREDENTIAL
        {
            public uint Flags;

            public uint Type;

            public IntPtr TargetName;

            public IntPtr Comment;

            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;

            public uint CredentialBlobSize;

            public IntPtr CredentialBlob;

            public uint Persist;

            public uint AttributeCount;

            public IntPtr Attributes;

            public IntPtr TargetAlias;

            public IntPtr UserName;
        }

        private static class NativeMethods
        {
            public const uint CRED_TYPE_GENERIC = 0x1;

            public const int CRED_MAX_GENERIC_TARGET_NAME_LENGTH = 32767;

            public const int CRED_MAX_STRING_LENGTH = 256;

            public const int CRED_MAX_CREDENTIAL_BLOB_SIZE = 512;

            public const uint CRED_PERSIST_LOCAL_MACHINE = 0x2;

            // CredDelete function
            // https://msdn.microsoft.com/en-us/library/windows/desktop/aa374787(v=vs.85).aspx
            [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern bool CredDelete([In] string targetName, [In] uint type, [In] uint flags);

            // CredEnumerate function
            // https://msdn.microsoft.com/en-us/library/windows/desktop/aa374794(v=vs.85).aspx
            [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern bool CredEnumerate([In] string filter, [In] uint flags, [Out] out uint count, [Out] out IntPtr credListPtr);

            // https://msdn.microsoft.com/en-us/library/windows/desktop/aa374796(v=vs.85).aspx
            [DllImport("Advapi32.dll", SetLastError = true)]
            public static extern bool CredFree([In] IntPtr credPtr);

            // CredRead function
            // https://msdn.microsoft.com/en-us/library/windows/desktop/aa374804(v=vs.85).aspx
            [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern bool CredRead([In] string targetName, [In] uint type, [In] uint flags, [Out] out IntPtr credPtr);

            // CredWrite function
            // https://msdn.microsoft.com/en-us/library/windows/desktop/aa375187(v=vs.85).aspx
            [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern bool CredWrite([In] ref CREDENTIAL credPtr, [In] uint flags);
        }

        public static GenericCredential[] ListCredentials(string filter)
        {
            IntPtr credListPtr = IntPtr.Zero;

            try
            {
                uint count;

                if (!NativeMethods.CredEnumerate(filter, 0, out count, out credListPtr))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                var credPtrs = new IntPtr[count];
                Marshal.Copy(credListPtr, credPtrs, 0, credPtrs.Length);

                var result = new GenericCredential[credPtrs.Length];

                for (int i = 0; i < credPtrs.Length; i++)
                {
                    var cred = (CREDENTIAL)Marshal.PtrToStructure(credPtrs[i], typeof(CREDENTIAL));

                    result[i] = new GenericCredential(
                        targetName: Marshal.PtrToStringUni(cred.TargetName),
                        userName: Marshal.PtrToStringUni(cred.UserName),
                        plainSecret: null);
                }

                return result;
            }
            finally
            {
                if (credListPtr != null)
                {
                    NativeMethods.CredFree(credListPtr);
                }
            }
        }

        public static GenericCredential ReadCredential(string targetName)
        {
            IntPtr credPtr = IntPtr.Zero;

            try
            {
                if (!NativeMethods.CredRead(targetName, NativeMethods.CRED_TYPE_GENERIC, 0, out credPtr))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                var cred = (CREDENTIAL)Marshal.PtrToStructure(credPtr, typeof(CREDENTIAL));

                var result = new GenericCredential(
                    targetName: Marshal.PtrToStringUni(cred.TargetName),
                    userName: Marshal.PtrToStringUni(cred.UserName),
                    plainSecret: Marshal.PtrToStringUni(cred.CredentialBlob, (int)cred.CredentialBlobSize / 2));

                return result;
            }
            finally
            {
                if (credPtr != IntPtr.Zero)
                {
                    NativeMethods.CredFree(credPtr);
                }
            }
        }

        public static void WriteCredential(string targetName, string userName, SecureString secret)
        {
            IntPtr targetNamePtr = IntPtr.Zero;
            IntPtr userNamePtr = IntPtr.Zero;
            IntPtr plainSecretPtr = IntPtr.Zero;

            try
            {
                targetNamePtr = Marshal.StringToCoTaskMemUni(targetName);
                userNamePtr = Marshal.StringToCoTaskMemUni(userName);
                plainSecretPtr = Marshal.SecureStringToCoTaskMemUnicode(secret);

                var cred = new CREDENTIAL
                {
                    Flags = 0,
                    Type = NativeMethods.CRED_TYPE_GENERIC,
                    TargetName = targetNamePtr,
                    Comment = IntPtr.Zero,
                    LastWritten = new System.Runtime.InteropServices.ComTypes.FILETIME(),
                    CredentialBlobSize = (uint)secret.Length * 2,
                    CredentialBlob = plainSecretPtr,
                    Persist = NativeMethods.CRED_PERSIST_LOCAL_MACHINE,
                    AttributeCount = 0,
                    Attributes = IntPtr.Zero,
                    TargetAlias = IntPtr.Zero,
                    UserName = userNamePtr
                };

                if (!NativeMethods.CredWrite(ref cred, 0))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }
            finally
            {
                if (plainSecretPtr != IntPtr.Zero)
                {
                    Marshal.ZeroFreeCoTaskMemUnicode(plainSecretPtr);
                }

                if (userNamePtr != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(userNamePtr);
                }

                if (targetNamePtr != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(targetNamePtr);
                }
            }
        }

        public static void DeleteCredential(string targetName)
        {
            if (!NativeMethods.CredDelete(targetName, NativeMethods.CRED_TYPE_GENERIC, 0))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
    }
}
"@

$compilerParameters = [System.CodeDom.Compiler.CompilerParameters]::new()
$compilerParameters.ReferencedAssemblies.Add('System.dll')
$compilerParameters.CompilerOptions = '/unsafe'

Add-Type -CompilerParameters $compilerParameters -TypeDefinition $source -ErrorAction Stop
