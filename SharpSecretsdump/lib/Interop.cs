using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpSecretsdump
{
    public class Interop
    {
        // for GetSystem()
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            UInt32 DesiredAccess,
            out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DuplicateToken(
            IntPtr ExistingTokenHandle,
            int SECURITY_IMPERSONATION_LEVEL,
            ref IntPtr DuplicateTokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(
            IntPtr hToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
                public static extern bool CloseHandle(
            IntPtr hObject
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();

        // for LSA Secrets Dump
        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public static extern int RegOpenKeyEx(
            uint hKey,
            string subKey,
            int ulOptions,
            int samDesired,
            ref IntPtr hkResult
        );

        [DllImport("advapi32.dll")]
        public static extern int RegQueryInfoKey(
            IntPtr hkey,
            StringBuilder lpClass,
            ref int lpcbClass,
            int lpReserved,
            ref IntPtr lpcSubKeys,
            ref IntPtr lpcbMaxSubKeyLen,
            ref IntPtr lpcbMaxClassLen,
            ref IntPtr lpcValues,
            ref IntPtr lpcbMaxValueNameLen,
            ref IntPtr lpcbMaxValueLen,
            ref IntPtr lpcbSecurityDescriptor,
            IntPtr lpftLastWriteTime
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int RegEnumKeyEx(
            IntPtr hKey,
            int dwIndex,
            StringBuilder lpName,
            ref int lpcchName,
            IntPtr lpReserved,
            IntPtr lpClass,
            IntPtr lpcchClass,
            ref IntPtr lpftLastWriteTime
            );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int RegEnumValue(
            IntPtr hKey,
            int dwIndex,
            StringBuilder lpValueName,
            ref int lpcchValueName,
            int lpReserved,
            IntPtr lpType,
            IntPtr lpDate,
            IntPtr lpcbData
            );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int RegQueryValueEx(
            IntPtr hKey,
            string lpValueName,
            int lpReserved,
            IntPtr type,
            IntPtr lpData,
            ref int lpcbData
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int RegCloseKey(
            IntPtr hKey
        );
    }
}
