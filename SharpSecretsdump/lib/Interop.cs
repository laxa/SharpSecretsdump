using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpSecretsdump
{
    public class Interop
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID Luid;
            public uint Attributes;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public static extern int RegOpenKeyEx(
            uint hKey,
            string subKey,
            int ulOptions,
            int samDesired,
            ref IntPtr hkResult
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public static extern int RegCreateKeyEx(
            uint hKey,
            string subKey,
            int reserved,
            string lpClass,
            int dwOptions,
            int samDesired,
            IntPtr lpSecurityAttributes,
            ref IntPtr hkResult,
            ref IntPtr lpdwDisposition
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
