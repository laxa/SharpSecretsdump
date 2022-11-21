using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace SharpSecretsdump.lib.Kerberos
{
    public static class CryptoUtility
    {
        #region Common
        /// <summary>
        /// Convert a byte to its binary presentation in char array
        /// (for example, byte b = 3, which will be presented by 
        /// char array {'0', '0', '0', '0', '0', '0', '1', '1'})
        /// </summary>
        /// <param name="b">the byte</param>
        /// <returns>the byte's binary presentation</returns>
        internal static char[] GetBits(byte b)
        {
            // initialize result array to '0'
            char[] result = new char[ConstValue.BYTE_SIZE] { '0', '0', '0', '0', '0', '0', '0', '0' };

            // get the binary
            char[] binary = Convert.ToString(b, 2).ToCharArray();

            // copy binary to result array
            Array.Copy(binary, 0, result, result.Length - binary.Length, binary.Length);
            return result;
        }


        /// <summary>
        /// Convert a list of binary bits to bytes
        /// (for example, char array {'0', '0', '0', '0', '0', '0', '1', '1'}
        /// will be converted to byte b = 3)
        /// </summary>
        /// <param name="bits">bits represented by chars ('0' and '1')</param>
        /// <returns>the converted byte array</returns>
        internal static byte[] ConvertBitsToBytes(List<char> bits)
        {
            if (null == bits)
            {
                throw new ArgumentNullException("bits");
            }
            if (bits.Count % ConstValue.BYTE_SIZE != 0)
            {
                throw new ArgumentException("Bits length should be a multiply of 8");
            }

            byte[] result = new byte[bits.Count / ConstValue.BYTE_SIZE];
            for (int i = 0; i < result.Length; i++)
            {
                string s = new string(bits.GetRange(i * ConstValue.BYTE_SIZE, ConstValue.BYTE_SIZE).ToArray());
                result[i] = Convert.ToByte(s, 2);
            }
            return result;
        }

        #endregion Common


        #region DES Crypto Related
        /// <summary>
        /// Create a DES-CBC encryptor
        /// </summary>
        /// <param name="key">the key</param>
        /// <param name="initialVector">the initialization vector</param>
        /// <param name="padding">the padding mode</param>
        /// <returns>the DES-CBC encryptor</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security.Cryptography", "CA5351:DESCannotBeUsed")]
        internal static ICryptoTransform CreateDesCbcEncryptor(
            byte[] key,
            byte[] initialVector,
            PaddingMode padding)
        {
            // check inputs
            if (null == key)
            {
                throw new ArgumentNullException("key");
            }
            if (null == initialVector)
            {
                throw new ArgumentNullException("initialVector");
            }

            // Set crypto to DES-CBC mode
            DESCryptoServiceProvider des = new DESCryptoServiceProvider();
            des.Mode = CipherMode.CBC;
            des.BlockSize = ConstValue.DES_CBC_BLOCK_SIZE;

            // Set padding mode
            des.Padding = padding;

            // Create encryptor from key and initilize vector
            return des.CreateEncryptor(key, initialVector);
        }

        #endregion DES Crypto Related

        #region AES Crypto Related
        /// <summary>
        /// Create AES-CTS encryptor/decryptor
        /// </summary>
        /// <param name="key">the key</param>
        /// <param name="initialVector">the initialization vector</param>
        /// <returns>the AES-CTS encryptor</returns>
        internal static CipherTextStealingMode CreateAesCtsCrypto(
            byte[] key,
            byte[] initialVector)
        {
            // check inputs
            if (null == key)
            {
                throw new ArgumentNullException("key");
            }
            if (null == initialVector)
            {
                throw new ArgumentNullException("initialVector");
            }

            // initialize AES
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            aes.Key = key;
            aes.IV = initialVector;

            // create AES-CTS encryptor/decryptor
            return new CipherTextStealingMode(aes);
        }
        #endregion AES Crypto Related
    }
}
