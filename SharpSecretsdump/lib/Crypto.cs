﻿using System;
using System.Security.Cryptography;
using System.IO;
using System.Collections.Generic;

namespace SharpSecretsdump
{
    public class Crypto
    {
        public static byte[] LSAAESDecrypt(byte[] key, byte[] data)
        {
            var aesCryptoProvider = new AesManaged();

            aesCryptoProvider.Key = key;
            aesCryptoProvider.IV = new byte[16];
            aesCryptoProvider.Mode = CipherMode.CBC;
            aesCryptoProvider.BlockSize = 128;
            aesCryptoProvider.Padding = PaddingMode.Zeros;
            var transform = aesCryptoProvider.CreateDecryptor();

            var chunks = Decimal.ToInt32(Math.Ceiling((decimal)data.Length / (decimal)16));
            var plaintext = new byte[chunks * 16];

            for (var i = 0; i < chunks; ++i)
            {
                var offset = i * 16;
                var chunk = new byte[16];
                Array.Copy(data, offset, chunk, 0, 16);

                var chunkPlaintextBytes = transform.TransformFinalBlock(chunk, 0, chunk.Length);
                Array.Copy(chunkPlaintextBytes, 0, plaintext, i * 16, 16);
            }
            
            return plaintext;
        }

        public static byte[] LSASHA256Hash(byte[]key, byte[] rawData)
        {
            // yay
            using (var sha256Hash = SHA256.Create())
            {
                var buffer = new byte[key.Length + (rawData.Length * 1000)];
                Array.Copy(key, 0, buffer, 0, key.Length);
                for (var i = 0; i < 1000; ++i)
                {
                    Array.Copy(rawData, 0, buffer, key.Length + (i * rawData.Length), rawData.Length);
                }
                return sha256Hash.ComputeHash(buffer);
            }
        }

        //https://stackoverflow.com/questions/7217627/is-there-anything-wrong-with-this-rc4-encryption-code-in-c-sharp
        internal static byte[] RC4Encrypt(byte[] pwd, byte[] data)
        {
            int a, i, j, k, tmp;
            int[] key, box;
            byte[] cipher;

            key = new int[256];
            box = new int[256];
            cipher = new byte[data.Length];

            for (i = 0; i < 256; i++)
            {
                key[i] = pwd[i % pwd.Length];
                box[i] = i;
            }
            for (j = i = 0; i < 256; i++)
            {
                j = (j + box[i] + key[i]) % 256;
                tmp = box[i];
                box[i] = box[j];
                box[j] = tmp;
            }
            for (a = j = i = 0; i < data.Length; i++)
            {
                a++;
                a %= 256;
                j += box[a];
                j %= 256;
                tmp = box[a];
                box[a] = box[j];
                box[j] = tmp;
                k = box[((box[a] + box[j]) % 256)];
                cipher[i] = (byte)(data[i] ^ k);
            }
            return cipher;
        }

        internal static byte[] DecryptAES_CBC(byte[] value, byte[] key, byte[] iv)
        {
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            aes.BlockSize = 128;
            aes.Key = key;
            aes.Mode = CipherMode.CBC;
            aes.IV = iv;
            //you would think this would work to pad out the rest of the final block to 16, but it doesnt? ¯\_(ツ)_/¯
            aes.Padding = PaddingMode.Zeros;

            int tailLength = value.Length % 16;
            if (tailLength != 0)
            {
                List<byte> manualPadding = new List<byte>();
                for (int i = 16 - tailLength; i > 0; i--)
                {
                    manualPadding.Add(0x00);
                }
                byte[] concat = new byte[value.Length + manualPadding.Count];
                System.Buffer.BlockCopy(value, 0, concat, 0, value.Length);
                System.Buffer.BlockCopy(manualPadding.ToArray(), 0, concat, value.Length, manualPadding.Count);
                value = concat;
            }

            using (ICryptoTransform decrypt = aes.CreateDecryptor())
            {
                byte[] dest = decrypt.TransformFinalBlock(value, 0, value.Length);
                return dest;
            }
        }

        internal static string DecryptSingleHash(byte[] obfuscatedHash, string user)
        {
            List<byte> key1 = new List<byte>();
            List<byte> key2 = new List<byte>();

            RidToKey(user, ref key1, ref key2);

            byte[] hashBytes1 = new byte[8];
            byte[] hashBytes2 = new byte[8];
            Buffer.BlockCopy(obfuscatedHash, 0, hashBytes1, 0, 8);
            Buffer.BlockCopy(obfuscatedHash, 8, hashBytes2, 0, 8);

            byte[] plain1 = DeObfuscateHashPart(hashBytes1, key1);
            byte[] plain2 = DeObfuscateHashPart(hashBytes2, key2);

            return (BitConverter.ToString(plain1) + BitConverter.ToString(plain2));
        }

        //method from SidToKey - https://github.com/woanware/ForensicUserInfo/blob/master/Source/SamParser.cs
        private static void RidToKey(string hexRid, ref List<byte> key1, ref List<byte> key2)
        {
            int rid = Int32.Parse(hexRid, System.Globalization.NumberStyles.HexNumber);
            List<byte> temp1 = new List<byte>();

            byte temp = (byte)(rid & 0xFF);
            temp1.Add(temp);

            temp = (byte)(((rid >> 8) & 0xFF));
            temp1.Add(temp);

            temp = (byte)(((rid >> 16) & 0xFF));
            temp1.Add(temp);

            temp = (byte)(((rid >> 24) & 0xFF));
            temp1.Add(temp);

            temp1.Add(temp1[0]);
            temp1.Add(temp1[1]);
            temp1.Add(temp1[2]);

            List<byte> temp2 = new List<byte>();
            temp2.Add(temp1[3]);
            temp2.Add(temp1[0]);
            temp2.Add(temp1[1]);
            temp2.Add(temp1[2]);

            temp2.Add(temp2[0]);
            temp2.Add(temp2[1]);
            temp2.Add(temp2[2]);

            key1 = TransformKey(temp1);
            key2 = TransformKey(temp2);
        }

        private static List<byte> TransformKey(List<byte> inputData)
        {
            List<byte> data = new List<byte>();
            data.Add(Convert.ToByte(((inputData[0] >> 1) & 0x7f) << 1));
            data.Add(Convert.ToByte(((inputData[0] & 0x01) << 6 | ((inputData[1] >> 2) & 0x3f)) << 1));
            data.Add(Convert.ToByte(((inputData[1] & 0x03) << 5 | ((inputData[2] >> 3) & 0x1f)) << 1));
            data.Add(Convert.ToByte(((inputData[2] & 0x07) << 4 | ((inputData[3] >> 4) & 0x0f)) << 1));
            data.Add(Convert.ToByte(((inputData[3] & 0x0f) << 3 | ((inputData[4] >> 5) & 0x07)) << 1));
            data.Add(Convert.ToByte(((inputData[4] & 0x1f) << 2 | ((inputData[5] >> 6) & 0x03)) << 1));
            data.Add(Convert.ToByte(((inputData[5] & 0x3f) << 1 | ((inputData[6] >> 7) & 0x01)) << 1));
            data.Add(Convert.ToByte((inputData[6] & 0x7f) << 1));
            return data;
        }

        //from https://github.com/woanware/ForensicUserInfo/blob/master/Source/SamParser.cs
        private static byte[] DeObfuscateHashPart(byte[] obfuscatedHash, List<byte> key)
        {
            DESCryptoServiceProvider cryptoProvider = new DESCryptoServiceProvider();
            cryptoProvider.Padding = PaddingMode.None;
            cryptoProvider.Mode = CipherMode.ECB;
            ICryptoTransform transform = cryptoProvider.CreateDecryptor(key.ToArray(), new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 });
            MemoryStream memoryStream = new MemoryStream(obfuscatedHash);
            CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Read);
            byte[] plainTextBytes = new byte[obfuscatedHash.Length];
            int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
            return plainTextBytes;
        }
    }
}
