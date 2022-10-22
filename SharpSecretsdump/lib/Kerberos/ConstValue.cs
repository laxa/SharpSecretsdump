using System;

namespace SharpSecretsdump.lib.Kerberos
{
    /// <summary>
    /// Define const values used in this project.
    /// </summary>
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
}
