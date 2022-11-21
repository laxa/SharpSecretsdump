using System;

namespace SharpSecretsdump.lib.Kerberos
{
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
}
