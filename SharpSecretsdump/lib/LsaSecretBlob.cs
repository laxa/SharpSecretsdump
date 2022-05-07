using System;
using System.Linq;
namespace SharpSecretsdump
{
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
}
