# SharpSecretsdump

C# project used to mimic `secretsdump.py` from impacket but only to be run locally on hosts without relying on the remote registry service. Nowadays, most EDR, IDS or next gen firewalls can detect the use of impacket or remote use of the registry service. This project aims to lower the fingerprint of retriveing secrets stored in the hives of a compromised host.

Most of the code used here is coming from these 2 project:
* https://github.com/G0ldenGunSec/SharpSecDump
* https://github.com/GhostPack/SharpDPAPI
