using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace RDPMonitor
{
    /// <summary>
    /// Mirrors WinService's ConfigCrypto so the monitor GUI can read/write the same
    /// DPAPI-machine-scope-encrypted config.json the service uses. See the WinService
    /// copy of this class for the threat-model notes (LocalMachine DPAPI protects the
    /// file from leaving the host intact; it does not replace ACLs on the file itself).
    /// </summary>
    internal static class ConfigCrypto
    {
        private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("RDPSecurityService.config.v1");

        public static string ReadConfigText(string path)
        {
            byte[] raw = File.ReadAllBytes(path);
            if (raw.Length == 0)
                return string.Empty;

            if (raw[0] == (byte)'{')
                return Encoding.UTF8.GetString(raw);

            byte[] plain = ProtectedData.Unprotect(raw, Entropy, DataProtectionScope.LocalMachine);
            return Encoding.UTF8.GetString(plain);
        }

        public static void WriteConfigText(string path, string json)
        {
            byte[] plain = Encoding.UTF8.GetBytes(json ?? string.Empty);
            byte[] encrypted = ProtectedData.Protect(plain, Entropy, DataProtectionScope.LocalMachine);
            File.WriteAllBytes(path, encrypted);
        }
    }
}
