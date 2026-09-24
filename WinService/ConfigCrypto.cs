using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

#pragma warning disable CA1416 // Windows-only service; DPAPI is always available here.

/// <summary>
/// Encrypts config.json at rest using Windows DPAPI (machine scope), so the file is only
/// usable when read on this exact machine. Confidentiality of secrets stored in it
/// (Telegram bot token, chat id, phone allowlist) still depends on restricting file access
/// via ACLs (see EnsureSecureAcl) — DPAPI LocalMachine keys can be unprotected by any
/// process running on the same host, so this is a defense-in-depth layer against the file
/// being copied off the box (backups, support bundles, stolen disks mounted elsewhere),
/// not a substitute for access control.
/// </summary>
internal static class ConfigCrypto
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("RDPSecurityService.config.v1");

    public static string ReadConfigText(string path)
    {
        byte[] raw = File.ReadAllBytes(path);
        if (raw.Length == 0)
            return string.Empty;

        // Back-compat: configs written before encryption was introduced are plain JSON.
        // Read them as-is; the next write re-saves them encrypted.
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
