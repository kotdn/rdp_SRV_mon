using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

/// <summary>
/// Splits the blocked-IP firewall rule into a fixed set of 16 rules
/// (RDP_BLOCK_0 .. RDP_BLOCK_15) instead of one big RDP_BLOCK_ALL rule.
///
/// Why: the old single-rule design rewrote the *entire* combined remoteip list on
/// every single ban/unban event, so one attacker's ban touched (and could fail
/// alongside) everyone else's. Bucketing by target address means a new ban only
/// ever rewrites the one bucket it falls into, and each bucket's remoteip list
/// stays roughly 1/16th the size of the full block list.
///
/// The bucket count is fixed (never grows/shrinks with traffic), so all 16 rules
/// are created once at install time and never renamed or pruned individually.
/// </summary>
internal static class FirewallBuckets
{
    public const int Count = 16;
    private const string RuleNamePrefix = "RDP_BLOCK_";

    /// <summary>Name still used by versions before bucketing existed; kept around only for cleanup.</summary>
    public const string LegacyRuleName = "RDP_BLOCK_ALL";

    public static string RuleName(int bucket) => RuleNamePrefix + bucket;

    public static IEnumerable<string> AllRuleNames()
    {
        for (int i = 0; i < Count; i++)
            yield return RuleName(i);
    }

    /// <summary>
    /// Buckets a plain IPv4 ("1.2.3.4"), a /24 CIDR ("1.2.3.0/24"), or a netsh-style
    /// range ("1.2.3.0-1.2.3.255") by XOR-ing the 3rd and 4th octets of its first
    /// address. A /24 always has a zero 4th octet, so bucketing on the 4th octet
    /// alone would collapse every subnet ban into bucket 0 — folding in the 3rd
    /// octet avoids that.
    /// </summary>
    public static int IndexFor(string target)
    {
        string ipPart = FirstIpToken(target);
        if (!IPAddress.TryParse(ipPart, out IPAddress? ip) || ip.AddressFamily != AddressFamily.InterNetwork)
            return 0;

        byte[] b = ip.GetAddressBytes();
        return (b[2] ^ b[3]) & (Count - 1);
    }

    private static string FirstIpToken(string target)
    {
        if (string.IsNullOrWhiteSpace(target))
            return string.Empty;

        string trimmed = target.Trim();

        int dash = trimmed.IndexOf('-');
        if (dash > 0)
            trimmed = trimmed.Substring(0, dash);

        int slash = trimmed.IndexOf('/');
        if (slash > 0)
            trimmed = trimmed.Substring(0, slash);

        return trimmed.Trim();
    }
}
