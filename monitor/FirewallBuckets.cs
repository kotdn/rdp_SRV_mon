using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace RDPMonitor
{
    /// <summary>
    /// Mirrors WinService's FirewallBuckets so the monitor GUI reads/writes the same
    /// RDP_BLOCK_0..RDP_BLOCK_15 rule set the service maintains, instead of a single
    /// RDP_BLOCK_ALL rule. See the WinService copy for the rationale.
    /// </summary>
    internal static class FirewallBuckets
    {
        public const int Count = 16;
        private const string RuleNamePrefix = "RDP_BLOCK_";

        public const string LegacyRuleName = "RDP_BLOCK_ALL";

        public static string RuleName(int bucket) => RuleNamePrefix + bucket;

        public static IEnumerable<string> AllRuleNames()
        {
            for (int i = 0; i < Count; i++)
                yield return RuleName(i);
        }

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
}
