using System;
using System.ServiceProcess;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.IO;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Net.NetworkInformation;
using System.Diagnostics.Eventing.Reader;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

#pragma warning disable CA1416 // Suppress Windows-only API warnings

class Program
{
#pragma warning disable CA1416
    internal const string TelegramUiRevision = "2026-04-26-telegram-grouped-menu";

    public static void WriteBootstrapLog(string message)
    {
        try
        {
            string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RDPSecurityService");
            Directory.CreateDirectory(dir);
            string path = Path.Combine(dir, "bootstrap.log");
            string entry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}";
            File.AppendAllText(path, entry + Environment.NewLine, Encoding.UTF8);
        }
        catch
        {
        }
    }

    static void Main(string[] args)
        {
            try
            {
                WriteBootstrapLog("Main started.");

                if (args.Length > 0)
                {
                    string command = args[0].ToLower();
                    if (command == "install")
                    {
                        InstallService();
                        return;
                    }
                    else if (command == "uninstall")
                    {
                        bool removeFirewallRule = false;
                        bool hasExplicitFirewallChoice = false;

                        for (int i = 1; i < args.Length; i++)
                        {
                            string arg = args[i];
                            if (arg.Equals("--remove-firewall", StringComparison.OrdinalIgnoreCase))
                            {
                                removeFirewallRule = true;
                                hasExplicitFirewallChoice = true;
                            }
                            else if (arg.Equals("--keep-firewall", StringComparison.OrdinalIgnoreCase))
                            {
                                removeFirewallRule = false;
                                hasExplicitFirewallChoice = true;
                            }
                        }

                        if (!hasExplicitFirewallChoice && Environment.UserInteractive)
                        {
                            Console.Write("Remove RDP_BLOCK_* firewall rules as well? (y/N): ");
                            string? answer = Console.ReadLine();
                            removeFirewallRule = !string.IsNullOrWhiteSpace(answer) &&
                                (answer.Trim().Equals("y", StringComparison.OrdinalIgnoreCase) ||
                                 answer.Trim().Equals("yes", StringComparison.OrdinalIgnoreCase));
                        }

                        UninstallService(removeFirewallRule);
                        return;
                    }
                    else if (command == "run" || command == "console")
                    {
                        WriteBootstrapLog("Starting in interactive console mode.");

                        var interactiveService = new RDPSecurityService();
                        interactiveService.StartInteractive(args.Skip(1).ToArray());

                        using var stopEvent = new ManualResetEventSlim(false);
                        Console.CancelKeyPress += (_, e) =>
                        {
                            e.Cancel = true;
                            stopEvent.Set();
                        };

                        Console.WriteLine("RDPSecurityService is running in interactive mode. Press Ctrl+C to stop.");
                        stopEvent.Wait();

                        interactiveService.StopInteractive();
                        WriteBootstrapLog("Interactive console mode stopped.");
                        return;
                    }
                }

                ServiceBase[] servicesToRun = new ServiceBase[] { new RDPSecurityService() };
                ServiceBase.Run(servicesToRun);
            }
            catch (Exception ex)
            {
                WriteBootstrapLog($"Fatal Main error: {ex}");
                throw;
            }
        }

        static void InstallService()
        {
            try
            {
                string serviceName = "RDPSecurityService";
                string displayName = "RDP Security Service - Auth Failures Blocker";
                string exePath = Environment.ProcessPath
                    ?? Process.GetCurrentProcess().MainModule?.FileName
                    ?? System.Reflection.Assembly.GetExecutingAssembly().Location;

                string quotedExePath = $"\"{exePath}\"";
                var processInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "sc.exe",
                    Arguments = $"create {serviceName} binPath= {quotedExePath} DisplayName= \"{displayName}\" start= auto",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var process = System.Diagnostics.Process.Start(processInfo))
                {
                    if (process == null)
                    {
                        Console.WriteLine("Failed to start sc.exe for service installation");
                        return;
                    }

                    process.WaitForExit();
                    if (process.ExitCode == 0)
                    {
                        InitializeWhitelistAndFirewallOnInstall();
                        Console.WriteLine("Service installed successfully");
                    }
                    else
                        Console.WriteLine($"Failed to install service (exit code: {process.ExitCode})");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        static void InitializeWhitelistAndFirewallOnInstall()
        {
            string logDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "RDPSecurityService");
            string whitelistPath = Path.Combine(logDirectory, "whiteList.log");
            string blockListPath = Path.Combine(logDirectory, "block_list.log");
            string configPath = Path.Combine(logDirectory, "config.json");

            // Reinstall safety: if service state already exists, do not bootstrap/overwrite anything.
            if (File.Exists(whitelistPath) || File.Exists(blockListPath) || File.Exists(configPath))
            {
                Console.WriteLine("Existing service state detected. Skipping install bootstrap.");
                return;
            }

            // Reinstall safety: if any block rule already exists, do not touch firewall/whitelist bootstrap.
            if (FirewallBuckets.AllRuleNames().Any(DoesFirewallRuleExistForInstall) || DoesFirewallRuleExistForInstall(FirewallBuckets.LegacyRuleName))
            {
                Console.WriteLine("Existing firewall block rule(s) detected. Skipping install bootstrap.");
                return;
            }

            try
            {
                Directory.CreateDirectory(logDirectory);

                var whitelist = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                if (File.Exists(whitelistPath))
                {
                    foreach (string raw in File.ReadAllLines(whitelistPath, Encoding.UTF8))
                    {
                        string value = raw?.Trim() ?? string.Empty;
                        if (string.IsNullOrWhiteSpace(value))
                            continue;

                        if (IPAddress.TryParse(value, out _))
                            whitelist.Add(value);
                    }
                }

                foreach (string ip in GetLocalAutoWhitelistIpsForInstall())
                    whitelist.Add(ip);

                File.WriteAllLines(whitelistPath, whitelist.OrderBy(x => x, StringComparer.OrdinalIgnoreCase), Encoding.UTF8);
                Console.WriteLine($"Whitelist initialized: {whitelist.Count} entries");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Whitelist bootstrap warning: {ex.Message}");
            }

            EnsureBlockRuleExistsForInstall();
        }

        static void EnsureBlockRuleExistsForInstall()
        {
            foreach (string ruleName in FirewallBuckets.AllRuleNames())
                EnsureSingleBlockRuleExistsForInstall(ruleName);

            // Clean up the pre-bucketing rule name so it doesn't linger alongside the new ones.
            RemoveLegacyBlockRuleForInstall();
        }

        static void EnsureSingleBlockRuleExistsForInstall(string ruleName)
        {
            try
            {
                bool ruleExists = DoesFirewallRuleExistForInstall(ruleName);

                if (ruleExists)
                {
                    Console.WriteLine($"Firewall rule {ruleName} already exists");
                    return;
                }

                var createPsi = new ProcessStartInfo
                {
                    FileName = "netsh.exe",
                    Arguments = $"advfirewall firewall add rule name=\"{ruleName}\" dir=in action=block protocol=any remoteip=\"255.255.255.255\" profile=any enable=yes",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using (var createProc = Process.Start(createPsi))
                {
                    if (createProc == null)
                    {
                        Console.WriteLine($"Firewall bootstrap warning: netsh process start failed for {ruleName}");
                        return;
                    }

                    string output = createProc.StandardOutput.ReadToEnd() + createProc.StandardError.ReadToEnd();
                    createProc.WaitForExit(10000);
                    if (createProc.ExitCode == 0 || output.IndexOf("Ok", StringComparison.OrdinalIgnoreCase) >= 0 || output.IndexOf("ОК", StringComparison.OrdinalIgnoreCase) >= 0)
                        Console.WriteLine($"Firewall rule {ruleName} created");
                    else
                        Console.WriteLine($"Firewall bootstrap warning: failed to create {ruleName} (exit {createProc.ExitCode}) {output}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Firewall bootstrap warning: {ex.Message}");
            }
        }

        static void RemoveLegacyBlockRuleForInstall()
        {
            try
            {
                if (!DoesFirewallRuleExistForInstall(FirewallBuckets.LegacyRuleName))
                    return;

                var psi = new ProcessStartInfo
                {
                    FileName = "netsh.exe",
                    Arguments = $"advfirewall firewall delete rule name=\"{FirewallBuckets.LegacyRuleName}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using (var p = Process.Start(psi))
                {
                    if (p == null)
                        return;

                    p.WaitForExit(5000);
                    if (p.ExitCode == 0)
                        Console.WriteLine($"Legacy firewall rule {FirewallBuckets.LegacyRuleName} removed (superseded by RDP_BLOCK_0..{FirewallBuckets.Count - 1}).");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Legacy rule cleanup warning: {ex.Message}");
            }
        }

        static bool DoesFirewallRuleExistForInstall(string ruleName)
        {
            try
            {
                var checkPsi = new ProcessStartInfo
                {
                    FileName = "netsh.exe",
                    Arguments = $"advfirewall firewall show rule name=\"{ruleName}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using (var checkProc = Process.Start(checkPsi))
                {
                    if (checkProc == null)
                        return false;

                    checkProc.WaitForExit(5000);
                    return checkProc.ExitCode == 0;
                }
            }
            catch
            {
                return false;
            }
        }

        static HashSet<string> GetLocalAutoWhitelistIpsForInstall()
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "127.0.0.1"
            };

            try
            {
                foreach (var ip in Dns.GetHostAddresses(Dns.GetHostName()))
                {
                    if (ip.AddressFamily != AddressFamily.InterNetwork)
                        continue;

                    string text = ip.ToString();
                    if (IsLocalOrPrivateIpForInstall(text))
                        set.Add(text);
                }
            }
            catch
            {
            }

            return set;
        }

        static bool IsLocalOrPrivateIpForInstall(string ipAddress)
        {
            if (!IPAddress.TryParse(ipAddress, out IPAddress parsedIp))
                return false;

            var ip = parsedIp.IsIPv4MappedToIPv6 ? parsedIp.MapToIPv4() : parsedIp;
            if (IPAddress.IsLoopback(ip))
                return true;

            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                byte[] bytes = ip.GetAddressBytes();
                if (bytes.Length != 4)
                    return false;

                return bytes[0] == 10
                    || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                    || (bytes[0] == 192 && bytes[1] == 168)
                    || (bytes[0] == 169 && bytes[1] == 254);
            }

            return false;
        }

        static void UninstallService(bool removeFirewallRule)
        {
            try
            {
                string serviceName = "RDPSecurityService";
                var processInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "sc.exe",
                    Arguments = $"stop {serviceName}",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var process = System.Diagnostics.Process.Start(processInfo))
                {
                    if (process == null)
                    {
                        Console.WriteLine("Failed to start sc.exe for service removal");
                        return;
                    }

                    process.WaitForExit();
                }

                var deleteInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "sc.exe",
                    Arguments = $"delete {serviceName}",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var deleteProcess = System.Diagnostics.Process.Start(deleteInfo))
                {
                    if (deleteProcess == null)
                    {
                        Console.WriteLine("Failed to start sc.exe for service removal");
                        return;
                    }

                    deleteProcess.WaitForExit();
                    if (deleteProcess.ExitCode == 0)
                        Console.WriteLine("Service uninstalled successfully");
                    else
                        Console.WriteLine($"Failed to uninstall service (exit code: {deleteProcess.ExitCode})");
                }

                if (removeFirewallRule)
                {
                    foreach (string ruleName in FirewallBuckets.AllRuleNames())
                        RemoveSingleFirewallRuleForUninstall(ruleName);

                    // Also remove the pre-bucketing rule name in case this machine was
                    // upgraded from a version that only ever created RDP_BLOCK_ALL.
                    RemoveSingleFirewallRuleForUninstall(FirewallBuckets.LegacyRuleName);
                }
                else
                {
                    Console.WriteLine("Firewall rules were left unchanged.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        static void RemoveSingleFirewallRuleForUninstall(string ruleName)
        {
            try
            {
                var firewallDeleteInfo = new ProcessStartInfo
                {
                    FileName = "netsh.exe",
                    Arguments = $"advfirewall firewall delete rule name=\"{ruleName}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using (var firewallProcess = Process.Start(firewallDeleteInfo))
                {
                    if (firewallProcess == null)
                    {
                        Console.WriteLine($"Failed to start netsh.exe for {ruleName} removal");
                        return;
                    }

                    string output = (firewallProcess.StandardOutput.ReadToEnd() + " " + firewallProcess.StandardError.ReadToEnd()).Trim();
                    firewallProcess.WaitForExit();
                    if (firewallProcess.ExitCode == 0)
                        Console.WriteLine($"Firewall rule {ruleName} removed.");
                    else
                        Console.WriteLine($"Firewall rule {ruleName} removal note (exit {firewallProcess.ExitCode}): {output}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error removing {ruleName}: {ex.Message}");
            }
        }
    }

    public class RDPSecurityService : ServiceBase
    {
        private enum WTS_CONNECTSTATE_CLASS
        {
            WTSActive,
            WTSConnected,
            WTSConnectQuery,
            WTSShadow,
            WTSDisconnected,
            WTSIdle,
            WTSListen,
            WTSReset,
            WTSDown,
            WTSInit
        }

        private enum WTS_INFO_CLASS
        {
            WTSInitialProgram,
            WTSApplicationName,
            WTSWorkingDirectory,
            WTSOEMId,
            WTSSessionId,
            WTSUserName,
            WTSWinStationName,
            WTSDomainName,
            WTSConnectState,
            WTSClientBuildNumber,
            WTSClientName,
            WTSClientDirectory,
            WTSClientProductId,
            WTSClientHardwareId,
            WTSClientAddress
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO
        {
            public int SessionID;
            [MarshalAs(UnmanagedType.LPStr)]
            public string pWinStationName;
            public WTS_CONNECTSTATE_CLASS State;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_CLIENT_ADDRESS
        {
            public int AddressFamily;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
            public byte[] Address;
        }

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern bool WTSEnumerateSessions(
            IntPtr hServer,
            int Reserved,
            int Version,
            out IntPtr ppSessionInfo,
            out int pCount);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern void WTSFreeMemory(IntPtr pointer);

        [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool WTSQuerySessionInformation(
            IntPtr hServer,
            int sessionId,
            WTS_INFO_CLASS wtsInfoClass,
            out IntPtr ppBuffer,
            out int pBytesReturned);

        // Defaults; overridden by C:\ProgramData\RDPSecurityService\config.json
        private const int DEFAULT_FAILED_ATTEMPTS_THRESHOLD = 5;
        private const int DEFAULT_BLOCK_MINUTES = 20;
        private const int DEFAULT_RDP_PORT = 3389;
        private const int CHECK_INTERVAL = 250;
        private EventLogWatcher failedLogonWatcher = null!;
        // Timestamps of recent failed logons per source IP, pruned to the last
        // failedAttemptsWindowDays on every read — a real automated brute-force burst
        // (seconds/minutes) is always far inside even a 1-day window, so this doesn't weaken
        // detection of actual attacks; it only stops unrelated typos by different people
        // behind a shared NAT/office IP, spread across days or weeks, from ever adding up.
        private Dictionary<string, List<DateTime>> failedAttempts = new Dictionary<string, List<DateTime>>();
        private readonly object failedAttemptsLock = new object();
        private Thread monitorThread = null!;
        private bool isRunning = false;
        private string logDirectory = "";
        private string accessLogPath = "";
        private string blockListLogPath = "";
        private string whitelistPath = "";
        private string configPath = "";
        private object logLock = new object();
        private object configLock = new object();
        private FileSystemWatcher logWatcher = null!;
        private readonly object firewallSyncLock = new object();
        private DateTime lastFirewallSyncUtc = DateTime.MinValue;
        private bool firewallSyncQueued = false;
        private static readonly TimeSpan FirewallSyncDebounce = TimeSpan.FromSeconds(1);

        private volatile int failedAttemptsThreshold = DEFAULT_FAILED_ATTEMPTS_THRESHOLD;
        private volatile int blockMinutes = DEFAULT_BLOCK_MINUTES;
        private volatile int rdpPort = DEFAULT_RDP_PORT;
        private volatile int ipAbuseWindowMinutes = 10;
        private volatile int ipAbuseDistinctUsersThreshold = 3;
        private volatile int failedAttemptsWindowDays = 1;
        private volatile List<BlockLevel> blockLevels = new List<BlockLevel> { new BlockLevel { Attempts = 3, BlockMinutes = 20 } };
        private volatile TelegramConfig? telegramConfig = null;
        private volatile string uiLanguage = "UA";
        private volatile AntiBruteConfig antiBruteConfig = AntiBruteConfig.CreateDefault();
        private Thread telegramCommandThread = null!;
        private long telegramUpdateOffset = 0;
        private bool telegramCommandBootstrapDone = false;
        private bool telegramPollingModeEnsured = false;
        private DateTime serviceStartUtc = DateTime.UtcNow;
        // private volatile GateConfig gateConfig = new GateConfig { Enabled = false, ListenPort = 3389, TargetHost = "127.0.0.1", TargetPort = 3389 };

        // private TcpListener gateListener;
        // private Thread gateThread;

        private sealed class BanState
        {
            public int AppliedAttempts;
            public DateTime UntilLocal;
        }

        private sealed class SprayState
        {
            public Dictionary<string, DateTime> SourceIps = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        }

        // Same as SprayState, but scoped to one (username, /24 subnet) pair instead of one
        // username across the whole internet — see TryApplySubnetUserSprayBan.
        private sealed class SubnetUserSprayState
        {
            public Dictionary<string, DateTime> SourceIps = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        }

        private enum PendingTelegramCommandType
        {
            None,
            BanIp,
            BanDuration,
            UnbanIp,
            HereIp,
            AddLimitedUserPhone
        }

        private sealed class PendingTelegramCommand
        {
            public PendingTelegramCommandType Type;
            public string IpAddress = string.Empty;
        }

        private sealed class HereProbeTokenState
        {
            public string ChatId = string.Empty;
            public DateTime CreatedUtc;
        }

        private static readonly TimeSpan HereProbeTokenTtl = TimeSpan.FromMinutes(10);

        private readonly Dictionary<string, BanState> bans = new Dictionary<string, BanState>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, BanState> subnetBans = new Dictionary<string, BanState>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, SprayState> sprayByUser = new Dictionary<string, SprayState>(StringComparer.OrdinalIgnoreCase);
        // key: "{normalizedUsername}|{subnet24}", e.g. "administrator|46.229.58.0/24"
        private readonly Dictionary<string, SubnetUserSprayState> subnetUserSprayByKey = new Dictionary<string, SubnetUserSprayState>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, List<DateTime>> tcpProbeHits = new Dictionary<string, List<DateTime>>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, DateTime> recentTcpProbeKeys = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, DateTime> recentRdpPortActivityByIp = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, PendingTelegramCommand> pendingTelegramCommands = new Dictionary<string, PendingTelegramCommand>(StringComparer.Ordinal);
        private readonly HashSet<string> authorizedTelegramChats = new HashSet<string>(StringComparer.Ordinal);
        private readonly HashSet<string> limitedTelegramChats = new HashSet<string>(StringComparer.Ordinal);
        private readonly Dictionary<string, string> lastHereIpByChat = new Dictionary<string, string>(StringComparer.Ordinal);
        private string lastHereIpGlobal = string.Empty;
        private readonly Dictionary<string, HereProbeTokenState> hereProbeTokens = new Dictionary<string, HereProbeTokenState>(StringComparer.Ordinal);
        private readonly object pendingTelegramCommandsLock = new object();
        private readonly object authorizedTelegramChatsLock = new object();
        private readonly object limitedTelegramChatsLock = new object();
        private readonly object hereIpMemoryLock = new object();
        private readonly object hereProbeTokensLock = new object();
        private readonly object tcpProbeStateLock = new object();
        private readonly object bansLock = new object();
        // login → IP tracking: key = IP (normalized), value = username
        private readonly Dictionary<string, string> activeLogonsByIp = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly object activeLogonsByIpLock = new object();
        private EventLogWatcher? successLogonWatcher;
        private static readonly TimeSpan TcpProbeWindow = TimeSpan.FromSeconds(60);
        private static readonly TimeSpan TcpProbeDedupWindow = TimeSpan.FromSeconds(10);
        private static readonly TimeSpan FailedLogonPortCorrelationWindow = TimeSpan.FromMinutes(5);
        private const int TCP_PROBE_THRESHOLD = 3;
        private HttpListener? hereProbeListener;
        private Thread? hereProbeThread;
        private int diagnosticsHandlersInitialized = 0;

        private sealed class IpFailedUsersState
        {
            public Dictionary<string, DateTime> Users = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        }

        private readonly Dictionary<string, IpFailedUsersState> failedUsersByIp = new Dictionary<string, IpFailedUsersState>(StringComparer.OrdinalIgnoreCase);
        private readonly object failedUsersByIpLock = new object();

        public RDPSecurityService()
        {
            ServiceName = "RDPSecurityService";
            this.ServiceName = "RDPSecurityService";
            CanStop = true;
            CanPauseAndContinue = false;
            AutoLog = false;
        }

        public void StartInteractive(string[] args)
        {
            OnStart(args);
        }

        public void StopInteractive()
        {
            OnStop();
        }

        protected override void OnStart(string[] args)
        {
            RequestAdditionalTime(120000);
            isRunning = true;
            serviceStartUtc = DateTime.UtcNow;
            logDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RDPSecurityService");
            if (!Directory.Exists(logDirectory))
                Directory.CreateDirectory(logDirectory);

            accessLogPath = Path.Combine(logDirectory, "access.log");
            blockListLogPath = Path.Combine(logDirectory, "block_list.log");
            whitelistPath = Path.Combine(logDirectory, "whiteList.log");
            configPath = Path.Combine(logDirectory, "config.json");

            WriteLog("Service start requested by SCM.");
            Program.WriteBootstrapLog("OnStart entered.");

            EnsureCrashDiagnosticsHooks();

            // Keep OnStart fast to avoid SCM timeout (1053) on slower or heavily restricted hosts.
            _ = Task.Run(InitializeServiceRuntime);
        }

        private void EnsureCrashDiagnosticsHooks()
        {
            if (Interlocked.Exchange(ref diagnosticsHandlersInitialized, 1) == 1)
                return;

            AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            {
                string details = e.ExceptionObject?.ToString() ?? "(null)";
                bool terminating = e.IsTerminating;
                try { WriteLog($"Unhandled exception (terminating={terminating}): {details}"); } catch { }
                Program.WriteBootstrapLog($"Unhandled exception (terminating={terminating}): {details}");
            };

            TaskScheduler.UnobservedTaskException += (_, e) =>
            {
                try { WriteLog($"Unobserved task exception: {e.Exception}"); } catch { }
                Program.WriteBootstrapLog($"Unobserved task exception: {e.Exception}");
                e.SetObserved();
            };

            AppDomain.CurrentDomain.ProcessExit += (_, _) =>
            {
                try { WriteLog("ProcessExit fired."); } catch { }
                Program.WriteBootstrapLog("ProcessExit fired.");
            };

            WriteLog("Crash diagnostics hooks initialized.");
            Program.WriteBootstrapLog("Crash diagnostics hooks initialized.");
        }

        private void InitializeServiceRuntime()
        {
            try
            {
                LoadOrCreateConfig();
                WriteLog($"Config: Port={rdpPort}; Levels={string.Join(",", blockLevels.Select(l => $"{l.Attempts}->{l.BlockMinutes}m"))}");

                // ACL update can be slow on some systems/policies. Run it in background.
                _ = Task.Run(() =>
                {
                    try
                    {
                        EnsureSecureAcl(logDirectory);
                    }
                    catch (Exception ex)
                    {
                        WriteLog($"ACL background setup error: {ex.Message}");
                    }
                });

                WriteLog("RDP Security Service started. Monitoring authentication failures...");
                WriteLog($"Logs directory: {logDirectory}");
                WriteLog($"Telegram notifications: {(telegramConfig?.Enabled == true ? "ENABLED" : "DISABLED")}");
                WriteLog("Startup mode: realtime Security 4625 watcher");

                StartFailedLogonWatcher();
                StartSuccessLogonWatcher();

                monitorThread = new Thread(MonitorAuthenticationFailures);
                monitorThread.IsBackground = true;
                monitorThread.Start();

                StartTelegramCommandWatcher();
                StartHereProbeWatcher();

                // Watch for changes in whitelist and blocklist to update firewall rule
                try
                {
                    logWatcher = new FileSystemWatcher(logDirectory);
                    logWatcher.Filter = "*.*";
                    logWatcher.NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.CreationTime;
                    logWatcher.Changed += OnLogChanged;
                    logWatcher.Created += OnLogChanged;
                    logWatcher.Deleted += OnLogChanged;
                    logWatcher.EnableRaisingEvents = true;
                }
                catch { }

                WriteLog("Authentication monitoring thread started.");

                try
                {
                    RequestFirewallSync(force: true);
                }
                catch (Exception ex)
                {
                    WriteLog($"Initial firewall sync error: {ex.Message}");
                }

                SendServiceNotification("🚀 СТАРТАНУЛ СЛУЖБУ");
            }
            catch (Exception ex)
            {
                WriteLog($"Startup initialization error: {ex.Message}");
            }
        }

        // Must match RDPMonitor's ServiceControlResyncFirewall in monitor/MainForm.cs.
        // Custom service control codes are only valid in the 128-255 range.
        private const int ServiceControlResyncFirewall = 128;

        protected override void OnCustomCommand(int command)
        {
            if (command == ServiceControlResyncFirewall)
            {
                WriteLog("Custom command: resync signalled by monitor — re-reading block_list.log/whiteList.log now.");
                try
                {
                    RequestFirewallSync(force: true);
                }
                catch (Exception ex)
                {
                    WriteLog($"Resync-on-signal error: {ex.Message}");
                }
                return;
            }

            base.OnCustomCommand(command);
        }

        protected override void OnStop()
        {
            isRunning = false;
            
            // Send stop notification to Telegram
            SendServiceNotification("🛑 СЛУЖБА ЗУПИНЕНА");
            // try { gateListener?.Stop(); } catch { }

            StopFailedLogonWatcher();
            StopSuccessLogonWatcher();

            if (monitorThread != null)
                monitorThread.Join(5000);

            try
            {
                if (telegramCommandThread != null && telegramCommandThread.IsAlive)
                    telegramCommandThread.Join(5000);
            }
            catch { }

            try
            {
                if (hereProbeListener != null && hereProbeListener.IsListening)
                    hereProbeListener.Stop();
            }
            catch { }

            try
            {
                if (hereProbeThread != null && hereProbeThread.IsAlive)
                    hereProbeThread.Join(5000);
            }
            catch { }

            // Gate functionality disabled
            // try
            // {
            //     if (gateThread != null && gateThread.IsAlive)
            //         gateThread.Join(2000);
            // }
            // catch { }

            WriteLog("RDP Security Service stopping...");

            try
            {
                WriteLog("RDP Security Service stopped.");
            }
            catch
            {
                WriteLog($"Error stopping service");
            }
        }
        private void MonitorAuthenticationFailures()
        {
            while (isRunning)
            {
                try
                {
                    MonitorTcpProbeConnections(DateTime.Now);
                }
                catch (Exception ex)
                {
                    WriteLog($"Monitor error: {ex.Message}");
                    SendServiceNotification($"🔴 УПАЛ: {ex.Message}");
                }

                Thread.Sleep(CHECK_INTERVAL);
            }
        }

        private void StartSuccessLogonWatcher()
        {
            try
            {
                // Watch 4624 (logon success) and 4634/4647 (logoff) to maintain activeLogonsByIp
                var query = new EventLogQuery("Security", PathType.LogName, "*[System[(EventID=4624 or EventID=4634 or EventID=4647)]]")
                {
                    ReverseDirection = false,
                    TolerateQueryErrors = true
                };
                successLogonWatcher = new EventLogWatcher(query);
                successLogonWatcher.EventRecordWritten += OnSuccessLogonEventRecordWritten;
                successLogonWatcher.Enabled = true;
                WriteLog("Security 4624/4634/4647 watcher started.");
            }
            catch (Exception ex)
            {
                WriteLog($"Success logon watcher start error: {ex.Message}");
            }
        }

        private void StopSuccessLogonWatcher()
        {
            try
            {
                if (successLogonWatcher == null) return;
                successLogonWatcher.Enabled = false;
                successLogonWatcher.EventRecordWritten -= OnSuccessLogonEventRecordWritten;
                successLogonWatcher.Dispose();
                successLogonWatcher = null;
                WriteLog("Security 4624/4634/4647 watcher stopped.");
            }
            catch (Exception ex)
            {
                WriteLog($"Success logon watcher stop error: {ex.Message}");
            }
        }

        private void OnSuccessLogonEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
        {
            if (!isRunning || e.EventException != null || e.EventRecord == null) return;
            EventRecord record = e.EventRecord;
            try
            {
                int eventId = record.Id;
                string xml = record.ToXml();

                if (eventId == 4624)
                {
                    // LogonType 10 = RemoteInteractive (RDP), also accept 3 (Network) as some RDP clients use it
                    string logonTypeStr = ExtractEventDataField(xml, "LogonType");
                    if (logonTypeStr != "10" && logonTypeStr != "3") return;

                    string ip = ExtractEventDataField(xml, "IpAddress");
                    if (string.IsNullOrWhiteSpace(ip) || ip == "-" || ip == "::1" || ip == "127.0.0.1") return;

                    string login = ExtractEventDataField(xml, "TargetUserName");
                    string normalizedIp = NormalizeIpCandidate(ip);
                    if (string.IsNullOrWhiteSpace(normalizedIp)) return;

                    lock (activeLogonsByIpLock)
                    {
                        activeLogonsByIp[normalizedIp] = login;
                    }
                    WriteLog($"Active logon registered: {login} from {normalizedIp}");
                }
                else // 4634 or 4647 — logoff
                {
                    string ip = ExtractEventDataField(xml, "IpAddress");
                    if (string.IsNullOrWhiteSpace(ip) || ip == "-") return;
                    string normalizedIp = NormalizeIpCandidate(ip);
                    if (string.IsNullOrWhiteSpace(normalizedIp)) return;

                    lock (activeLogonsByIpLock)
                    {
                        activeLogonsByIp.Remove(normalizedIp);
                    }
                    WriteLog($"Active logon removed for IP: {normalizedIp} (event {eventId})");
                }
            }
            catch (Exception ex)
            {
                WriteLog($"Success logon watcher callback error: {ex.Message}");
            }
            finally
            {
                try { record.Dispose(); } catch { }
            }
        }

        private void StartFailedLogonWatcher()
        {
            try
            {
                var query = new EventLogQuery("Security", PathType.LogName, "*[System[(EventID=4625)]]")
                {
                    ReverseDirection = false,
                    TolerateQueryErrors = true
                };

                failedLogonWatcher = new EventLogWatcher(query);
                failedLogonWatcher.EventRecordWritten += OnFailedLogonEventRecordWritten;
                failedLogonWatcher.Enabled = true;
                WriteLog("Security 4625 watcher started.");
            }
            catch (Exception ex)
            {
                WriteLog($"Watcher start error: {ex.Message}");
                SendServiceNotification($"🔴 УПАЛ: watcher start error: {ex.Message}");
            }
        }

        private void StopFailedLogonWatcher()
        {
            try
            {
                if (failedLogonWatcher == null)
                    return;

                failedLogonWatcher.Enabled = false;
                failedLogonWatcher.EventRecordWritten -= OnFailedLogonEventRecordWritten;
                failedLogonWatcher.Dispose();
                failedLogonWatcher = null!;
                WriteLog("Security 4625 watcher stopped.");
            }
            catch (Exception ex)
            {
                WriteLog($"Watcher stop error: {ex.Message}");
            }
        }

        private void OnFailedLogonEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
        {
            if (!isRunning)
                return;

            if (e.EventException != null)
            {
                WriteLog($"Watcher callback error: {e.EventException.Message}");
                return;
            }

            EventRecord record = e.EventRecord;
            if (record == null)
                return;

            try
            {
                string sourceIP = ExtractSourceIpFromEventRecord(record);
                if (string.IsNullOrEmpty(sourceIP) || sourceIP == "::1" || sourceIP == "127.0.0.1" || sourceIP == "-")
                {
                    WriteLog($"4625 without valid source IP (Record={record.RecordId})");
                    DumpSuspicious4625(record);
                    return;
                }

                DateTime eventTimeLocal = (record.TimeCreated ?? DateTime.UtcNow).ToLocalTime();
                if (!HasRecentRdpPortActivity(sourceIP, DateTime.Now))
                {
                    WriteLog($"4625 weak-correlation: no recent TCP activity on configured RDP port {rdpPort}; processing anyway. ip={sourceIP}");
                }

                ProcessFailedLogonEvent(sourceIP, ExtractTargetUserFromEventRecord(record), eventTimeLocal);
            }
            catch (Exception ex)
            {
                WriteLog($"Watcher process error: {ex.Message}");
            }
            finally
            {
                try { record.Dispose(); } catch { }
            }
        }

        private void ProcessFailedLogonEvent(string sourceIP, string targetUser, DateTime eventTimeLocal)
        {
            if (IsIPWhitelisted(sourceIP))
            {
                return;
            }

            // If the failing user is the same as the currently logged-in user from this IP
            // (e.g. screen unlock typo) — ignore, don't count. Only count if it's a different
            // user (brute-force from same NAT IP).
            string normalizedSource = NormalizeIpCandidate(sourceIP);
            if (!string.IsNullOrWhiteSpace(normalizedSource) && !string.IsNullOrWhiteSpace(targetUser))
            {
                string? activeUser = null;
                lock (activeLogonsByIpLock)
                {
                    activeLogonsByIp.TryGetValue(normalizedSource, out activeUser);
                }
                if (!string.IsNullOrWhiteSpace(activeUser) &&
                    string.Equals(activeUser, targetUser, StringComparison.OrdinalIgnoreCase))
                {
                    WriteLog($"Ignored failed logon — same user '{targetUser}' is active from {sourceIP} (screen unlock typo?)");
                    return;
                }
            }

            int attempts;
            DateTime nowLocal = DateTime.Now;
            lock (failedAttemptsLock)
            {
                if (!failedAttempts.TryGetValue(sourceIP, out List<DateTime>? timestamps))
                {
                    timestamps = new List<DateTime>();
                    failedAttempts[sourceIP] = timestamps;
                }

                DateTime cutoff = nowLocal.AddDays(-Math.Max(1, failedAttemptsWindowDays));
                timestamps.RemoveAll(ts => ts < cutoff);
                timestamps.Add(nowLocal);
                attempts = timestamps.Count;
            }

            WriteAccessLog(sourceIP, eventTimeLocal, attempts);
            SendAccessAttemptNotification(sourceIP, targetUser, attempts, eventTimeLocal);
            TryApplySprayBan(targetUser, sourceIP, eventTimeLocal, DateTime.Now);
            TryApplySubnetUserSprayBan(targetUser, sourceIP, eventTimeLocal, DateTime.Now);

            var level = GetLevelForAttempts(attempts);
            if (level != null && ShouldApplyBan(sourceIP, attempts, level, DateTime.Now))
            {
                bool ipAbuseDetected = RegisterFailedUserAndCheckIpAbuse(sourceIP, targetUser, DateTime.Now);
                if (!ipAbuseDetected)
                {
                    WriteLog($"Per-IP threshold reached for {sourceIP}; proceeding with ban without spray signal (distinct users < {ipAbuseDistinctUsersThreshold} in {ipAbuseWindowMinutes}m)");
                }

                ApplyIpBan(
                    sourceIP,
                    eventTimeLocal,
                    attempts,
                    level.BlockMinutes,
                    level.Attempts,
                    ipAbuseDetected ? "per-ip-threshold+spray-signal" : "per-ip-threshold",
                    targetUser);
            }
        }

        private string ExtractSourceIpFromEventRecord(EventRecord record)
        {
            string xml = record.ToXml();
            return ExtractEventDataField(xml, "IpAddress");
        }

        private string ExtractTargetUserFromEventRecord(EventRecord record)
        {
            string xml = record.ToXml();
            return ExtractEventDataField(xml, "TargetUserName");
        }

        private string ExtractEventDataField(string xml, string fieldName)
        {
            if (string.IsNullOrWhiteSpace(xml) || string.IsNullOrWhiteSpace(fieldName))
                return "-";

            Match match = Regex.Match(
                xml,
                $"<Data Name=['\"]{Regex.Escape(fieldName)}['\"]>(.*?)</Data>",
                RegexOptions.IgnoreCase | RegexOptions.Singleline);

            if (!match.Success || match.Groups.Count < 2)
                return "-";

            string value = WebUtility.HtmlDecode(match.Groups[1].Value).Trim();
            return string.IsNullOrWhiteSpace(value) ? "-" : value;
        }
        
        private void SendServiceNotification(string message)
        {
            try
            {
                var cfg = telegramConfig;
                if (cfg == null || !cfg.Enabled || string.IsNullOrWhiteSpace(cfg.BotToken) || string.IsNullOrWhiteSpace(cfg.ChatId))
                {
                    WriteLog($"Telegram disabled or not configured. Message not sent: {message}");
                    return;
                }

                WriteLog($"Sending Telegram notification: {message}");
                TrySendTelegramText(cfg.ChatId, message);
            }
            catch (Exception ex)
            {
                WriteLog($"Service notification error: {ex.Message}");
            }
        }

        private bool TrySendTelegramText(string chatId, string message, string? replyMarkupJson = null)
        {
            try
            {
                var cfg = telegramConfig;
                if (cfg == null || !cfg.Enabled || string.IsNullOrWhiteSpace(cfg.BotToken) || string.IsNullOrWhiteSpace(chatId))
                    return false;

                string normalizedMessage = NormalizeTelegramText(message);
                string effectiveReplyMarkupJson = string.IsNullOrWhiteSpace(replyMarkupJson)
                    ? BuildDefaultKeyboardJsonForChat(chatId)
                    : replyMarkupJson;

                using (var client = new System.Net.Http.HttpClient())
                {
                    client.Timeout = TimeSpan.FromSeconds(15);
                    var url = $"https://api.telegram.org/bot{cfg.BotToken}/sendMessage";
                    var formFields = new List<KeyValuePair<string, string>>
                    {
                        new KeyValuePair<string, string>("chat_id", chatId),
                        new KeyValuePair<string, string>("text", normalizedMessage)
                    };

                    if (!string.IsNullOrWhiteSpace(effectiveReplyMarkupJson))
                        formFields.Add(new KeyValuePair<string, string>("reply_markup", effectiveReplyMarkupJson));

                    var content = new System.Net.Http.FormUrlEncodedContent(formFields);

                    var task = client.PostAsync(url, content);
                    task.Wait(TimeSpan.FromSeconds(15));
                    if (!task.IsCompletedSuccessfully)
                    {
                        if (task.IsFaulted)
                            WriteLog($"Telegram send failed: {task.Exception?.InnerException?.Message}");
                        return false;
                    }

                    var response = task.Result;
                    if (!response.IsSuccessStatusCode)
                    {
                        WriteLog($"Telegram send failed: {response.StatusCode}");
                        return false;
                    }

                    return true;
                }
            }
            catch (Exception ex)
            {
                WriteLog($"Telegram send error: {ex.Message}");
                return false;
            }
        }

        private string BuildCommandKeyboardJson()
        {
            var keyboard = new
            {
                keyboard = new[]
                {
                    new[] { UiText("Статуси", "Statuses"), UiText("Адмін", "Admin") }
                },
                resize_keyboard = true,
                one_time_keyboard = false,
                selective = true,
                input_field_placeholder = UiText("Оберіть розділ або введіть команду вручну", "Choose a section or type a command manually")
            };

            return JsonSerializer.Serialize(keyboard);
        }

        private string BuildAdminKeyboardJson()
        {
            var keyboard = new
            {
                keyboard = new[]
                {
                    new[] { "/adduser", "/groupmembers" },
                    new[] { "/ban", "/unban" },
                    new[] { "/monitor start", "/monitor stop" },
                    new[] { "/service stop", UiText("Назад", "Back") }
                },
                resize_keyboard = true,
                one_time_keyboard = false,
                selective = true,
                input_field_placeholder = UiText("Адмін-команди", "Admin commands")
            };

            return JsonSerializer.Serialize(keyboard);
        }

        private string BuildStatusKeyboardJson()
        {
            var keyboard = new
            {
                keyboard = new[]
                {
                    new[] { "/status", "/status all" },
                    new[] { "/thresholds", "/here" },
                    new[] { UiText("Назад", "Back") }
                },
                resize_keyboard = true,
                one_time_keyboard = false,
                selective = true,
                input_field_placeholder = UiText("Статуси та діагностика", "Statuses and diagnostics")
            };

            return JsonSerializer.Serialize(keyboard);
        }

        private string BuildKeyboardRemoveJson()
        {
            var keyboard = new
            {
                remove_keyboard = true,
                selective = true
            };

            return JsonSerializer.Serialize(keyboard);
        }

        private string BuildDefaultKeyboardJsonForChat(string chatId)
        {
            if (IsLimitedTelegramChatAuthorized(chatId) && !IsTelegramChatAuthorized(chatId))
                return BuildSelfUnbanKeyboardJson();

            return BuildCommandKeyboardJson();
        }

        private string BuildSelfUnbanKeyboardJson()
        {
            var keyboard = new
            {
                keyboard = new[]
                {
                    new[] { UiText("Розблокуй мене", "Unblock me") }
                },
                resize_keyboard = true,
                one_time_keyboard = false,
                selective = true,
                input_field_placeholder = UiText("Натисніть кнопку для саморозблокування", "Press button for self-unban")
            };

            return JsonSerializer.Serialize(keyboard);
        }

        private bool IsSelfUnbanButtonText(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return false;

            string trimmed = text.Trim();
            return trimmed.Equals(UiText("Розблокуй мене", "Unblock me"), StringComparison.OrdinalIgnoreCase)
                || trimmed.Equals("Разлочь меня", StringComparison.OrdinalIgnoreCase)
                || trimmed.Equals("Unblock me", StringComparison.OrdinalIgnoreCase);
        }

        private bool IsGroupMembersButtonText(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return false;

            string trimmed = text.Trim();
            return trimmed.Equals("Пользователи в группе: членство в канале", StringComparison.OrdinalIgnoreCase)
                || trimmed.Equals("Користувачі в групі: членство в каналі", StringComparison.OrdinalIgnoreCase)
                || trimmed.Equals("Users in group: channel membership", StringComparison.OrdinalIgnoreCase);
        }

        private bool IsAdminMenuButtonText(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return false;

            string trimmed = text.Trim();
            return trimmed.Equals(UiText("Адмін", "Admin"), StringComparison.OrdinalIgnoreCase)
                || trimmed.Equals("Админ", StringComparison.OrdinalIgnoreCase)
                || trimmed.Equals("Admin", StringComparison.OrdinalIgnoreCase);
        }

        private bool IsStatusMenuButtonText(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return false;

            string trimmed = text.Trim();
            return trimmed.Equals(UiText("Статуси", "Statuses"), StringComparison.OrdinalIgnoreCase)
                || trimmed.Equals("Статусы", StringComparison.OrdinalIgnoreCase)
                || trimmed.Equals("Statuses", StringComparison.OrdinalIgnoreCase);
        }

        private bool IsBackMenuButtonText(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return false;

            string trimmed = text.Trim();
            return trimmed.Equals(UiText("Назад", "Back"), StringComparison.OrdinalIgnoreCase)
                || trimmed.Equals("Назад", StringComparison.OrdinalIgnoreCase)
                || trimmed.Equals("Back", StringComparison.OrdinalIgnoreCase);
        }

        private string BuildContactRequestKeyboardJson()
        {
            var keyboard = new
            {
                keyboard = new object[]
                {
                    new object[]
                    {
                        new
                        {
                            text = UiText("Поділитися телефоном", "Share phone"),
                            request_contact = true
                        }
                    }
                },
                resize_keyboard = true,
                one_time_keyboard = false,
                selective = true,
                input_field_placeholder = UiText("Поділіться номером телефону", "Share your phone number")
            };

            return JsonSerializer.Serialize(keyboard);
        }

        private string BuildForceReplyJson(string placeholder)
        {
            var reply = new
            {
                force_reply = true,
                selective = true,
                input_field_placeholder = placeholder
            };

            return JsonSerializer.Serialize(reply);
        }

        private static string NormalizeTelegramText(string message)
        {
            if (string.IsNullOrEmpty(message))
                return string.Empty;

            return message
                .Replace("`r`n", "\n")
                .Replace("`n", "\n")
                .Replace("\\r\\n", "\n")
                .Replace("\\n", "\n")
                .Replace("\r\n", "\n")
                .Replace("\r", "\n");
        }

        private void StartTelegramCommandWatcher()
        {
            try
            {
                telegramCommandThread = new Thread(MonitorTelegramCommands);
                telegramCommandThread.IsBackground = true;
                telegramCommandThread.Start();
                WriteLog("Telegram command watcher started.");
            }
            catch (Exception ex)
            {
                WriteLog($"Telegram command watcher start error: {ex.Message}");
            }
        }

        private void MonitorTelegramCommands()
        {
            while (isRunning)
            {
                try
                {
                    PollTelegramCommands();
                }
                catch (Exception ex)
                {
                    WriteLog($"Telegram command poll error: {ex.Message}");
                }

                Thread.Sleep(1500);
            }
        }

        private void StartHereProbeWatcher()
        {
            try
            {
                var cfg = telegramConfig;
                if (cfg == null || !cfg.HereProbeEnabled)
                    return;

                if (string.IsNullOrWhiteSpace(cfg.HereProbeListenPrefix))
                {
                    WriteLog("Here probe listener disabled: empty hereProbeListenPrefix in config.");
                    return;
                }

                hereProbeListener = new HttpListener();
                string prefix = cfg.HereProbeListenPrefix.Trim();
                if (!prefix.EndsWith("/", StringComparison.Ordinal))
                    prefix += "/";

                hereProbeListener.Prefixes.Add(prefix);
                hereProbeListener.Start();

                hereProbeThread = new Thread(MonitorHereProbeRequests);
                hereProbeThread.IsBackground = true;
                hereProbeThread.Start();

                WriteLog($"Here probe listener started on {prefix}");
            }
            catch (Exception ex)
            {
                WriteLog($"Here probe listener start error: {ex.Message}");
            }
        }

        private void MonitorHereProbeRequests()
        {
            while (isRunning)
            {
                try
                {
                    if (hereProbeListener == null || !hereProbeListener.IsListening)
                        return;

                    HttpListenerContext context = hereProbeListener.GetContext();
                    HandleHereProbeRequest(context);
                }
                catch (HttpListenerException)
                {
                    if (!isRunning)
                        return;
                }
                catch (Exception ex)
                {
                    WriteLog($"Here probe request error: {ex.Message}");
                }
            }
        }

        private void HandleHereProbeRequest(HttpListenerContext context)
        {
            try
            {
                string token = context.Request.QueryString["t"] ?? string.Empty;
                if (string.IsNullOrWhiteSpace(token))
                {
                    WriteHereProbeResponse(context, 400, "Немає токена. Поверніться в Telegram і натисніть /here ще раз.");
                    return;
                }

                string chatId;
                lock (hereProbeTokensLock)
                {
                    CleanupExpiredHereProbeTokens();
                    if (!hereProbeTokens.TryGetValue(token, out HereProbeTokenState? tokenState))
                    {
                        WriteHereProbeResponse(context, 404, "Токен недійсний або прострочений. Поверніться в Telegram і натисніть /here ще раз.");
                        return;
                    }

                    chatId = tokenState.ChatId;
                }

                if (IsLikelyPreviewRequest(context.Request.UserAgent))
                {
                    WriteHereProbeResponse(context, 200, "Посилання активне. Відкрийте його напряму в браузері телефона, щоб продовжити.");
                    return;
                }

                string remoteNormalized = ExtractClientIpFromProbeRequest(context.Request);
                if (string.IsNullOrWhiteSpace(remoteNormalized) || !IPAddress.TryParse(remoteNormalized, out IPAddress parsedIp))
                {
                    WriteHereProbeResponse(context, 400, "Не вдалося визначити ваш IP із цього запиту.");
                    return;
                }

                if (IPAddress.IsLoopback(parsedIp) || IsPrivateIp(parsedIp))
                {
                    WriteHereProbeResponse(context, 400, "Не вдалося визначити публічний IP. Вимкніть preview посилань і відкрийте його напряму з телефона.");
                    return;
                }

                string ip = parsedIp.ToString();
                RememberHereIp(chatId, ip);
                TrySendTelegramText(chatId, BuildIpStatusReply(ip));

                lock (hereProbeTokensLock)
                {
                    hereProbeTokens.Remove(token);
                }

                WriteHereProbeResponse(context, 200, "IP отримано. Поверніться в Telegram: статус уже надіслано.");
            }
            catch (Exception ex)
            {
                WriteLog($"Here probe handler error: {ex.Message}");
                try { WriteHereProbeResponse(context, 500, "Внутрішня помилка. Поверніться в Telegram і спробуйте ще раз."); } catch { }
            }
        }

        private void WriteHereProbeResponse(HttpListenerContext context, int statusCode, string message)
        {
            context.Response.StatusCode = statusCode;
            context.Response.ContentType = "text/html; charset=utf-8";

            string safe = WebUtility.HtmlEncode(message);
            string html = "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>RDP Security</title></head><body style=\"font-family:Segoe UI,Arial,sans-serif;padding:20px;\"><h3>RDP Security Service</h3><p>" + safe + "</p></body></html>";
            byte[] buffer = Encoding.UTF8.GetBytes(html);
            context.Response.ContentLength64 = buffer.Length;
            using (Stream output = context.Response.OutputStream)
            {
                output.Write(buffer, 0, buffer.Length);
            }
        }

        private string ExtractClientIpFromProbeRequest(HttpListenerRequest request)
        {
            string[] headerCandidates =
            {
                "CF-Connecting-IP",
                "True-Client-IP",
                "X-Real-IP",
                "X-Forwarded-For"
            };

            for (int i = 0; i < headerCandidates.Length; i++)
            {
                string headerValue = request.Headers[headerCandidates[i]] ?? string.Empty;
                if (string.IsNullOrWhiteSpace(headerValue))
                    continue;

                string[] parts = headerValue.Split(',');
                for (int j = 0; j < parts.Length; j++)
                {
                    string candidate = NormalizeIpCandidate(parts[j]);
                    if (!string.IsNullOrWhiteSpace(candidate))
                        return candidate;
                }
            }

            string remoteRaw = request.RemoteEndPoint?.Address?.ToString() ?? string.Empty;
            return NormalizeIpCandidate(remoteRaw);
        }

        private bool IsLikelyPreviewRequest(string? userAgent)
        {
            if (string.IsNullOrWhiteSpace(userAgent))
                return false;

            string ua = userAgent.Trim();
            return ua.IndexOf("TelegramBot", StringComparison.OrdinalIgnoreCase) >= 0
                || ua.IndexOf("bot", StringComparison.OrdinalIgnoreCase) >= 0
                || ua.IndexOf("crawler", StringComparison.OrdinalIgnoreCase) >= 0
                || ua.IndexOf("spider", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private bool IsPrivateIp(IPAddress ip)
        {
            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                byte[] b = ip.GetAddressBytes();
                if (b[0] == 10)
                    return true;
                if (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                    return true;
                if (b[0] == 192 && b[1] == 168)
                    return true;
                if (b[0] == 169 && b[1] == 254)
                    return true;
                return false;
            }

            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal)
                    return true;

                byte[] b = ip.GetAddressBytes();
                // fc00::/7 (unique local addresses)
                return (b[0] & 0xFE) == 0xFC;
            }

            return false;
        }

        private void CleanupExpiredHereProbeTokens()
        {
            DateTime nowUtc = DateTime.UtcNow;
            var expired = hereProbeTokens
                .Where(kv => (nowUtc - kv.Value.CreatedUtc) > HereProbeTokenTtl)
                .Select(kv => kv.Key)
                .ToList();

            for (int i = 0; i < expired.Count; i++)
                hereProbeTokens.Remove(expired[i]);
        }

        private void PollTelegramCommands()
        {
            var cfg = telegramConfig;
            if (cfg == null || !cfg.Enabled || string.IsNullOrWhiteSpace(cfg.BotToken) || string.IsNullOrWhiteSpace(cfg.ChatId))
                return;

            using (var client = new System.Net.Http.HttpClient())
            {
                client.Timeout = TimeSpan.FromSeconds(35);

                if (!telegramPollingModeEnsured)
                {
                    EnsureTelegramPollingMode(client, cfg);
                }

                string url = $"https://api.telegram.org/bot{cfg.BotToken}/getUpdates?offset={telegramUpdateOffset}&timeout=25";
                var task = client.GetAsync(url);
                task.Wait(TimeSpan.FromSeconds(35));
                if (!task.IsCompletedSuccessfully)
                    return;

                var response = task.Result;
                if (!response.IsSuccessStatusCode)
                {
                    string errorBody = string.Empty;
                    try
                    {
                        errorBody = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                    }
                    catch
                    {
                        errorBody = string.Empty;
                    }

                    WriteLog($"Telegram getUpdates failed: {response.StatusCode}; body={errorBody}");

                    if ((int)response.StatusCode == 409)
                    {
                        telegramPollingModeEnsured = false;
                        EnsureTelegramPollingMode(client, cfg);
                    }
                    return;
                }

                string json = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                using (JsonDocument document = JsonDocument.Parse(json))
                {
                    if (!document.RootElement.TryGetProperty("ok", out JsonElement okElement) || !okElement.GetBoolean())
                        return;

                    if (!document.RootElement.TryGetProperty("result", out JsonElement resultElement) || resultElement.ValueKind != JsonValueKind.Array)
                        return;

                    long maxUpdateId = telegramUpdateOffset - 1;
                    if (!telegramCommandBootstrapDone)
                    {
                        DateTime recentThresholdUtc = serviceStartUtc.AddSeconds(-10);
                        long skippedBacklogUpdateId = telegramUpdateOffset - 1;

                        foreach (JsonElement update in resultElement.EnumerateArray())
                        {
                            if (!update.TryGetProperty("update_id", out JsonElement updateIdElement) || !updateIdElement.TryGetInt64(out long bootstrapUpdateId))
                                continue;

                            maxUpdateId = Math.Max(maxUpdateId, bootstrapUpdateId);

                            if (!update.TryGetProperty("message", out JsonElement bootstrapMessageElement))
                            {
                                skippedBacklogUpdateId = Math.Max(skippedBacklogUpdateId, bootstrapUpdateId);
                                continue;
                            }

                            string bootstrapChatId = string.Empty;
                            if (bootstrapMessageElement.TryGetProperty("chat", out JsonElement bootstrapChatElement)
                                && bootstrapChatElement.TryGetProperty("id", out JsonElement bootstrapChatIdElement))
                            {
                                bootstrapChatId = bootstrapChatIdElement.ToString();
                            }

                            long messageUnix = 0;
                            if (bootstrapMessageElement.TryGetProperty("date", out JsonElement bootstrapDateElement))
                                bootstrapDateElement.TryGetInt64(out messageUnix);

                            DateTime messageUtc = messageUnix > 0
                                ? DateTimeOffset.FromUnixTimeSeconds(messageUnix).UtcDateTime
                                : DateTime.MinValue;

                            bool keepForProcessing = string.Equals(bootstrapChatId, cfg.ChatId, StringComparison.Ordinal)
                                && messageUtc >= recentThresholdUtc;

                            if (!keepForProcessing)
                                skippedBacklogUpdateId = Math.Max(skippedBacklogUpdateId, bootstrapUpdateId);
                        }

                        telegramCommandBootstrapDone = true;
                        if (skippedBacklogUpdateId >= telegramUpdateOffset)
                        {
                            telegramUpdateOffset = skippedBacklogUpdateId + 1;
                            WriteLog($"Telegram command watcher skipped backlog up to update_id={skippedBacklogUpdateId}");
                        }
                    }

                    foreach (JsonElement update in resultElement.EnumerateArray())
                    {
                        if (!update.TryGetProperty("update_id", out JsonElement updateIdElement) || !updateIdElement.TryGetInt64(out long updateId))
                            continue;

                        if (updateId < telegramUpdateOffset)
                            continue;

                        maxUpdateId = Math.Max(maxUpdateId, updateId);

                        if (!update.TryGetProperty("message", out JsonElement messageElement))
                            continue;

                        if (!messageElement.TryGetProperty("chat", out JsonElement chatElement))
                            continue;

                        string incomingChatId = chatElement.TryGetProperty("id", out JsonElement chatIdElement)
                            ? chatIdElement.ToString()
                            : string.Empty;

                        string text = messageElement.TryGetProperty("text", out JsonElement textElement)
                            ? textElement.GetString() ?? string.Empty
                            : string.Empty;

                        string contactPhone = TryExtractContactPhone(messageElement);
                        bool isAdminAuthorized = IsTelegramChatAuthorized(incomingChatId);
                        bool isLimitedAuthorized = IsLimitedTelegramChatAuthorized(incomingChatId);

                        if (!string.Equals(incomingChatId, cfg.ChatId, StringComparison.Ordinal)
                            && !isAdminAuthorized
                            && !isLimitedAuthorized)
                        {
                            bool canAttemptLogin = false;
                            string trimmedIncoming = text.Trim();

                            if (trimmedIncoming.StartsWith("/start", StringComparison.OrdinalIgnoreCase))
                            {
                                canAttemptLogin = true;
                            }

                            if (!string.IsNullOrWhiteSpace(contactPhone))
                            {
                                canAttemptLogin = true;
                            }

                            if (!canAttemptLogin)
                            {
                                WriteLog($"Ignoring Telegram command from unauthorized chat: {incomingChatId}");
                                continue;
                            }
                        }

                        if (!string.IsNullOrWhiteSpace(contactPhone))
                        {
                            WriteLog($"Telegram contact received from chat {incomingChatId}");
                            HandleTelegramContactShare(incomingChatId, contactPhone);
                            continue;
                        }

                        if (!string.IsNullOrWhiteSpace(text))
                        {
                            WriteLog($"Telegram command received: {text}");
                            HandleTelegramCommand(incomingChatId, text);
                        }
                    }

                    if (maxUpdateId >= telegramUpdateOffset)
                        telegramUpdateOffset = maxUpdateId + 1;
                }
            }
        }

        private void EnsureTelegramPollingMode(System.Net.Http.HttpClient client, TelegramConfig cfg)
        {
            try
            {
                string deleteWebhookUrl = $"https://api.telegram.org/bot{cfg.BotToken}/deleteWebhook?drop_pending_updates=false";
                var task = client.GetAsync(deleteWebhookUrl);
                task.Wait(TimeSpan.FromSeconds(15));
                if (!task.IsCompletedSuccessfully)
                {
                    WriteLog("Telegram deleteWebhook did not complete successfully.");
                    return;
                }

                var response = task.Result;
                string body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                if (!response.IsSuccessStatusCode)
                {
                    WriteLog($"Telegram deleteWebhook failed: {response.StatusCode}; body={body}");
                    return;
                }

                try
                {
                    using (JsonDocument document = JsonDocument.Parse(body))
                    {
                        if (document.RootElement.TryGetProperty("ok", out JsonElement okElement) && okElement.GetBoolean())
                        {
                            telegramPollingModeEnsured = true;
                            WriteLog("Telegram polling mode ensured (webhook disabled).");
                            return;
                        }
                    }
                }
                catch
                {
                    // Ignore parse errors and fall through to generic log.
                }

                WriteLog($"Telegram deleteWebhook unexpected response: {body}");
            }
            catch (Exception ex)
            {
                WriteLog($"Telegram polling mode ensure error: {ex.Message}");
            }
        }

        private void HandleTelegramCommand(string chatId, string text)
        {
            try
            {
                string trimmed = (text ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(trimmed))
                    return;

                if (!trimmed.StartsWith("/", StringComparison.Ordinal) && TryHandlePendingTelegramInput(chatId, trimmed))
                    return;

                string[] parts = trimmed.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 0)
                    return;

                string command = parts[0];
                int atIndex = command.IndexOf('@');
                if (atIndex >= 0)
                    command = command.Substring(0, atIndex);

                command = command.ToLowerInvariant();

                bool isAdminChat = IsTelegramChatAuthorized(chatId) || string.Equals(chatId, telegramConfig?.ChatId, StringComparison.Ordinal);
                bool isLimitedChat = IsLimitedTelegramChatAuthorized(chatId);

                if (command == "/start")
                {
                    ClearPendingTelegramCommand(chatId);

                    if (isAdminChat)
                    {
                        AuthorizeTelegramChat(chatId);
                        // Force keyboard refresh in Telegram clients that cache old layouts.
                        TrySendTelegramText(chatId, UiText("Оновлюю клавіатуру...", "Refreshing keyboard..."), BuildKeyboardRemoveJson());
                        TrySendTelegramText(
                            chatId,
                            UiText($"✅ Вхід виконано. Команди розблоковано.\nUI: {Program.TelegramUiRevision}", $"✅ Signed in. Commands are unlocked.\nUI: {Program.TelegramUiRevision}"),
                            BuildCommandKeyboardJson());
                        return;
                    }

                    AuthorizeLimitedTelegramChat(chatId);
                    // Force keyboard refresh in Telegram clients that cache old layouts.
                    TrySendTelegramText(chatId, UiText("Оновлюю клавіатуру...", "Refreshing keyboard..."), BuildKeyboardRemoveJson());
                    TrySendTelegramText(
                        chatId,
                        UiText($"✅ Доступ обмеженого користувача активовано.\nUI: {Program.TelegramUiRevision}", $"✅ Limited user access activated.\nUI: {Program.TelegramUiRevision}"),
                        BuildSelfUnbanKeyboardJson());
                    return;
                }

                if (!isAdminChat && !isLimitedChat)
                {
                    if (command == "/cancel")
                    {
                        ClearPendingTelegramCommand(chatId);
                        TrySendTelegramText(chatId, UiText("Дію скасовано. Для входу виконайте /start", "Action cancelled. Run /start to sign in."));
                        return;
                    }

                    TrySendTelegramText(chatId, UiText("🔒 Доступ закрито. Спочатку виконайте /start.", "🔒 Access is locked. Run /start first."));
                    return;
                }

                if (isLimitedChat && !isAdminChat)
                {
                    if (command == "/cancel")
                    {
                        ClearPendingTelegramCommand(chatId);
                        TrySendTelegramText(chatId, UiText("Дію скасовано.", "Action cancelled."), BuildSelfUnbanKeyboardJson());
                        return;
                    }

                    bool isSelfUnbanButton = IsSelfUnbanButtonText(trimmed);
                    if (isSelfUnbanButton || command == "/unbanme")
                    {
                        ClearPendingTelegramCommand(chatId);
                        string selfUnbanIp = telegramConfig?.SelfUnbanIp ?? string.Empty;
                        if (string.IsNullOrWhiteSpace(selfUnbanIp))
                        {
                            TrySendTelegramText(
                                chatId,
                                UiText("Self-unban IP не налаштовано в config.json (telegram.selfUnbanIp).", "Self-unban IP is not configured in config.json (telegram.selfUnbanIp)."),
                                BuildSelfUnbanKeyboardJson());
                            return;
                        }

                        TelegramUnblockResult limitedUnbanResult = UnblockIpFromTelegramCore(selfUnbanIp);
                        TrySendTelegramText(
                            chatId,
                            limitedUnbanResult.WasUnblocked
                                ? "ок разлочил"
                                : "не нашел, у тебя все ОК",
                            BuildSelfUnbanKeyboardJson());
                        return;
                    }

                    if (command == "/?" || command == "/help")
                    {
                        TrySendTelegramText(chatId, BuildLimitedHelpReply(), BuildSelfUnbanKeyboardJson());
                        return;
                    }

                    TrySendTelegramText(
                        chatId,
                        UiText("Для вашої ролі доступна лише кнопка «Розблокуй мене».", "Only the 'Unblock me' button is available for your role."),
                        BuildSelfUnbanKeyboardJson());
                    return;
                }

                if (IsSelfUnbanButtonText(trimmed) || command == "/unbanme")
                {
                    ClearPendingTelegramCommand(chatId);
                    string adminSelfUnbanIp = telegramConfig?.SelfUnbanIp ?? string.Empty;
                    if (string.IsNullOrWhiteSpace(adminSelfUnbanIp))
                    {
                        TrySendTelegramText(
                            chatId,
                            UiText("Self-unban IP не налаштовано в config.json (telegram.selfUnbanIp).", "Self-unban IP is not configured in config.json (telegram.selfUnbanIp)."),
                            BuildCommandKeyboardJson());
                        return;
                    }

                    TelegramUnblockResult adminSelfUnbanResult = UnblockIpFromTelegramCore(adminSelfUnbanIp);
                    TrySendTelegramText(
                        chatId,
                        adminSelfUnbanResult.WasUnblocked
                            ? UiText($"Ок, розблокував {adminSelfUnbanIp}", $"OK, unblocked {adminSelfUnbanIp}")
                            : UiText($"Не знайшов блок для {adminSelfUnbanIp}, схоже у тебе все ОК", $"No active block found for {adminSelfUnbanIp}, looks like you are OK"),
                        BuildCommandKeyboardJson());
                    return;
                }

                if (IsStatusMenuButtonText(trimmed))
                {
                    ClearPendingTelegramCommand(chatId);
                    TrySendTelegramText(chatId, UiText("Розділ статусів відкрито.", "Status section opened."), BuildStatusKeyboardJson());
                    return;
                }

                if (IsAdminMenuButtonText(trimmed))
                {
                    ClearPendingTelegramCommand(chatId);
                    TrySendTelegramText(chatId, UiText("Розділ адмін-команд відкрито.", "Admin section opened."), BuildAdminKeyboardJson());
                    return;
                }

                if (IsBackMenuButtonText(trimmed))
                {
                    ClearPendingTelegramCommand(chatId);
                    TrySendTelegramText(chatId, UiText("Повернув головне меню.", "Returned to main menu."), BuildCommandKeyboardJson());
                    return;
                }

                if (string.Equals(trimmed, "I am here", StringComparison.OrdinalIgnoreCase)
                    || command == "/here")
                {
                    StartHereFlow(chatId);
                    return;
                }

                if (command == "/cancel")
                {
                    ClearPendingTelegramCommand(chatId);
                    TrySendTelegramText(chatId, UiText("Поточну дію скасовано.", "Current action cancelled."));
                    return;
                }

                if (command == "/?" || command == "/help")
                {
                    TrySendTelegramText(chatId, BuildHelpReply(), BuildCommandKeyboardJson());
                    return;
                }

                if (command == "/adduser")
                {
                    if (parts.Length >= 2)
                    {
                        ClearPendingTelegramCommand(chatId);
                        TrySendTelegramText(chatId, RegisterLimitedTelegramPhone(parts[1]));
                        return;
                    }

                    SetPendingTelegramCommand(chatId, new PendingTelegramCommand { Type = PendingTelegramCommandType.AddLimitedUserPhone });
                    TrySendTelegramText(
                        chatId,
                        UiText("Введіть номер телефону користувача у форматі +380..., або /cancel.",
                               "Enter user phone in format +380..., or /cancel."),
                        BuildForceReplyJson(UiText("Наприклад: +380991234567", "Example: +380991234567")));
                    return;
                }

                if (IsGroupMembersButtonText(trimmed) || command == "/groupmembers")
                {
                    ClearPendingTelegramCommand(chatId);
                    TrySendTelegramText(chatId, BuildGroupMembersReply(), BuildAdminKeyboardJson());
                    return;
                }

                if (command == "/status")
                {
                    if (parts.Length < 2)
                    {
                        TrySendTelegramText(chatId, BuildSystemStatusReply(), BuildStatusKeyboardJson());
                        return;
                    }

                    if (string.Equals(parts[1], "all", StringComparison.OrdinalIgnoreCase))
                    {
                        TrySendTelegramText(chatId, BuildAllBlocksReply(), BuildStatusKeyboardJson());
                        return;
                    }

                    TrySendTelegramText(chatId, BuildIpStatusReply(parts[1]), BuildStatusKeyboardJson());
                    return;
                }

                if (command == "/service")
                {
                    string action = parts.Length >= 2 ? parts[1] : "status";
                    TrySendTelegramText(chatId, HandleServiceTelegramCommand(action), BuildAdminKeyboardJson());
                    return;
                }

                if (command == "/monitor")
                {
                    string action = parts.Length >= 2 ? parts[1] : "status";
                    TrySendTelegramText(chatId, HandleMonitorTelegramCommand(action), BuildAdminKeyboardJson());
                    return;
                }

                if (command == "/thresholds" || command == "/levels")
                {
                    TrySendTelegramText(chatId, BuildThresholdsReply(), BuildStatusKeyboardJson());
                    return;
                }

                if (command == "/ban")
                {
                    if (parts.Length < 2)
                    {
                        SetPendingTelegramCommand(chatId, new PendingTelegramCommand { Type = PendingTelegramCommandType.BanIp });
                        TrySendTelegramText(
                            chatId,
                            UiText("Введіть IP для блокування.\nПотім я попрошу тривалість.\nСкасування: /cancel",
                                   "Enter the IP to block.\nThen I will ask for the duration.\nCancel: /cancel"),
                            BuildForceReplyJson(UiText("Наприклад: 1.2.3.4", "Example: 1.2.3.4")));
                        return;
                    }

                    if (parts.Length < 3)
                    {
                        SetPendingTelegramCommand(chatId, new PendingTelegramCommand { Type = PendingTelegramCommandType.BanDuration, IpAddress = parts[1] });
                        TrySendTelegramText(
                            chatId,
                            UiText($"IP прийнято: {parts[1]}\nТепер введіть тривалість: 1d, 6h, 30m або 1440\nСкасування: /cancel",
                                   $"IP accepted: {parts[1]}\nNow enter duration: 1d, 6h, 30m or 1440\nCancel: /cancel"),
                            BuildForceReplyJson(UiText("Наприклад: 1d", "Example: 1d")));
                        return;
                    }

                    ClearPendingTelegramCommand(chatId);
                    TrySendTelegramText(chatId, ManualBanIpFromTelegram(parts[1], parts[2]));
                    return;
                }

                if (command == "/unban")
                {
                    if (parts.Length < 2)
                    {
                        if (TryGetRememberedHereIp(chatId, out string rememberedIp))
                        {
                            ClearPendingTelegramCommand(chatId);
                            string unbanResult = UnblockIpFromTelegram(rememberedIp);
                            TrySendTelegramText(
                                chatId,
                                UiText($"Підставлено IP з /here: {rememberedIp}\n{unbanResult}",
                                       $"Used IP from /here: {rememberedIp}\n{unbanResult}"));
                            return;
                        }

                        SetPendingTelegramCommand(chatId, new PendingTelegramCommand { Type = PendingTelegramCommandType.UnbanIp });
                        TrySendTelegramText(
                            chatId,
                            UiText("Введіть IP для розблокування.\nСкасування: /cancel",
                                   "Enter the IP to unban.\nCancel: /cancel"),
                            BuildForceReplyJson(UiText("Наприклад: 1.2.3.4", "Example: 1.2.3.4")));
                        return;
                    }

                    ClearPendingTelegramCommand(chatId);
                    TrySendTelegramText(chatId, UnblockIpFromTelegram(parts[1]));
                    return;
                }
            }
            catch (Exception ex)
            {
                WriteLog($"Telegram command handling error: {ex.Message}");
            }
        }

        private bool IsUiLanguageUa()
        {
            return !string.Equals(uiLanguage, "EN", StringComparison.OrdinalIgnoreCase);
        }

        private string UiText(string ua, string en)
        {
            return IsUiLanguageUa() ? ua : en;
        }

        private string BuildHelpReply()
        {
            var lines = new List<string>
            {
                UiText("📋 Доступні команди:", "📋 Available commands:"),
                "",
                  UiText("/start — вхід та активація чату керування", "/start — sign in and activate control chat"),
                                UiText("/adduser <телефон> — додати користувача з кнопкою 'Розблокуй мене'",
                                             "/adduser <phone> — add limited user with 'Unblock me' button"),
                  UiText("/groupmembers — користувачі в групі та членство в каналі",
                      "/groupmembers — users in group and channel membership"),
                UiText("/status — стан системи (служба, процеси)",
                       "/status — system state (service, processes)"),
                UiText("/status all — список усіх активних блокувань",
                       "/status all — list all active blocks"),
                UiText("/status <ip> — детальний стан конкретного IP",
                       "/status <ip> — detailed info for a specific IP"),
                  UiText("/service [status|start|stop|restart] — керування службою",
                      "/service [status|start|stop|restart] — service control"),
                  UiText("/monitor [status|start|stop|restart] — керування монітором",
                      "/monitor [status|start|stop|restart] — monitor control"),
                  UiText("/thresholds або /levels — поточні пороги блокування",
                      "/thresholds or /levels — current block thresholds"),
                  UiText("/here — перевірити свій IP", "/here — check your IP status"),
                                UiText("/unbanme — швидко розблокувати себе", "/unbanme — quick self-unban"),
                UiText("/ban <ip> <тривалість> — вручну заблокувати IP (1d, 6h, 30m, 1440)",
                       "/ban <ip> <duration> — manually block an IP (1d, 6h, 30m, 1440)"),
                  UiText("/unban <ip> — зняти пряме блокування з IP",
                      "/unban <ip> — remove direct block from IP"),
                UiText("/cancel — скасувати поточне введення",
                       "/cancel — cancel the current prompt"),
                UiText("/? або /help — ця довідка",
                       "/? or /help — this help message"),
            };
            return string.Join("\n", lines);
        }

        private string BuildLimitedHelpReply()
        {
            var lines = new List<string>
            {
                UiText("📋 Доступна команда:", "📋 Available command:"),
                UiText("Кнопка «Розблокуй мене» — зняти блок тільки для дозволеного IP.",
                       "'Unblock me' button — remove block only for the allowed IP.")
            };

            return string.Join("\n", lines);
        }

        private void StartHereFlow(string chatId)
        {
            if (TryBuildHereProbeLink(chatId, out string autoLink))
            {
                TrySendTelegramText(
                    chatId,
                    UiText(
                        $"Натисніть це посилання з телефона, щоб я сам визначив ваш IP:\n{autoLink}\n\nПісля відкриття я одразу надішлю статус IP в Telegram.\nСкасування: /cancel",
                        $"Open this link on your phone so I can capture your IP automatically:\n{autoLink}\n\nAfter opening, I will send your IP status to Telegram immediately.\nCancel: /cancel"));
                return;
            }

            SetPendingTelegramCommand(chatId, new PendingTelegramCommand { Type = PendingTelegramCommandType.HereIp });
            TrySendTelegramText(
                chatId,
                UiText(
                    "Щоб визначити ваш IP з поточного підключення, відкрийте з телефона:\nhttps://api.ipify.org?format=json\n\nВажливо: після відкриття посилання Telegram не підставляє відповідь автоматично. Скопіюйте текст зі сторінки (IP або JSON) і надішліть сюди.\nСкасування: /cancel",
                    "To detect your IP from the current connection, open on your phone:\nhttps://api.ipify.org?format=json\n\nImportant: after opening the link, Telegram does not insert the result automatically. Copy the page text (IP or JSON) and send it here.\nCancel: /cancel"),
                BuildForceReplyJson(UiText("Наприклад: 1.2.3.4", "Example: 1.2.3.4")));
        }

        private bool TryBuildHereProbeLink(string chatId, out string link)
        {
            link = string.Empty;

            var cfg = telegramConfig;
            if (cfg == null || !cfg.HereProbeEnabled || string.IsNullOrWhiteSpace(cfg.HereProbePublicUrl))
                return false;

            string token = Guid.NewGuid().ToString("N");
            lock (hereProbeTokensLock)
            {
                CleanupExpiredHereProbeTokens();
                hereProbeTokens[token] = new HereProbeTokenState
                {
                    ChatId = chatId,
                    CreatedUtc = DateTime.UtcNow
                };
            }

            string separator = cfg.HereProbePublicUrl.Contains("?", StringComparison.Ordinal) ? "&" : "?";
            link = cfg.HereProbePublicUrl + separator + "t=" + Uri.EscapeDataString(token);
            return true;
        }

        private void SetPendingTelegramCommand(string chatId, PendingTelegramCommand pendingCommand)
        {
            lock (pendingTelegramCommandsLock)
            {
                pendingTelegramCommands[chatId] = pendingCommand;
            }
        }

        private void ClearPendingTelegramCommand(string chatId)
        {
            lock (pendingTelegramCommandsLock)
            {
                pendingTelegramCommands.Remove(chatId);
            }
        }

        private bool TryGetPendingTelegramCommand(string chatId, out PendingTelegramCommand pendingCommand)
        {
            lock (pendingTelegramCommandsLock)
            {
                return pendingTelegramCommands.TryGetValue(chatId, out pendingCommand!);
            }
        }

        private void RememberHereIp(string chatId, string ip)
        {
            if (string.IsNullOrWhiteSpace(chatId) || string.IsNullOrWhiteSpace(ip))
                return;

            lock (hereIpMemoryLock)
            {
                lastHereIpByChat[chatId] = ip;
                lastHereIpGlobal = ip;
            }
        }

        private bool TryGetRememberedHereIp(string chatId, out string ip)
        {
            lock (hereIpMemoryLock)
            {
                if (!string.IsNullOrWhiteSpace(chatId) && lastHereIpByChat.TryGetValue(chatId, out string chatIp) && !string.IsNullOrWhiteSpace(chatIp))
                {
                    ip = chatIp;
                    return true;
                }

                if (!string.IsNullOrWhiteSpace(lastHereIpGlobal))
                {
                    ip = lastHereIpGlobal;
                    return true;
                }
            }

            ip = string.Empty;
            return false;
        }

        private bool IsTelegramChatAuthorized(string chatId)
        {
            lock (authorizedTelegramChatsLock)
            {
                return authorizedTelegramChats.Contains(chatId);
            }
        }

        private bool IsLimitedTelegramChatAuthorized(string chatId)
        {
            lock (limitedTelegramChatsLock)
            {
                return limitedTelegramChats.Contains(chatId);
            }
        }

        private void AuthorizeTelegramChat(string chatId)
        {
            lock (authorizedTelegramChatsLock)
            {
                authorizedTelegramChats.Add(chatId);
            }
        }

        private void AuthorizeLimitedTelegramChat(string chatId)
        {
            lock (limitedTelegramChatsLock)
            {
                limitedTelegramChats.Add(chatId);
            }
        }

        private void PromoteTelegramControlChat(string chatId)
        {
            try
            {
                lock (configLock)
                {
                    ServiceConfig? cfg = null;
                    if (File.Exists(configPath))
                    {
                        string json = ConfigCrypto.ReadConfigText(configPath);
                        cfg = JsonSerializer.Deserialize<ServiceConfig>(json, ServiceConfigJson.Options);
                    }

                    cfg ??= ServiceConfig.CreateDefault();
                    cfg.Telegram ??= new TelegramConfig { Enabled = false, BotToken = string.Empty, ChatId = string.Empty };

                    if (!string.Equals(cfg.Telegram.ChatId, chatId, StringComparison.Ordinal))
                    {
                        cfg.Telegram.ChatId = chatId;
                        ConfigCrypto.WriteConfigText(configPath, JsonSerializer.Serialize(cfg, ServiceConfigJson.Options));
                        telegramConfig = cfg.Telegram;
                        WriteLog($"Telegram control chat switched to: {chatId}");
                    }
                }
            }
            catch (Exception ex)
            {
                WriteLog($"Telegram control chat switch error: {ex.Message}");
            }
        }

        private bool TryHandlePendingTelegramInput(string chatId, string text)
        {
            if (!TryGetPendingTelegramCommand(chatId, out PendingTelegramCommand pendingCommand))
                return false;

            switch (pendingCommand.Type)
            {
                case PendingTelegramCommandType.BanIp:
                    if (!IPAddress.TryParse(text, out IPAddress parsedIp))
                    {
                        TrySendTelegramText(
                            chatId,
                            UiText("Некоректний IP. Введіть IP ще раз або /cancel.",
                                   "Invalid IP. Enter the IP again or /cancel."),
                            BuildForceReplyJson(UiText("Наприклад: 1.2.3.4", "Example: 1.2.3.4")));
                        return true;
                    }

                    SetPendingTelegramCommand(chatId, new PendingTelegramCommand
                    {
                        Type = PendingTelegramCommandType.BanDuration,
                        IpAddress = parsedIp.ToString()
                    });
                    TrySendTelegramText(
                        chatId,
                        UiText($"IP прийнято: {parsedIp}\nВведіть тривалість: 1d, 6h, 30m або 1440\nСкасування: /cancel",
                               $"IP accepted: {parsedIp}\nEnter duration: 1d, 6h, 30m or 1440\nCancel: /cancel"),
                        BuildForceReplyJson(UiText("Наприклад: 1d", "Example: 1d")));
                    return true;

                case PendingTelegramCommandType.BanDuration:
                    if (!TryParseDuration(text, out int _) || text.Trim().StartsWith("/", StringComparison.Ordinal))
                    {
                        TrySendTelegramText(
                            chatId,
                            UiText("Некоректна тривалість. Введіть 1d, 6h, 30m або 1440.\nСкасування: /cancel",
                                   "Invalid duration. Enter 1d, 6h, 30m or 1440.\nCancel: /cancel"),
                            BuildForceReplyJson(UiText("Наприклад: 1d", "Example: 1d")));
                        return true;
                    }

                    ClearPendingTelegramCommand(chatId);
                    TrySendTelegramText(chatId, ManualBanIpFromTelegram(pendingCommand.IpAddress, text.Trim()));
                    return true;

                case PendingTelegramCommandType.UnbanIp:
                    if (!IPAddress.TryParse(text, out IPAddress unbanIp))
                    {
                        TrySendTelegramText(
                            chatId,
                            UiText("Некоректний IP. Введіть IP ще раз або /cancel.",
                                   "Invalid IP. Enter the IP again or /cancel."),
                            BuildForceReplyJson(UiText("Наприклад: 1.2.3.4", "Example: 1.2.3.4")));
                        return true;
                    }

                    ClearPendingTelegramCommand(chatId);
                    TrySendTelegramText(chatId, UnblockIpFromTelegram(unbanIp.ToString()));
                    return true;

                case PendingTelegramCommandType.HereIp:
                    string normalizedHereIp = ExtractFirstIpFromText(text);
                    if (string.IsNullOrWhiteSpace(normalizedHereIp) || !IPAddress.TryParse(normalizedHereIp, out IPAddress hereIp))
                    {
                        if (text.IndexOf("api.ipify.org", StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            TrySendTelegramText(
                                chatId,
                                UiText(
                                    "Бачу лише посилання. Відкрийте його, скопіюйте результат зі сторінки (IP або JSON) і надішліть сюди текстом.\nСкасування: /cancel",
                                    "I can see only the link. Open it, copy the page result (IP or JSON), and send that text here.\nCancel: /cancel"),
                                BuildForceReplyJson(UiText("Наприклад: 1.2.3.4", "Example: 1.2.3.4")));
                            return true;
                        }

                        TrySendTelegramText(
                            chatId,
                            UiText(
                                "Не бачу коректний IP. Надішліть IP або відповідь з https://api.ipify.org?format=json\nСкасування: /cancel",
                                "I could not find a valid IP. Send an IP or response from https://api.ipify.org?format=json\nCancel: /cancel"),
                            BuildForceReplyJson(UiText("Наприклад: 1.2.3.4", "Example: 1.2.3.4")));
                        return true;
                    }

                    ClearPendingTelegramCommand(chatId);
                        string detectedIp = hereIp.ToString();
                        RememberHereIp(chatId, detectedIp);
                        TrySendTelegramText(chatId, BuildIpStatusReply(detectedIp));
                    return true;

                case PendingTelegramCommandType.AddLimitedUserPhone:
                    if (!IsTelegramChatAuthorized(chatId) && !string.Equals(chatId, telegramConfig?.ChatId, StringComparison.Ordinal))
                    {
                        ClearPendingTelegramCommand(chatId);
                        TrySendTelegramText(chatId, UiText("Недостатньо прав для цієї дії.", "Insufficient privileges for this action."));
                        return true;
                    }

                    string registerResult = RegisterLimitedTelegramPhone(text);
                    ClearPendingTelegramCommand(chatId);
                    TrySendTelegramText(chatId, registerResult);
                    return true;
            }

            return false;
        }

        private string TryExtractContactPhone(JsonElement messageElement)
        {
            if (!messageElement.TryGetProperty("contact", out JsonElement contactElement))
                return string.Empty;

            if (!contactElement.TryGetProperty("phone_number", out JsonElement phoneElement))
                return string.Empty;

            return phoneElement.GetString() ?? string.Empty;
        }

        private void HandleTelegramContactShare(string chatId, string rawPhone)
        {
            try
            {
                string normalizedPhone = NormalizePhoneForTelegramRole(rawPhone);
                if (string.IsNullOrWhiteSpace(normalizedPhone))
                {
                    TrySendTelegramText(chatId, UiText("Некоректний номер телефону.", "Invalid phone number."));
                    return;
                }

                if (!IsLimitedPhoneAllowed(normalizedPhone))
                {
                    TrySendTelegramText(chatId, UiText("Цей номер не має доступу.", "This phone is not allowed."));
                    return;
                }

                ClearPendingTelegramCommand(chatId);
                AuthorizeLimitedTelegramChat(chatId);
                TrySendTelegramText(
                    chatId,
                    UiText("✅ Доступ надано. Використовуйте кнопку «Розблокуй мене».", "✅ Access granted. Use the 'Unblock me' button."),
                    BuildSelfUnbanKeyboardJson());
            }
            catch (Exception ex)
            {
                WriteLog($"Telegram contact processing error: {ex.Message}");
            }
        }

        private bool IsLimitedPhoneAllowed(string normalizedPhone)
        {
            var cfg = telegramConfig;
            if (cfg == null || cfg.LimitedPhones == null || cfg.LimitedPhones.Count == 0)
                return false;

            foreach (string allowed in cfg.LimitedPhones)
            {
                string normalizedAllowed = NormalizePhoneForTelegramRole(allowed);
                if (!string.IsNullOrWhiteSpace(normalizedAllowed)
                    && string.Equals(normalizedAllowed, normalizedPhone, StringComparison.Ordinal))
                    return true;
            }

            return false;
        }

        private string RegisterLimitedTelegramPhone(string rawPhone)
        {
            string normalizedPhone = NormalizePhoneForTelegramRole(rawPhone);
            if (string.IsNullOrWhiteSpace(normalizedPhone))
                return UiText("Некоректний формат номера. Приклад: +380991234567", "Invalid phone format. Example: +380991234567");

            try
            {
                lock (configLock)
                {
                    ServiceConfig? cfg = null;
                    if (File.Exists(configPath))
                    {
                        string json = ConfigCrypto.ReadConfigText(configPath);
                        cfg = JsonSerializer.Deserialize<ServiceConfig>(json, ServiceConfigJson.Options);
                    }

                    cfg ??= ServiceConfig.CreateDefault();
                    cfg.Telegram ??= new TelegramConfig { Enabled = false, BotToken = string.Empty, ChatId = string.Empty };
                    cfg.Telegram.LimitedPhones ??= new List<string>();

                    bool exists = cfg.Telegram.LimitedPhones
                        .Select(NormalizePhoneForTelegramRole)
                        .Any(p => string.Equals(p, normalizedPhone, StringComparison.Ordinal));

                    if (!exists)
                    {
                        cfg.Telegram.LimitedPhones.Add(normalizedPhone);
                        cfg.Telegram.LimitedPhones = cfg.Telegram.LimitedPhones
                            .Select(NormalizePhoneForTelegramRole)
                            .Where(p => !string.IsNullOrWhiteSpace(p))
                            .Distinct(StringComparer.Ordinal)
                            .OrderBy(p => p, StringComparer.Ordinal)
                            .ToList();

                        ConfigCrypto.WriteConfigText(configPath, JsonSerializer.Serialize(cfg, ServiceConfigJson.Options));
                        telegramConfig = cfg.Telegram;
                    }

                    return exists
                        ? UiText($"Користувач вже існує: {normalizedPhone}", $"User already exists: {normalizedPhone}")
                        : UiText($"Користувача додано: {normalizedPhone}", $"User added: {normalizedPhone}");
                }
            }
            catch (Exception ex)
            {
                WriteLog($"Register limited phone error: {ex.Message}");
                return UiText("Помилка додавання користувача.", "Failed to add user.");
            }
        }

        private string NormalizePhoneForTelegramRole(string rawPhone)
        {
            if (string.IsNullOrWhiteSpace(rawPhone))
                return string.Empty;

            string trimmed = rawPhone.Trim();
            bool hasPlus = trimmed.StartsWith("+", StringComparison.Ordinal);
            var digits = new StringBuilder(trimmed.Length);
            foreach (char c in trimmed)
            {
                if (char.IsDigit(c))
                    digits.Append(c);
            }

            if (digits.Length < 10 || digits.Length > 15)
                return string.Empty;

            return (hasPlus ? "+" : "+") + digits.ToString();
        }

        private string BuildGroupMembersReply()
        {
            try
            {
                var cfg = telegramConfig;
                var normalizedPhones = (cfg?.LimitedPhones ?? new List<string>())
                    .Select(NormalizePhoneForTelegramRole)
                    .Where(p => !string.IsNullOrWhiteSpace(p))
                    .Distinct(StringComparer.Ordinal)
                    .OrderBy(p => p, StringComparer.Ordinal)
                    .ToList();

                List<string> authorizedLimitedChatsSnapshot;
                lock (limitedTelegramChatsLock)
                {
                    authorizedLimitedChatsSnapshot = limitedTelegramChats
                        .OrderBy(c => c, StringComparer.Ordinal)
                        .ToList();
                }

                var lines = new List<string>
                {
                    UiText("👥 Користувачі в групі: членство в каналі", "👥 Users in group: channel membership"),
                    UiText($"Дозволених телефонів у групі: {normalizedPhones.Count}", $"Allowed phones in group: {normalizedPhones.Count}"),
                    UiText($"Підтверджених чатів у каналі: {authorizedLimitedChatsSnapshot.Count}", $"Authorized chats in channel: {authorizedLimitedChatsSnapshot.Count}")
                };

                lines.Add(string.Empty);
                lines.Add(UiText("Телефони групи:", "Group phones:"));
                if (normalizedPhones.Count == 0)
                    lines.Add(UiText("- (порожньо)", "- (empty)"));
                else
                    lines.AddRange(normalizedPhones.Select(p => "- " + p));

                lines.Add(string.Empty);
                lines.Add(UiText("Чати з активним членством:", "Chats with active membership:"));
                if (authorizedLimitedChatsSnapshot.Count == 0)
                    lines.Add(UiText("- (немає)", "- (none)"));
                else
                    lines.AddRange(authorizedLimitedChatsSnapshot.Select(c => "- chat_id: " + c));

                return string.Join("\n", lines);
            }
            catch (Exception ex)
            {
                WriteLog($"BuildGroupMembersReply error: {ex.Message}");
                return UiText("Не вдалося отримати членство користувачів групи.", "Failed to get group users membership.");
            }
        }

        private string ExtractFirstIpFromText(string raw)
        {
            string direct = NormalizeIpCandidate(raw);
            if (!string.IsNullOrWhiteSpace(direct))
                return direct;

            foreach (string token in SplitIpCandidates(raw))
            {
                string candidate = NormalizeIpCandidate(token);
                if (!string.IsNullOrWhiteSpace(candidate))
                    return candidate;
            }

            return string.Empty;
        }

        private string BuildUsersReply()
        {
            try
            {
                var sessions = GetActiveUserSessions();
                if (sessions.Count == 0)
                    return UiText("Активних користувачів не знайдено.", "No active users found.");

                var lines = new List<string>
                {
                    UiText($"👥 Активні користувачі ({sessions.Count}):", $"👥 Active users ({sessions.Count}):")
                };

                foreach (var session in sessions)
                {
                    string userLabel = string.IsNullOrWhiteSpace(session.Domain)
                        ? session.UserName
                        : $"{session.Domain}\\{session.UserName}";
                    string sourceLabel = string.IsNullOrWhiteSpace(session.ClientIp)
                        ? UiText("локально", "local")
                        : session.ClientIp;

                    lines.Add($"{userLabel} | ID {session.SessionId} | {session.StateText} | IP: {sourceLabel}");
                }

                return string.Join("\n", lines);
            }
            catch (Exception ex)
            {
                WriteLog($"BuildUsersReply error: {ex.Message}");
                return UiText("Не вдалося отримати список активних користувачів.", "Failed to get active users list.");
            }
        }

        private sealed class ActiveUserSession
        {
            public int SessionId;
            public string UserName = string.Empty;
            public string Domain = string.Empty;
            public string ClientIp = string.Empty;
            public string StateText = string.Empty;
        }

        private List<ActiveUserSession> GetActiveUserSessions()
        {
            var result = new List<ActiveUserSession>();
            IntPtr sessionInfoPtr = IntPtr.Zero;
            int sessionCount = 0;

            if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out sessionInfoPtr, out sessionCount) || sessionInfoPtr == IntPtr.Zero)
                return result;

            try
            {
                int dataSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));

                for (int index = 0; index < sessionCount; index++)
                {
                    IntPtr current = IntPtr.Add(sessionInfoPtr, index * dataSize);
                    var sessionInfo = Marshal.PtrToStructure<WTS_SESSION_INFO>(current);
                    if (sessionInfo.State != WTS_CONNECTSTATE_CLASS.WTSActive && sessionInfo.State != WTS_CONNECTSTATE_CLASS.WTSConnected)
                        continue;

                    string userName = QuerySessionString(sessionInfo.SessionID, WTS_INFO_CLASS.WTSUserName);
                    if (string.IsNullOrWhiteSpace(userName))
                        continue;

                    result.Add(new ActiveUserSession
                    {
                        SessionId = sessionInfo.SessionID,
                        UserName = userName,
                        Domain = QuerySessionString(sessionInfo.SessionID, WTS_INFO_CLASS.WTSDomainName),
                        ClientIp = QuerySessionClientIp(sessionInfo.SessionID),
                        StateText = sessionInfo.State == WTS_CONNECTSTATE_CLASS.WTSActive
                            ? UiText("АКТИВНА", "ACTIVE")
                            : UiText("ПІДКЛЮЧЕНА", "CONNECTED")
                    });
                }
            }
            finally
            {
                if (sessionInfoPtr != IntPtr.Zero)
                    WTSFreeMemory(sessionInfoPtr);
            }

            return result
                .OrderBy(s => s.UserName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(s => s.SessionId)
                .ToList();
        }

        private string QuerySessionString(int sessionId, WTS_INFO_CLASS infoClass)
        {
            IntPtr buffer = IntPtr.Zero;
            int bytesReturned = 0;

            try
            {
                if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, infoClass, out buffer, out bytesReturned)
                    || buffer == IntPtr.Zero
                    || bytesReturned <= 1)
                {
                    return string.Empty;
                }

                return Marshal.PtrToStringAuto(buffer)?.Trim() ?? string.Empty;
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    WTSFreeMemory(buffer);
            }
        }

        private string QuerySessionClientIp(int sessionId)
        {
            IntPtr buffer = IntPtr.Zero;
            int bytesReturned = 0;

            try
            {
                if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, WTS_INFO_CLASS.WTSClientAddress, out buffer, out bytesReturned)
                    || buffer == IntPtr.Zero
                    || bytesReturned < Marshal.SizeOf(typeof(WTS_CLIENT_ADDRESS)))
                {
                    return string.Empty;
                }

                var address = Marshal.PtrToStructure<WTS_CLIENT_ADDRESS>(buffer);
                if (address.Address == null || address.Address.Length < 6)
                    return string.Empty;

                // AF_INET (2): first 2 bytes are reserved, IPv4 is stored in bytes [2..5]
                if (address.AddressFamily == 2)
                {
                    return string.Join('.', address.Address[2], address.Address[3], address.Address[4], address.Address[5]);
                }

                // AF_INET6 (23): first 2 bytes are reserved, IPv6 is stored in bytes [2..17]
                if (address.AddressFamily == 23 && address.Address.Length >= 18)
                {
                    byte[] ipv6Bytes = new byte[16];
                    Buffer.BlockCopy(address.Address, 2, ipv6Bytes, 0, 16);
                    var ip = new IPAddress(ipv6Bytes);
                    return ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4().ToString() : ip.ToString();
                }

                return string.Empty;
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    WTSFreeMemory(buffer);
            }
        }

        private bool AreSameIpAddress(string left, string right)
        {
            string leftNormalized = NormalizeIpCandidate(left);
            string rightNormalized = NormalizeIpCandidate(right);

            if (string.IsNullOrWhiteSpace(leftNormalized) || string.IsNullOrWhiteSpace(rightNormalized))
                return false;

            return string.Equals(leftNormalized, rightNormalized, StringComparison.OrdinalIgnoreCase);
        }

        private string ManualBanIpFromTelegram(string ipAddress, string durationStr)
        {
            if (!IPAddress.TryParse(ipAddress, out IPAddress parsedIp))
                return UiText($"Некоректний IP: {ipAddress}", $"Invalid IP: {ipAddress}");

            string ip = parsedIp.ToString();

            if (IsLocalOrPrivateIp(ip))
                return UiText($"IP {ip} є локальним/приватним — блокування заборонено.",
                               $"IP {ip} is local/private — blocking not allowed.");

            if (IsIPWhitelisted(ip))
                return UiText($"IP {ip} у білому списку — блокування заборонено.",
                               $"IP {ip} is whitelisted — blocking not allowed.");

            if (!TryParseDuration(durationStr, out int minutes) || minutes <= 0)
                return UiText(
                    $"Некоректна тривалість: '{durationStr}'.\nПриклади: 1d, 6h, 30m, 1440",
                    $"Invalid duration: '{durationStr}'.\nExamples: 1d, 6h, 30m, 1440");

            try
            {
                DateTime nowLocal = DateTime.Now;
                DateTime untilLocal = nowLocal.AddMinutes(minutes);

                string logEntry =
                    $"[{nowLocal:yyyy-MM-dd HH:mm:ss}] BLOCKED IP: {ip} | Failed Attempts: 0 | BlockMinutes: {minutes} | Until: {untilLocal:yyyy-MM-dd HH:mm:ss} | Source: manual";

                lock (logLock)
                {
                    File.AppendAllText(blockListLogPath, logEntry + Environment.NewLine, Encoding.UTF8);
                }

                RequestFirewallSync(force: true);

                string dur = minutes >= 1440
                    ? $"{minutes / 1440}д {(minutes % 1440 > 0 ? $"{minutes % 1440 / 60}г" : "")}".Trim()
                    : minutes >= 60
                        ? $"{minutes / 60}г {(minutes % 60 > 0 ? $"{minutes % 60}хв" : "")}".Trim()
                        : $"{minutes}хв";

                WriteLog($"Telegram manual ban: {ip}, minutes={minutes}, until={untilLocal:yyyy-MM-dd HH:mm:ss}");

                return UiText(
                    $"🔒 IP {ip} заблоковано на {dur}.\nДо: {untilLocal:yyyy-MM-dd HH:mm:ss}",
                    $"🔒 IP {ip} blocked for {dur}.\nUntil: {untilLocal:yyyy-MM-dd HH:mm:ss}");
            }
            catch (Exception ex)
            {
                WriteLog($"Telegram manual ban error for {ip}: {ex.Message}");
                return UiText($"Помилка блокування {ip}: {ex.Message}",
                               $"Failed to ban {ip}: {ex.Message}");
            }
        }

        private static bool TryParseDuration(string s, out int minutes)
        {
            minutes = 0;
            if (string.IsNullOrWhiteSpace(s)) return false;
            s = s.Trim().ToLowerInvariant();

            if (s.EndsWith("d") && int.TryParse(s.TrimEnd('d'), out int days) && days > 0)
            { minutes = days * 1440; return true; }
            if (s.EndsWith("h") && int.TryParse(s.TrimEnd('h'), out int hours) && hours > 0)
            { minutes = hours * 60; return true; }
            if (s.EndsWith("m") && int.TryParse(s.TrimEnd('m'), out int mins) && mins > 0)
            { minutes = mins; return true; }
            if (int.TryParse(s, out int plain) && plain > 0)
            { minutes = plain; return true; }

            return false;
        }

        private string BuildAllBlocksReply()
        {
            if (!File.Exists(blockListLogPath))
                return UiText("Активних блокувань немає.", "No active blocks.");

            DateTime nowLocal = DateTime.Now;
            var directBlocks = new List<(string ip, DateTime until, int minutes)>();
            var subnetBlocks = new List<(string subnet, DateTime until)>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            lock (logLock)
            {
                foreach (string line in File.ReadAllLines(blockListLogPath))
                {
                    string target = ExtractBlockedTargetFromLine(line);
                    if (string.IsNullOrWhiteSpace(target))
                        continue;
                    if (IsBlockEntryExpired(line, nowLocal, out DateTime until))
                        continue;
                    if (!seen.Add(target + until.ToString("s")))
                        continue;

                    if (target.Contains("/", StringComparison.Ordinal))
                        subnetBlocks.Add((target, until));
                    else
                        directBlocks.Add((target, until, ExtractBlockMinutesFromBlockLogLine(line)));
                }
            }

            // deduplicate direct blocks — keep latest until per IP
            var bestDirect = directBlocks
                .GroupBy(b => b.ip, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.OrderByDescending(b => b.until).First())
                .OrderByDescending(b => b.until)
                .ToList();

            var bestSubnet = subnetBlocks
                .GroupBy(b => b.subnet, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.OrderByDescending(b => b.until).First())
                .OrderByDescending(b => b.until)
                .ToList();

            if (bestDirect.Count == 0 && bestSubnet.Count == 0)
                return UiText("Активних блокувань немає.", "No active blocks.");

            var lines = new List<string>();
            lines.Add(UiText($"🔒 Активні блокування ({bestDirect.Count + bestSubnet.Count}):",
                              $"🔒 Active blocks ({bestDirect.Count + bestSubnet.Count}):"));

            if (bestDirect.Count > 0)
            {
                lines.Add("");
                lines.Add(UiText("IP-адреси:", "IP addresses:"));
                foreach (var b in bestDirect)
                {
                    TimeSpan left = b.until - nowLocal;
                    string rem = left.TotalHours >= 1
                        ? $"{(int)left.TotalHours}г {left.Minutes:D2}хв"
                        : $"{(int)left.TotalMinutes}хв";
                    lines.Add($"  {b.ip}  ⏱ {b.until:HH:mm:ss}  ({rem})");
                }
            }

            if (bestSubnet.Count > 0)
            {
                lines.Add("");
                lines.Add(UiText("Підмережі:", "Subnets:"));
                foreach (var b in bestSubnet)
                {
                    TimeSpan left = b.until - nowLocal;
                    string rem = left.TotalHours >= 1
                        ? $"{(int)left.TotalHours}г {left.Minutes:D2}хв"
                        : $"{(int)left.TotalMinutes}хв";
                    lines.Add($"  {b.subnet}  ⏱ {b.until:HH:mm:ss}  ({rem})");
                }
            }

            return string.Join("\n", lines);
        }

        private string BuildIpStatusReply(string ipAddress)
        {
            if (!IPAddress.TryParse(ipAddress, out IPAddress parsedIp))
                return UiText($"Некоректний IP: {ipAddress}", $"Invalid IP: {ipAddress}");

            string ip = parsedIp.ToString();
            bool isWhitelisted = IsIPWhitelisted(ip);
            bool directBlocked = TryGetActiveDirectBlock(ip, out DateTime directUntilLocal, out int directMinutes);
            bool subnetBlocked = TryGetActiveSubnetBlock(ip, out string subnet, out DateTime subnetUntilLocal);
            bool protectedIp = IsLocalOrPrivateIp(ip);

            var lines = new List<string>
            {
                $"IP: {ip}",
                $"{UiText("Локальна/приватна адреса", "Protected local/private")}: {(protectedIp ? UiText("так", "yes") : UiText("ні", "no"))}",
                $"{UiText("У білому списку", "Whitelisted")}: {(isWhitelisted ? UiText("так", "yes") : UiText("ні", "no"))}",
                directBlocked
                    ? UiText($"Пряме блокування: активне до {directUntilLocal:yyyy-MM-dd HH:mm:ss} ({directMinutes} хв)", $"Direct block: active until {directUntilLocal:yyyy-MM-dd HH:mm:ss} ({directMinutes} min)")
                    : UiText("Пряме блокування: немає", "Direct block: none"),
                subnetBlocked
                    ? UiText($"Блокування підмережі: {subnet} до {subnetUntilLocal:yyyy-MM-dd HH:mm:ss}", $"Subnet block: {subnet} until {subnetUntilLocal:yyyy-MM-dd HH:mm:ss}")
                    : UiText("Блокування підмережі: немає", "Subnet block: none")
            };

            string effectiveStatus = (directBlocked || subnetBlocked) && !isWhitelisted
                ? UiText("ЗАБЛОКОВАНО", "BLOCKED")
                : UiText("НЕ ЗАБЛОКОВАНО", "NOT BLOCKED");
            lines.Add($"{UiText("Загальний статус", "Effective status")}: {effectiveStatus}");

            return string.Join("\n", lines);
        }

        private string BuildSystemStatusReply()
        {
            string serviceStatus = GetServiceStatusSummary();
            bool localEngineRunning = IsProcessRunning("WinService");
            bool monitorRunning = IsProcessRunning("RDPMonitor");

            var lines = new List<string>
            {
                UiText("Стан системи:", "System status:"),
                $"{UiText("Служба", "Service")}: {serviceStatus}",
                $"{UiText("Процес служби (WinService.exe)", "Service process (WinService.exe)")}: {(localEngineRunning ? UiText("ПРАЦЮЄ", "RUNNING") : UiText("ЗУПИНЕНО", "STOPPED"))}",
                $"{UiText("Монітор (RDPMonitor.exe)", "Monitor (RDPMonitor.exe)")}: {(monitorRunning ? UiText("ПРАЦЮЄ", "RUNNING") : UiText("ЗУПИНЕНО", "STOPPED"))}"
            };

            return string.Join("\n", lines);
        }

        private string BuildThresholdsReply()
        {
            try
            {
                var levels = blockLevels ?? new List<BlockLevel>();
                if (levels.Count == 0)
                    return UiText("Пороги не налаштовані.", "No thresholds configured.");

                var lines = new List<string>
                {
                    UiText("🎯 Поточні пороги блокування:", "🎯 Current block thresholds:")
                };

                for (int i = 0; i < levels.Count; i++)
                {
                    var level = levels[i];
                    lines.Add($"L{i + 1}: {level.Attempts} -> {level.BlockMinutes}m");
                }

                lines.Add("");
                lines.Add(UiText($"RDP порт: {rdpPort}", $"RDP port: {rdpPort}"));
                lines.Add(UiText($"Вікно лічильника спроб: {failedAttemptsWindowDays}д", $"Attempt counter window: {failedAttemptsWindowDays}d"));
                lines.Add(UiText($"AntiBrute: {(antiBruteConfig?.Enabled == true ? "ON" : "OFF")}",
                                 $"AntiBrute: {(antiBruteConfig?.Enabled == true ? "ON" : "OFF")}"));
                return string.Join("\n", lines);
            }
            catch (Exception ex)
            {
                WriteLog($"BuildThresholdsReply error: {ex.Message}");
                return UiText("Не вдалося отримати пороги.", "Failed to get thresholds.");
            }
        }

        private string HandleServiceTelegramCommand(string actionRaw)
        {
            string action = (actionRaw ?? string.Empty).Trim().ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(action) || action == "status")
                return UiText($"Служба: {GetServiceStatusSummary()}", $"Service: {GetServiceStatusSummary()}");

            if (action == "start")
                return UiText("Служба вже запущена.", "Service is already running.");

            if (action == "stop" || action == "restart")
            {
                try
                {
                    bool doRestart = action == "restart";
                    if (doRestart)
                    {
                        // Restart must be scheduled in a separate process because this service process exits on stop.
                        var restartPsi = new ProcessStartInfo
                        {
                            FileName = "cmd.exe",
                            Arguments = "/c ping 127.0.0.1 -n 4 >nul & sc start RDPSecurityService",
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };
                        Process.Start(restartPsi);
                    }

                    ThreadPool.QueueUserWorkItem(_ =>
                    {
                        try
                        {
                            using (var service = new ServiceController("RDPSecurityService"))
                            {
                                service.Refresh();
                                if (service.Status != ServiceControllerStatus.Stopped && service.Status != ServiceControllerStatus.StopPending)
                                    service.Stop();
                            }
                        }
                        catch (Exception ex)
                        {
                            try { WriteLog($"Telegram service {action} error: {ex.Message}"); } catch { }
                        }
                    });

                    return doRestart
                        ? UiText("♻️ Перезапуск служби ініційовано.", "♻️ Service restart initiated.")
                        : UiText("🛑 Зупинка служби ініційована.", "🛑 Service stop initiated.");
                }
                catch (Exception ex)
                {
                    WriteLog($"HandleServiceTelegramCommand error: {ex.Message}");
                    return UiText($"Помилка керування службою: {ex.Message}", $"Service control error: {ex.Message}");
                }
            }

            return UiText("Невідома дія. Використовуйте /service status|start|stop|restart",
                          "Unknown action. Use /service status|start|stop|restart");
        }

        private string HandleMonitorTelegramCommand(string actionRaw)
        {
            string action = (actionRaw ?? string.Empty).Trim().ToLowerInvariant();
            bool running = IsProcessRunning("RDPMonitor");

            if (string.IsNullOrWhiteSpace(action) || action == "status")
                return running ? UiText("Монітор: ПРАЦЮЄ", "Monitor: RUNNING") : UiText("Монітор: ЗУПИНЕНО", "Monitor: STOPPED");

            if (action == "stop")
            {
                if (!running)
                    return UiText("Монітор вже зупинено.", "Monitor is already stopped.");

                try
                {
                    var list = Process.GetProcessesByName("RDPMonitor");
                    for (int i = 0; i < list.Length; i++)
                    {
                        try { list[i].Kill(); } catch { }
                    }
                    return UiText("🛑 Монітор зупинено.", "🛑 Monitor stopped.");
                }
                catch (Exception ex)
                {
                    WriteLog($"Monitor stop error: {ex.Message}");
                    return UiText($"Помилка зупинки монітора: {ex.Message}", $"Monitor stop error: {ex.Message}");
                }
            }

            if (action == "start" || action == "restart")
            {
                try
                {
                    if (action == "restart" && running)
                    {
                        var list = Process.GetProcessesByName("RDPMonitor");
                        for (int i = 0; i < list.Length; i++)
                        {
                            try { list[i].Kill(); } catch { }
                        }
                    }

                    if (!TryResolveMonitorPath(out string monitorExe))
                        return UiText("Не знайдено RDPMonitor.exe", "RDPMonitor.exe was not found");

                    var psi = new ProcessStartInfo
                    {
                        FileName = monitorExe,
                        WorkingDirectory = Path.GetDirectoryName(monitorExe) ?? AppDomain.CurrentDomain.BaseDirectory,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };

                    Process.Start(psi);
                    return action == "restart"
                        ? UiText("♻️ Монітор перезапущено.", "♻️ Monitor restarted.")
                        : UiText("▶️ Монітор запущено.", "▶️ Monitor started.");
                }
                catch (Exception ex)
                {
                    WriteLog($"Monitor start/restart error: {ex.Message}");
                    return UiText($"Помилка запуску монітора: {ex.Message}", $"Monitor start error: {ex.Message}");
                }
            }

            return UiText("Невідома дія. Використовуйте /monitor status|start|stop|restart",
                          "Unknown action. Use /monitor status|start|stop|restart");
        }

        private bool TryResolveMonitorPath(out string monitorExePath)
        {
            var candidates = new List<string>
            {
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Monitor", "RDPMonitor.exe"),
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "Monitor", "RDPMonitor.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "RDPSecurityService", "Monitor", "RDPMonitor.exe")
            };

            for (int i = 0; i < candidates.Count; i++)
            {
                string candidate = Path.GetFullPath(candidates[i]);
                if (File.Exists(candidate))
                {
                    monitorExePath = candidate;
                    return true;
                }
            }

            monitorExePath = string.Empty;
            return false;
        }

        private sealed class TelegramUnblockResult
        {
            public bool WasUnblocked;
            public string Message = string.Empty;
        }

        private string UnblockIpFromTelegram(string ipAddress)
        {
            return UnblockIpFromTelegramCore(ipAddress).Message;
        }

        private TelegramUnblockResult UnblockIpFromTelegramCore(string ipAddress)
        {
            if (!IPAddress.TryParse(ipAddress, out IPAddress parsedIp))
            {
                return new TelegramUnblockResult
                {
                    WasUnblocked = false,
                    Message = UiText($"Некоректний IP: {ipAddress}", $"Invalid IP: {ipAddress}")
                };
            }

            string ip = parsedIp.ToString();
            int removedDirectLines = 0;

            try
            {
                lock (logLock)
                {
                    if (File.Exists(blockListLogPath))
                    {
                        var keptLines = new List<string>();
                        foreach (string line in File.ReadAllLines(blockListLogPath))
                        {
                            string target = ExtractBlockedTargetFromLine(line);
                            if (string.IsNullOrWhiteSpace(target))
                            {
                                keptLines.Add(line);
                                continue;
                            }

                            // Only remove this IP's own direct-block entry here. A /24 subnet
                            // block that happens to cover this IP exists because several
                            // *other* IPs in that range triggered it, and must not be silently
                            // lifted for everyone just because one specific IP was unbanned —
                            // that requires a separate, explicit subnet-unban action.
                            if (!target.Contains("/", StringComparison.Ordinal)
                                && target.Equals(ip, StringComparison.OrdinalIgnoreCase))
                            {
                                removedDirectLines++;
                                continue;
                            }

                            keptLines.Add(line);
                        }

                        File.WriteAllLines(blockListLogPath, keptLines);
                    }
                }

                lock (bansLock)
                {
                    bans.Remove(ip);
                }
                lock (failedAttemptsLock)
                {
                    failedAttempts.Remove(ip);
                }

                // For unblock we keep log as source of truth and run firewall sync in parallel.
                _ = Task.Run(() =>
                {
                    try
                    {
                        RequestFirewallSync(force: true);
                    }
                    catch (Exception syncEx)
                    {
                        WriteLog($"Telegram unblock firewall sync error for {ip}: {syncEx.Message}");
                    }
                });

                bool subnetBlocked = TryGetActiveSubnetBlock(ip, out string subnet, out DateTime subnetUntilLocal);
                if (removedDirectLines > 0)
                {
                    WriteLog($"Telegram manual unblock: {ip}, removed_direct={removedDirectLines}");
                    return new TelegramUnblockResult
                    {
                        WasUnblocked = true,
                        Message = subnetBlocked
                            ? UiText($"Пряме блокування IP {ip} знято. Але IP усе ще під блокуванням підмережі: {subnet} до {subnetUntilLocal:yyyy-MM-dd HH:mm:ss}. Щоб зняти й це — потрібна окрема розблокування підмережі.", $"Direct block for {ip} removed. It is still covered by an active subnet block: {subnet} until {subnetUntilLocal:yyyy-MM-dd HH:mm:ss}. Lifting that needs a separate subnet unban.")
                            : UiText($"IP {ip} розблоковано.", $"Unblocked {ip}.")
                    };
                }

                return new TelegramUnblockResult
                {
                    WasUnblocked = false,
                    Message = subnetBlocked
                        ? UiText($"Прямого блокування для {ip} не знайдено, але IP під блокуванням підмережі: {subnet} до {subnetUntilLocal:yyyy-MM-dd HH:mm:ss}.", $"No direct IP block found for {ip}, but it is covered by an active subnet block: {subnet} until {subnetUntilLocal:yyyy-MM-dd HH:mm:ss}.")
                        : UiText($"Прямого блокування для {ip} не знайдено.", $"No direct IP block found for {ip}.")
                };
            }
            catch (Exception ex)
            {
                WriteLog($"Telegram unblock error for {ip}: {ex.Message}");
                return new TelegramUnblockResult
                {
                    WasUnblocked = false,
                    Message = UiText($"Не вдалося розблокувати {ip}: {ex.Message}", $"Failed to unblock {ip}: {ex.Message}")
                };
            }
        }

        private bool TryGetActiveDirectBlock(string ipAddress, out DateTime untilLocal, out int blockMinutesValue)
        {
            untilLocal = default;
            blockMinutesValue = 0;
            if (string.IsNullOrWhiteSpace(ipAddress) || !File.Exists(blockListLogPath))
                return false;

            DateTime nowLocal = DateTime.Now;
            bool found = false;
            lock (logLock)
            {
                foreach (string line in File.ReadAllLines(blockListLogPath))
                {
                    string target = ExtractBlockedTargetFromLine(line);
                    if (string.IsNullOrWhiteSpace(target)
                        || target.Contains("/", StringComparison.Ordinal)
                        || !target.Equals(ipAddress, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    if (IsBlockEntryExpired(line, nowLocal, out DateTime candidateUntil))
                        continue;

                    untilLocal = candidateUntil;
                    blockMinutesValue = ExtractBlockMinutesFromBlockLogLine(line);
                    found = true;
                }
            }

            return found;
        }

        private bool TryGetLatestActiveDirectBlockedIp(out string ipAddress)
        {
            ipAddress = string.Empty;
            if (!File.Exists(blockListLogPath))
                return false;

            DateTime nowLocal = DateTime.Now;
            DateTime bestUntil = DateTime.MinValue;
            string bestIp = string.Empty;

            lock (logLock)
            {
                foreach (string line in File.ReadAllLines(blockListLogPath))
                {
                    string target = ExtractBlockedTargetFromLine(line);
                    if (string.IsNullOrWhiteSpace(target) || target.Contains("/", StringComparison.Ordinal))
                        continue;

                    if (IsBlockEntryExpired(line, nowLocal, out DateTime candidateUntil))
                        continue;

                    if (candidateUntil > bestUntil)
                    {
                        bestUntil = candidateUntil;
                        bestIp = target;
                    }
                }
            }

            if (string.IsNullOrWhiteSpace(bestIp))
                return false;

            ipAddress = bestIp;
            return true;
        }

        private bool TryGetActiveSubnetBlock(string ipAddress, out string subnetCidr, out DateTime untilLocal)
        {
            subnetCidr = string.Empty;
            untilLocal = default;
            if (string.IsNullOrWhiteSpace(ipAddress) || !File.Exists(blockListLogPath))
                return false;

            DateTime nowLocal = DateTime.Now;
            bool found = false;
            lock (logLock)
            {
                foreach (string line in File.ReadAllLines(blockListLogPath))
                {
                    string target = ExtractBlockedTargetFromLine(line);
                    if (string.IsNullOrWhiteSpace(target)
                        || !target.Contains("/", StringComparison.Ordinal)
                        || !IsIpv4InSubnet24(ipAddress, target))
                    {
                        continue;
                    }

                    if (IsBlockEntryExpired(line, nowLocal, out DateTime candidateUntil))
                        continue;

                    subnetCidr = target;
                    untilLocal = candidateUntil;
                    found = true;
                }
            }

            return found;
        }

        private bool IsBlockEntryExpired(string line, DateTime nowLocal, out DateTime untilLocal)
        {
            untilLocal = default;
            if (TryParseUntilFromBlockLogLine(line, out untilLocal))
                return nowLocal > untilLocal;

            if (TryParseBlockLogTimestamp(line, out DateTime tsLocal))
            {
                untilLocal = tsLocal.AddMinutes(Math.Max(1, blockMinutes));
                return nowLocal > untilLocal;
            }

            return true;
        }

        private int ExtractBlockMinutesFromBlockLogLine(string line)
        {
            if (string.IsNullOrWhiteSpace(line))
                return Math.Max(1, blockMinutes);

            int idx = line.IndexOf("BlockMinutes:", StringComparison.OrdinalIgnoreCase);
            if (idx < 0)
                return Math.Max(1, blockMinutes);

            string tail = line.Substring(idx + 13).Trim();
            if (tail.Contains("|"))
                tail = tail.Split('|')[0].Trim();

            return int.TryParse(tail, out int parsed)
                ? Math.Max(1, parsed)
                : Math.Max(1, blockMinutes);
        }

        private string GetServiceStatusSummary()
        {
            try
            {
                var service = ServiceController.GetServices().FirstOrDefault(s => s.ServiceName == "RDPSecurityService");
                if (service == null)
                    return IsProcessRunning("WinService")
                        ? "NOT INSTALLED (local WinService.exe is RUNNING)"
                        : "NOT INSTALLED";

                service.Refresh();
                return $"{service.Status} | Startup: {service.StartType}";
            }
            catch (Exception ex)
            {
                return $"ERROR: {ex.Message}";
            }
        }

        private bool IsProcessRunning(string processName)
        {
            try
            {
                return Process.GetProcessesByName(processName).Any();
            }
            catch
            {
                return false;
            }
        }

        private void MonitorTcpProbeConnections(DateTime nowLocal)
        {
            try
            {
                lock (tcpProbeStateLock)
                {
                    CleanupTcpProbeState(nowLocal);
                }

                var connections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
                foreach (var connection in connections)
                {
                    if (connection.LocalEndPoint == null || connection.RemoteEndPoint == null)
                        continue;

                    if (connection.LocalEndPoint.Port != rdpPort)
                        continue;

                    if (connection.State != TcpState.Established && connection.State != TcpState.SynReceived)
                        continue;

                    string remoteIp = connection.RemoteEndPoint.Address.ToString();
                    if (string.IsNullOrWhiteSpace(remoteIp) || IsIPWhitelisted(remoteIp))
                        continue;

                    bool skip = false;
                    lock (tcpProbeStateLock)
                    {
                        recentRdpPortActivityByIp[remoteIp] = nowLocal;

                        string probeKey = $"{remoteIp}|{connection.RemoteEndPoint.Port}|{connection.State}";
                        if (recentTcpProbeKeys.TryGetValue(probeKey, out DateTime seenUntil) && seenUntil > nowLocal)
                            skip = true;
                        else
                            recentTcpProbeKeys[probeKey] = nowLocal.Add(TcpProbeDedupWindow);
                    }

                    if (skip)
                        continue;

                    RegisterTcpProbe(remoteIp, connection.RemoteEndPoint.Port, connection.State, nowLocal);
                }
            }
            catch (Exception ex)
            {
                WriteLog($"TCP probe monitor error: {ex.Message}");
            }
        }

        private void RegisterTcpProbe(string remoteIp, int remotePort, TcpState state, DateTime nowLocal)
        {
            int probeCount;
            lock (tcpProbeStateLock)
            {
                if (!tcpProbeHits.TryGetValue(remoteIp, out List<DateTime>? hits))
                {
                    hits = new List<DateTime>();
                    tcpProbeHits[remoteIp] = hits;
                }

                DateTime cutoff = nowLocal - TcpProbeWindow;
                hits.RemoveAll(ts => ts < cutoff);
                hits.Add(nowLocal);
                probeCount = hits.Count;
            }

            WriteLog($"TCP probe: ip={remoteIp}, remote_port={remotePort}, state={state}, count={probeCount}/{TCP_PROBE_THRESHOLD}, window={TcpProbeWindow.TotalSeconds:0}s");

            if (probeCount < TCP_PROBE_THRESHOLD)
                return;

            // TCP probe monitor is used only for 4625 correlation with configured port activity.
            // Do not ban directly from probe count to avoid premature blocks before login threshold is reached.
            WriteLog($"SCAN threshold reached: ip={remoteIp}, probes={probeCount} (correlation-only, no direct ban)");
        }

        private void CleanupTcpProbeState(DateTime nowLocal)
        {
            DateTime cutoff = nowLocal - TcpProbeWindow;
            var staleIps = tcpProbeHits
                .Where(kvp =>
                {
                    kvp.Value.RemoveAll(ts => ts < cutoff);
                    return kvp.Value.Count == 0;
                })
                .Select(kvp => kvp.Key)
                .ToList();

            for (int i = 0; i < staleIps.Count; i++)
                tcpProbeHits.Remove(staleIps[i]);

            var staleKeys = recentTcpProbeKeys
                .Where(kvp => kvp.Value <= nowLocal)
                .Select(kvp => kvp.Key)
                .ToList();

            for (int i = 0; i < staleKeys.Count; i++)
                recentTcpProbeKeys.Remove(staleKeys[i]);

            DateTime portCutoff = nowLocal - FailedLogonPortCorrelationWindow;
            var staleActivityIps = recentRdpPortActivityByIp
                .Where(kvp => kvp.Value < portCutoff)
                .Select(kvp => kvp.Key)
                .ToList();

            for (int i = 0; i < staleActivityIps.Count; i++)
                recentRdpPortActivityByIp.Remove(staleActivityIps[i]);
        }

        private bool HasRecentRdpPortActivity(string sourceIp, DateTime nowLocal)
        {
            if (string.IsNullOrWhiteSpace(sourceIp))
                return false;

            lock (tcpProbeStateLock)
            {
                if (!recentRdpPortActivityByIp.TryGetValue(sourceIp, out DateTime lastSeen))
                    return false;

                return (nowLocal - lastSeen) <= FailedLogonPortCorrelationWindow;
            }
        }

        private void LogBruteThresholdHit(string sourceIp, int attempts, BlockLevel level)
        {
            if (level == null || attempts != level.Attempts)
                return;

            WriteLog($"BRUTE threshold reached: ip={sourceIp}, attempts={attempts}, block={level.BlockMinutes}m");
        }

        private BlockLevel GetScanBlockLevel()
        {
            var levels = blockLevels;
            BlockLevel firstLevel = levels
                .OrderBy(l => l.Attempts)
                .FirstOrDefault();

            if (firstLevel != null)
            {
                return new BlockLevel
                {
                    Attempts = TCP_PROBE_THRESHOLD,
                    BlockMinutes = Math.Max(1, firstLevel.BlockMinutes)
                };
            }

            return new BlockLevel
            {
                Attempts = TCP_PROBE_THRESHOLD,
                BlockMinutes = 30
            };
        }

        private void SendAccessAttemptNotification(string ipAddress, string targetUser, int attemptCount, DateTime eventTimeLocal)
        {
            try
            {
                string userLabel = string.IsNullOrWhiteSpace(targetUser) ? "unknown" : targetUser.Trim();
                string message = $"🔐 FAILED RDP LOGON\n\nIP: {ipAddress}\nUser: {userLabel}\nAttempt: {attemptCount}\nTime: {eventTimeLocal:yyyy-MM-dd HH:mm:ss}";
                Task.Run(() => SendServiceNotification(message));
            }
            catch { }
        }
        
        private bool IsFailedLogonEvent(EventLogEntry entry)
        {
            try
            {
                if (entry.InstanceId == 4625)
                    return true;

                return ((int)entry.InstanceId & 0xFFFF) == 4625;
            }
            catch
            {
                return false;
            }
        }

        private string ExtractSourceIP(EventLogEntry entry)
        {
            try
            {
                var rs = entry.ReplacementStrings;
                if (rs != null)
                {
                    int[] preferredIndexes = new[] { 19, 20, 21 };
                    foreach (int index in preferredIndexes)
                    {
                        if (index < 0 || index >= rs.Length)
                            continue;

                        string candidate = NormalizeIpCandidate(rs[index]);
                        if (!string.IsNullOrWhiteSpace(candidate))
                            return candidate;
                    }
                }

                string[] markers = new[]
                {
                    "Source Network Address",
                    "Source Network Adress",
                    "Network Address",
                    "Source Address",
                    "Сетевой адрес источника",
                    "Адрес источника",
                    "РЎРµС‚РµРІРѕР№ Р°РґСЂРµСЃ РёСЃС‚РѕС‡РЅРёРєР°",
                    "РђРґСЂРµСЃ РёСЃС‚РѕС‡РЅРёРєР°"
                };

                string eventMessage = entry.Message ?? string.Empty;
                string[] lines = eventMessage.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
                foreach (string line in lines)
                {
                    if (markers.Any(m => line.IndexOf(m, StringComparison.OrdinalIgnoreCase) >= 0))
                    {
                        string candidate = ExtractIpFromMarkedLine(line);
                        if (!string.IsNullOrWhiteSpace(candidate))
                            return candidate;
                    }
                }
            }
            catch (Exception ex)
            {
                WriteLog($"IP parse error: {ex.Message}");
            }
            return null;
        }

        private string ExtractIpFromMarkedLine(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return null;

            int colonIndex = text.IndexOf(':');
            string valuePart = colonIndex >= 0 && colonIndex < text.Length - 1
                ? text.Substring(colonIndex + 1)
                : text;

            foreach (string token in SplitIpCandidates(valuePart))
            {
                string candidate = NormalizeIpCandidate(token);
                if (!string.IsNullOrWhiteSpace(candidate))
                    return candidate;
            }

            return null;
        }

        private void DumpSuspicious4625(EventLogEntry entry)
        {
            try
            {
                string dumpPath = Path.Combine(logDirectory, "4625-dump.log");
                var lines = new List<string>
                {
                    $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] Record={entry.Index}; Time={entry.TimeGenerated:yyyy-MM-dd HH:mm:ss}; InstanceId={entry.InstanceId}"
                };

                var rs = entry.ReplacementStrings;
                if (rs != null)
                {
                    for (int i = 0; i < rs.Length; i++)
                    {
                        string value = rs[i] ?? string.Empty;
                        value = value.Replace("\r", " ").Replace("\n", " ").Trim();
                        lines.Add($"RS[{i}]={value}");
                    }
                }

                string message = (entry.Message ?? string.Empty).Replace("\r", string.Empty);
                if (!string.IsNullOrWhiteSpace(message))
                {
                    lines.Add("MSG_BEGIN");
                    lines.AddRange(message.Split('\n').Select(line => line.TrimEnd()));
                    lines.Add("MSG_END");
                }

                lines.Add(string.Empty);

                lock (logLock)
                {
                    File.AppendAllLines(dumpPath, lines, Encoding.UTF8);
                }
            }
            catch { }
        }

        private void DumpSuspicious4625(EventRecord record)
        {
            try
            {
                string dumpPath = Path.Combine(logDirectory, "4625-dump.log");
                string xml = record.ToXml() ?? string.Empty;
                var lines = new List<string>
                {
                    $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] Record={record.RecordId}; Time={record.TimeCreated:yyyy-MM-dd HH:mm:ss}; EventId={record.Id}",
                    "XML_BEGIN",
                    xml,
                    "XML_END",
                    string.Empty
                };

                lock (logLock)
                {
                    File.AppendAllLines(dumpPath, lines, Encoding.UTF8);
                }
            }
            catch { }
        }

        private IEnumerable<string> SplitIpCandidates(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return Enumerable.Empty<string>();

            return text.Split(new[] { ' ', '\t', '\r', '\n', ',', ';', '|', '(', ')', '{', '}', '"', '\'' }, StringSplitOptions.RemoveEmptyEntries);
        }

        private string NormalizeIpCandidate(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw))
                return null;

            string candidate = raw.Trim().Trim('.', ':');
            if (candidate == "-" || candidate.Equals("localhost", StringComparison.OrdinalIgnoreCase))
                return null;

            if (candidate.StartsWith("[", StringComparison.Ordinal) && candidate.Contains("]", StringComparison.Ordinal))
            {
                int close = candidate.IndexOf(']');
                candidate = candidate.Substring(1, close - 1);
            }

            if (candidate.Count(c => c == ':') == 1 && candidate.Contains('.') && candidate.LastIndexOf(':') > 0)
            {
                string withoutPort = candidate.Substring(0, candidate.LastIndexOf(':'));
                if (IPAddress.TryParse(withoutPort, out _))
                    candidate = withoutPort;
            }

            if (candidate.StartsWith("::ffff:", StringComparison.OrdinalIgnoreCase))
            {
                string mapped = candidate.Substring(7);
                if (IPAddress.TryParse(mapped, out IPAddress mappedIp))
                    candidate = mappedIp.ToString();
            }

            if (!IPAddress.TryParse(candidate, out IPAddress ip))
                return null;

            if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any))
                return null;

            if (ip.IsIPv4MappedToIPv6)
                return ip.MapToIPv4().ToString();

            return ip.ToString();
        }

        private string ExtractTargetUser(EventLogEntry entry)
        {
            try
            {
                var rs = entry.ReplacementStrings;
                if (rs != null)
                {
                    if (rs.Length > 5)
                    {
                        string candidate = NormalizeUserCandidate(rs[5]);
                        if (!string.IsNullOrWhiteSpace(candidate))
                            return candidate;
                    }

                    for (int i = 0; i < rs.Length; i++)
                    {
                        string candidate = NormalizeUserCandidate(rs[i]);
                        if (!string.IsNullOrWhiteSpace(candidate))
                            return candidate;
                    }
                }

                string[] markers = new[]
                {
                    "Account For Which Logon Failed",
                    "TargetUserName",
                    "Имя учетной записи",
                    "Учетная запись"
                };

                string eventMessage = entry.Message ?? string.Empty;
                string[] lines = eventMessage.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
                foreach (string line in lines)
                {
                    if (markers.Any(m => line.IndexOf(m, StringComparison.OrdinalIgnoreCase) >= 0))
                    {
                        string candidate = NormalizeUserCandidate(line);
                        if (!string.IsNullOrWhiteSpace(candidate))
                            return candidate;
                    }
                }
            }
            catch { }

            return string.Empty;
        }

        private string NormalizeUserCandidate(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw))
                return string.Empty;

            string s = raw.Trim();
            int colon = s.LastIndexOf(':');
            if (colon >= 0 && colon < s.Length - 1)
                s = s.Substring(colon + 1).Trim();

            if (s.StartsWith(".", StringComparison.Ordinal))
                return string.Empty;

            if (s.Equals("-", StringComparison.OrdinalIgnoreCase) ||
                s.Equals("ANONYMOUS LOGON", StringComparison.OrdinalIgnoreCase) ||
                s.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                s.Equals("LOCAL SERVICE", StringComparison.OrdinalIgnoreCase) ||
                s.Equals("NETWORK SERVICE", StringComparison.OrdinalIgnoreCase) ||
                s.Equals("N/A", StringComparison.OrdinalIgnoreCase))
                return string.Empty;

            if (s.Contains("\\", StringComparison.Ordinal))
                s = s.Split('\\').LastOrDefault()?.Trim() ?? string.Empty;

            if (string.IsNullOrWhiteSpace(s))
                return string.Empty;

            return s;
        }

        private bool RegisterFailedUserAndCheckIpAbuse(string sourceIp, string targetUser, DateTime nowLocal)
        {
            string normalizedIp = NormalizeIpCandidate(sourceIp);
            if (string.IsNullOrWhiteSpace(normalizedIp))
                return false;

            string userKey = NormalizeUserCandidate(targetUser);
            if (string.IsNullOrWhiteSpace(userKey))
                return false;

            int windowMinutes = Math.Max(1, ipAbuseWindowMinutes);
            int usersThreshold = Math.Max(2, ipAbuseDistinctUsersThreshold);

            int distinctUsers;
            lock (failedUsersByIpLock)
            {
                if (!failedUsersByIp.TryGetValue(normalizedIp, out IpFailedUsersState? state))
                {
                    state = new IpFailedUsersState();
                    failedUsersByIp[normalizedIp] = state;
                }

                DateTime cutoff = nowLocal.AddMinutes(-windowMinutes);
                var staleUsers = state.Users
                    .Where(p => p.Value < cutoff)
                    .Select(p => p.Key)
                    .ToList();

                for (int i = 0; i < staleUsers.Count; i++)
                    state.Users.Remove(staleUsers[i]);

                state.Users[userKey] = nowLocal;
                distinctUsers = state.Users.Count;
            }

            return distinctUsers >= usersThreshold;
        }

        private bool TryApplySprayBan(string targetUser, string sourceIp, DateTime eventTimeLocal, DateTime nowLocal)
        {
            var anti = antiBruteConfig;
            if (anti == null || !anti.Enabled)
                return false;

            var cfg = anti.Spray;
            if (cfg == null || !cfg.Enabled)
                return false;

            if (string.IsNullOrWhiteSpace(targetUser) || string.IsNullOrWhiteSpace(sourceIp))
                return false;

            int windowMinutes = Math.Max(1, cfg.WindowMinutes);
            int uniqueIpsThreshold = Math.Max(2, cfg.UniqueIpsThreshold);
            int sprayBlockMinutes = Math.Max(1, cfg.BlockMinutes);

            string userKey = targetUser.Trim().ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(userKey))
                return false;

            int uniqueCount;
            if (!sprayByUser.TryGetValue(userKey, out SprayState? state))
            {
                state = new SprayState();
                sprayByUser[userKey] = state;
            }

            DateTime cutoff = nowLocal.AddMinutes(-windowMinutes);
            var stale = state.SourceIps
                .Where(p => p.Value < cutoff)
                .Select(p => p.Key)
                .ToList();

            for (int i = 0; i < stale.Count; i++)
                state.SourceIps.Remove(stale[i]);

            state.SourceIps[sourceIp] = nowLocal;
            uniqueCount = state.SourceIps.Count;

            if (uniqueCount < uniqueIpsThreshold)
                return false;

            var sprayLevel = new BlockLevel { Attempts = uniqueIpsThreshold, BlockMinutes = sprayBlockMinutes };
            if (!ShouldApplyBan(sourceIp, uniqueCount, sprayLevel, nowLocal))
                return false;

            ApplyIpBan(sourceIp, eventTimeLocal, uniqueCount, sprayLevel.BlockMinutes, sprayLevel.Attempts, $"spray user={targetUser}");
            SendServiceNotification($"🧯 SPRAY: user={targetUser}, ip={sourceIp}, unique_ips={uniqueCount}, window={windowMinutes}m");
            return true;
        }

        // Catches the "low-and-slow" pattern that TryApplySprayBan can miss: only 1-2 failed
        // attempts per IP, but all hitting the same login from IPs inside one /24 — a much
        // stronger brute-force signal than a bare distinct-IP count, so it can trigger on far
        // fewer attempts. Only bans the specific IPs seen for this (user, subnet) pair;
        // escalating to a whole-subnet ban stays the job of TryEscalateSubnetBan.
        private bool TryApplySubnetUserSprayBan(string targetUser, string sourceIp, DateTime eventTimeLocal, DateTime nowLocal)
        {
            var anti = antiBruteConfig;
            if (anti == null || !anti.Enabled)
                return false;

            var cfg = anti.SubnetUserSpray;
            if (cfg == null || !cfg.Enabled)
                return false;

            if (string.IsNullOrWhiteSpace(targetUser) || string.IsNullOrWhiteSpace(sourceIp))
                return false;

            string? subnet = GetSubnet24(sourceIp);
            if (string.IsNullOrWhiteSpace(subnet))
                return false;

            int windowMinutes = Math.Max(1, cfg.WindowMinutes);
            int uniqueIpsThreshold = Math.Max(2, cfg.UniqueIpsInSubnetThreshold);
            int sprayBlockMinutes = Math.Max(1, cfg.BlockMinutes);

            string userKey = targetUser.Trim().ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(userKey))
                return false;

            string stateKey = $"{userKey}|{subnet}";

            int uniqueCount;
            if (!subnetUserSprayByKey.TryGetValue(stateKey, out SubnetUserSprayState? state))
            {
                state = new SubnetUserSprayState();
                subnetUserSprayByKey[stateKey] = state;
            }

            DateTime cutoff = nowLocal.AddMinutes(-windowMinutes);
            var stale = state.SourceIps
                .Where(p => p.Value < cutoff)
                .Select(p => p.Key)
                .ToList();

            for (int i = 0; i < stale.Count; i++)
                state.SourceIps.Remove(stale[i]);

            state.SourceIps[sourceIp] = nowLocal;
            uniqueCount = state.SourceIps.Count;

            if (uniqueCount < uniqueIpsThreshold)
                return false;

            var level = new BlockLevel { Attempts = uniqueIpsThreshold, BlockMinutes = sprayBlockMinutes };
            if (!ShouldApplyBan(sourceIp, uniqueCount, level, nowLocal))
                return false;

            ApplyIpBan(sourceIp, eventTimeLocal, uniqueCount, level.BlockMinutes, level.Attempts, $"subnet-user-spray user={targetUser} subnet={subnet}");
            SendServiceNotification($"🧯 SUBNET+USER SPRAY: user={targetUser}, subnet={subnet}, ip={sourceIp}, unique_ips_in_subnet={uniqueCount}, window={windowMinutes}m");
            return true;
        }

        private void ApplyIpBan(string ipAddress, DateTime eventTimeLocal, int attemptCount, int requestedBlockMinutes, int appliedAttempts, string reason, string? attackingUser = null)
        {
            if (IsLocalOrPrivateIp(ipAddress))
            {
                WriteLog($"Skipped ban for protected local/private IP: {ipAddress}");
                return;
            }

            // Skip ban only if the attacking user is the same as the currently active session user from this IP.
            // If a different user is being brute-forced from an active-session IP — still block it.
            if (HasActiveRdpSessionFromIp(ipAddress))
            {
                string? activeUser = null;
                lock (activeLogonsByIpLock)
                {
                    activeLogonsByIp.TryGetValue(NormalizeIpCandidate(ipAddress) ?? ipAddress, out activeUser);
                }
                bool sameUser = !string.IsNullOrWhiteSpace(attackingUser) &&
                                !string.IsNullOrWhiteSpace(activeUser) &&
                                string.Equals(activeUser, attackingUser, StringComparison.OrdinalIgnoreCase);
                if (sameUser)
                {
                    WriteLog($"Skipped ban for active RDP session IP: {ipAddress}, same user '{activeUser}' (reason={reason})");
                    return;
                }
                // Different user attacking from a shared/NAT IP with active session — proceed with ban
                WriteLog($"Proceeding with ban for IP {ipAddress}: active user='{activeUser}' but attacking user='{attackingUser}' (reason={reason})");
            }

            DateTime nowLocal = DateTime.Now;
            int effectiveBlockMinutes = GetEffectiveBlockMinutes(ipAddress, requestedBlockMinutes, nowLocal);
            DateTime until = nowLocal.AddMinutes(Math.Max(1, effectiveBlockMinutes));

            WriteBlockLog(ipAddress, eventTimeLocal, attemptCount, effectiveBlockMinutes, until);

            lock (bansLock)
            {
                bans[ipAddress] = new BanState
                {
                    AppliedAttempts = appliedAttempts,
                    UntilLocal = until
                };
            }

            // Note: Do NOT reset failedAttempts[ipAddress] here.
            // Resetting prevents escalation to higher ban levels (e.g., 3 attempts -> 10 attempts for stronger ban).
            // The counter must persist to allow proper level progression during the ban period.
            // (It still ages out naturally: entries older than failedAttemptsWindowDays are
            // pruned on the next failed attempt, and it's cleared entirely once this ban is
            // lifted — see ClearInMemoryStateForExpiredTarget / ReconcileBanStateAgainstBlockList.)

            if (!string.IsNullOrWhiteSpace(reason))
                WriteLog($"Ban applied ({reason}): {ipAddress} for {effectiveBlockMinutes}m (until {until:yyyy-MM-dd HH:mm:ss})");

            TryEscalateSubnetBan(ipAddress, eventTimeLocal, nowLocal);
        }

        private int GetEffectiveBlockMinutes(string ipAddress, int baseMinutes, DateTime nowLocal)
        {
            int safeBaseMinutes = Math.Max(1, baseMinutes);
            var anti = antiBruteConfig;
            if (anti == null || !anti.Enabled)
                return safeBaseMinutes;

            var cfg = anti.Recurrence;
            if (cfg == null || !cfg.Enabled)
                return safeBaseMinutes;

            int lookbackHours = Math.Max(1, cfg.LookbackHours);
            double stepMultiplier = Math.Max(0.0, cfg.StepMultiplier);
            double maxMultiplier = Math.Max(1.0, cfg.MaxMultiplier);

            int recentBanCount = CountRecentIpBans(ipAddress, nowLocal.AddHours(-lookbackHours), nowLocal);
            if (recentBanCount <= 0)
                return safeBaseMinutes;

            double factor = Math.Min(maxMultiplier, 1.0 + (recentBanCount * stepMultiplier));
            int boosted = (int)Math.Ceiling(safeBaseMinutes * factor);
            WriteLog($"Recurrence boost for {ipAddress}: history={recentBanCount}, factor={factor:F2}, minutes={boosted}");
            return Math.Max(1, boosted);
        }

        private int CountRecentIpBans(string ipAddress, DateTime fromLocal, DateTime nowLocal)
        {
            if (string.IsNullOrWhiteSpace(ipAddress) || !File.Exists(blockListLogPath))
                return 0;

            int count = 0;
            lock (logLock)
            {
                foreach (string line in File.ReadAllLines(blockListLogPath))
                {
                    if (!TryParseBlockLogTimestamp(line, out DateTime tsLocal))
                        continue;

                    if (tsLocal < fromLocal || tsLocal > nowLocal)
                        continue;

                    string target = ExtractBlockedTargetFromLine(line);
                    if (!string.IsNullOrWhiteSpace(target) && target.Equals(ipAddress, StringComparison.OrdinalIgnoreCase))
                        count++;
                }
            }

            return count;
        }

        private void TryEscalateSubnetBan(string sourceIp, DateTime eventTimeLocal, DateTime nowLocal)
        {
            var anti = antiBruteConfig;
            if (anti == null || !anti.Enabled)
                return;

            var cfg = anti.Subnet;
            if (cfg == null || !cfg.Enabled)
                return;

            string subnet = GetSubnet24(sourceIp);
            if (string.IsNullOrWhiteSpace(subnet))
                return;

            int windowMinutes = Math.Max(1, cfg.WindowMinutes);
            int uniqueIpsThreshold = Math.Max(2, cfg.UniqueIpsThreshold);
            int subnetBlockMinutes = Math.Max(1, cfg.BlockMinutes);

            int recentUniqueIps = CountRecentBlockedIpsInSubnet(subnet, nowLocal.AddMinutes(-windowMinutes), nowLocal);
            if (recentUniqueIps < uniqueIpsThreshold)
                return;

            lock (bansLock)
            {
                if (subnetBans.TryGetValue(subnet, out BanState? state))
                {
                    if (nowLocal <= state.UntilLocal)
                        return;

                    subnetBans.Remove(subnet);
                }
            }

            var whitelist = LoadWhitelistSet();
            if (SubnetContainsWhitelistedIp(subnet, whitelist))
            {
                WriteLog($"Subnet escalation skipped due to whitelist overlap: {subnet}");
                return;
            }

            if (SubnetContainsActiveRdpSessionIp(subnet))
            {
                WriteLog($"Subnet escalation skipped due to active RDP session in subnet: {subnet}");
                return;
            }

            DateTime until = nowLocal.AddMinutes(subnetBlockMinutes);
            WriteSubnetBlockLog(subnet, eventTimeLocal, recentUniqueIps, subnetBlockMinutes, until);

            lock (bansLock)
            {
                subnetBans[subnet] = new BanState
                {
                    AppliedAttempts = recentUniqueIps,
                    UntilLocal = until
                };
            }

            SendServiceNotification($"🚫 SUBNET BLOCK: {subnet} | Unique IPs: {recentUniqueIps} | Ban: {subnetBlockMinutes} min");
        }

        private void WriteSubnetBlockLog(string subnetCidr, DateTime timestamp, int triggerCount, int blockMinutesValue, DateTime untilLocal)
        {
            try
            {
                lock (logLock)
                {
                    string logEntry =
                        $"[{timestamp:yyyy-MM-dd HH:mm:ss}] BLOCKED NET: {subnetCidr} | Triggers: {triggerCount} | BlockMinutes: {blockMinutesValue} | Until: {untilLocal:yyyy-MM-dd HH:mm:ss}";
                    File.AppendAllText(blockListLogPath, logEntry + Environment.NewLine, Encoding.UTF8);
                }
            }
            catch (Exception ex)
            {
                try { WriteLog($"Failed to write block_list.log (subnet): {ex.Message}"); } catch { }
            }

            RequestFirewallSync();
        }

        private int CountRecentBlockedIpsInSubnet(string subnetCidr, DateTime fromLocal, DateTime nowLocal)
        {
            if (string.IsNullOrWhiteSpace(subnetCidr) || !File.Exists(blockListLogPath))
                return 0;

            var uniqueIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            lock (logLock)
            {
                foreach (string line in File.ReadAllLines(blockListLogPath))
                {
                    if (!TryParseBlockLogTimestamp(line, out DateTime tsLocal))
                        continue;

                    if (tsLocal < fromLocal || tsLocal > nowLocal)
                        continue;

                    string target = ExtractBlockedTargetFromLine(line);
                    if (string.IsNullOrWhiteSpace(target))
                        continue;

                    if (target.Contains("/", StringComparison.Ordinal))
                        continue;

                    if (IsIpv4InSubnet24(target, subnetCidr))
                        uniqueIps.Add(target);
                }
            }

            return uniqueIps.Count;
        }

        private string? GetSubnet24(string ipAddress)
        {
            if (!IPAddress.TryParse(ipAddress, out IPAddress ip))
                return null;

            if (ip.AddressFamily != AddressFamily.InterNetwork)
                return null;

            byte[] bytes = ip.GetAddressBytes();
            return $"{bytes[0]}.{bytes[1]}.{bytes[2]}.0/24";
        }

        private bool IsIpv4InSubnet24(string ipAddress, string subnetCidr)
        {
            if (!IPAddress.TryParse(ipAddress, out IPAddress ip))
                return false;

            if (ip.AddressFamily != AddressFamily.InterNetwork)
                return false;

            if (!TryParseSubnet24(subnetCidr, out byte[]? netBytes) || netBytes == null)
                return false;

            byte[] bytes = ip.GetAddressBytes();
            return bytes[0] == netBytes[0] && bytes[1] == netBytes[1] && bytes[2] == netBytes[2];
        }

        private bool SubnetContainsWhitelistedIp(string subnetCidr, HashSet<string> whitelist)
        {
            if (whitelist == null || whitelist.Count == 0)
                return false;

            foreach (string ip in whitelist)
            {
                if (IsIpv4InSubnet24(ip, subnetCidr))
                    return true;
            }

            return false;
        }

        private bool HasActiveRdpSessionFromIp(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return false;

            try
            {
                var sessions = GetActiveUserSessions();
                for (int i = 0; i < sessions.Count; i++)
                {
                    string clientIp = sessions[i].ClientIp?.Trim() ?? string.Empty;
                    if (!string.IsNullOrWhiteSpace(clientIp)
                        && AreSameIpAddress(clientIp, ipAddress))
                    {
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                WriteLog($"Active session IP check error: {ex.Message}");
            }

            return false;
        }

        private bool SubnetContainsActiveRdpSessionIp(string subnetCidr)
        {
            if (string.IsNullOrWhiteSpace(subnetCidr))
                return false;

            try
            {
                var sessions = GetActiveUserSessions();
                for (int i = 0; i < sessions.Count; i++)
                {
                    string clientIp = sessions[i].ClientIp?.Trim() ?? string.Empty;
                    if (!string.IsNullOrWhiteSpace(clientIp) && IsIpv4InSubnet24(clientIp, subnetCidr))
                        return true;
                }
            }
            catch (Exception ex)
            {
                WriteLog($"Active session subnet check error: {ex.Message}");
            }

            return false;
        }

        private bool TryParseSubnet24(string subnetCidr, out byte[]? netBytes)
        {
            netBytes = null;
            if (string.IsNullOrWhiteSpace(subnetCidr))
                return false;

            string[] parts = subnetCidr.Trim().Split('/');
            if (parts.Length != 2 || parts[1] != "24")
                return false;

            if (!IPAddress.TryParse(parts[0], out IPAddress net) || net.AddressFamily != AddressFamily.InterNetwork)
                return false;

            netBytes = net.GetAddressBytes();
            return true;
        }

        private void OnLogChanged(object sender, FileSystemEventArgs e)
        {
            try
            {
                // small debounce
                Thread.Sleep(200);
                if (string.Equals(e.Name, "block_list.log", StringComparison.OrdinalIgnoreCase))
                {
                    RequestFirewallSync();
                }
                else if (string.Equals(e.Name, "whiteList.log", StringComparison.OrdinalIgnoreCase))
                {
                    // whitelist changed: ensure no whitelisted IP remains in firewall block list
                    RequestFirewallSync();
                }
                else if (string.Equals(e.Name, "config.json", StringComparison.OrdinalIgnoreCase))
                {
                    LoadOrCreateConfig();
                    RequestFirewallSync();
                    WriteLog($"Config reloaded: Port={rdpPort}; Levels={string.Join(",", blockLevels.Select(l => $"{l.Attempts}->{l.BlockMinutes}m"))}");
                }
            }
            catch { }
        }

        private bool IsIPWhitelisted(string ipAddress)
        {
            try
            {
                return LoadWhitelistSet().Contains(ipAddress);
            }
            catch (Exception ex)
            {
                WriteLog($"Error checking whitelist: {ex.Message}");
                return false;
            }
        }

        private bool IsLocalOrPrivateIp(string ipAddress)
        {
            if (!IPAddress.TryParse(ipAddress, out IPAddress parsedIp))
                return false;

            var ip = parsedIp.IsIPv4MappedToIPv6 ? parsedIp.MapToIPv4() : parsedIp;
            if (IPAddress.IsLoopback(ip))
                return true;

            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                byte[] bytes = ip.GetAddressBytes();
                if (bytes.Length != 4)
                    return false;

                return bytes[0] == 10
                    || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                    || (bytes[0] == 192 && bytes[1] == 168)
                    || (bytes[0] == 169 && bytes[1] == 254);
            }

            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal)
                    return true;

                byte[] bytes = ip.GetAddressBytes();
                return bytes.Length > 0 && (bytes[0] & 0xFE) == 0xFC;
            }

            return false;
        }

        private HashSet<string> GetLocalAutoWhitelistIps()
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "127.0.0.1"
            };

            try
            {
                foreach (var ip in Dns.GetHostAddresses(Dns.GetHostName()))
                {
                    if (ip.AddressFamily != AddressFamily.InterNetwork)
                        continue;

                    string text = ip.ToString();
                    if (IsLocalOrPrivateIp(text))
                        set.Add(text);
                }
            }
            catch
            {
            }

            return set;
        }

        private void BlockIP(string ipAddress)
        {
            // Deprecated: we update firewall rules centrally from block_list.log
            // Keep this method for compatibility but simply update the aggregate rule
            try
            {
                RequestFirewallSync();
            }
            catch (Exception ex)
            {
                WriteLog($"Error updating aggregated firewall rule: {ex.Message}");
            }
        }

        private void WriteAccessLog(string ipAddress, DateTime timestamp, int attemptCount)
        {
            try
            {
                lock (logLock)
                {
                    string logEntry = $"[{timestamp:yyyy-MM-dd HH:mm:ss}] IP: {ipAddress} | Attempts: {attemptCount}";
                    File.AppendAllText(accessLogPath, logEntry + Environment.NewLine, Encoding.UTF8);
                }
            }
            catch (Exception ex)
            {
                try { WriteLog($"Failed to write access.log: {ex.Message}"); } catch { }
            }
        }

        private void WriteBlockLog(string ipAddress, DateTime timestamp, int attemptCount, int blockMinutes, DateTime untilLocal)
        {
            try
            {
                lock (logLock)
                {
                    string logEntry =
                        $"[{timestamp:yyyy-MM-dd HH:mm:ss}] BLOCKED IP: {ipAddress} | Failed Attempts: {attemptCount} | BlockMinutes: {blockMinutes} | Until: {untilLocal:yyyy-MM-dd HH:mm:ss}";
                    File.AppendAllText(blockListLogPath, logEntry + Environment.NewLine, Encoding.UTF8);
                }
            }
            catch (Exception ex)
            {
                try { WriteLog($"Failed to write block_list.log: {ex.Message}"); } catch { }
            }

            // РџРѕСЃР»Рµ Р·Р°РїРёСЃРё РІ С„Р°Р№Р» РѕР±РЅРѕРІР»СЏРµРј РµРґРёРЅРѕРµ РїСЂР°РІРёР»Рѕ
            RequestFirewallSync();

            // Send Telegram notification
            try { SendTelegramNotification(ipAddress, attemptCount, blockMinutes, untilLocal); } catch { }
        }

        private async void SendTelegramNotification(string ipAddress, int attemptCount, int blockMinutes, DateTime untilLocal)
        {
            try
            {
                var cfg = telegramConfig;
                if (cfg == null || !cfg.Enabled || string.IsNullOrWhiteSpace(cfg.BotToken) || string.IsNullOrWhiteSpace(cfg.ChatId))
                    return;

                // Determine which level template to use
                string templateKey = "default";
                var levels = blockLevels;
                if (levels != null && levels.Count > 0)
                {
                    for (int i = 0; i < levels.Count; i++)
                    {
                        if (attemptCount <= levels[i].Attempts)
                        {
                            templateKey = $"level{i + 1}";
                            break;
                        }
                    }
                    // If attempts exceed all levels, use the last level
                    if (templateKey == "default" && attemptCount > levels[levels.Count - 1].Attempts)
                    {
                        templateKey = $"level{levels.Count}";
                    }
                }

                // Get template
                string template;
                if (cfg.MessageTemplates != null && cfg.MessageTemplates.ContainsKey(templateKey))
                {
                    template = cfg.MessageTemplates[templateKey];
                }
                else if (cfg.MessageTemplates != null && cfg.MessageTemplates.ContainsKey("default"))
                {
                    template = cfg.MessageTemplates["default"];
                }
                else
                {
                    // Fallback template
                    template = "🚨 RDP Security Alert\\n\\nBlocked IP: {ip}\\nAttempts: {attempts}\\nBan: {duration} min";
                }

                // Replace placeholders
                string message = template
                    .Replace("{ip}", ipAddress)
                    .Replace("{attempts}", attemptCount.ToString())
                    .Replace("{duration}", blockMinutes.ToString())
                    .Replace("\\n", "\n");

                message = NormalizeTelegramText(message);

                using (var client = new System.Net.Http.HttpClient())
                {
                    client.Timeout = TimeSpan.FromSeconds(10);
                    var url = $"https://api.telegram.org/bot{cfg.BotToken}/sendMessage";
                    var content = new System.Net.Http.FormUrlEncodedContent(new[]
                    {
                        new KeyValuePair<string, string>("chat_id", cfg.ChatId),
                        new KeyValuePair<string, string>("text", message),
                        new KeyValuePair<string, string>("parse_mode", "Markdown")
                    });
                    
                    var response = await client.PostAsync(url, content);
                    if (!response.IsSuccessStatusCode)
                    {
                        WriteLog($"Telegram notification failed: {response.StatusCode}");
                    }
                }
            }
            catch (Exception ex)
            {
                WriteLog($"Telegram send error: {ex.Message}");
            }
        }

        private void RequestFirewallSync(bool force = false)
        {
            if (force)
            {
                TryUpdateFirewallNow();
                return;
            }

            TimeSpan delay = TimeSpan.Zero;
            bool runNow = false;

            lock (firewallSyncLock)
            {
                DateTime nowUtc = DateTime.UtcNow;
                DateTime nextAllowed = lastFirewallSyncUtc + FirewallSyncDebounce;

                if (nowUtc >= nextAllowed)
                {
                    lastFirewallSyncUtc = nowUtc;
                    runNow = true;
                }
                else
                {
                    if (firewallSyncQueued)
                        return;

                    firewallSyncQueued = true;
                    delay = nextAllowed - nowUtc;
                }
            }

            if (runNow)
            {
                TryUpdateFirewallNow();
                return;
            }

            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    if (delay > TimeSpan.Zero)
                        Thread.Sleep(delay);
                }
                catch { }

                lock (firewallSyncLock)
                {
                    firewallSyncQueued = false;
                    lastFirewallSyncUtc = DateTime.UtcNow;
                }

                TryUpdateFirewallNow();
            });
        }

        private void TryUpdateFirewallNow()
        {
            try
            {
                UpdateFirewallRuleFromBlockList();
            }
            catch (Exception ex)
            {
                WriteLog($"Firewall sync error: {ex.Message}");
            }
        }

        // Mirrors manual unban: once a block has run its full natural course, the target
        // gets a clean slate instead of leaving its lifetime failed-attempt count sitting
        // at/above the threshold, which would otherwise re-trigger a ban on the very next
        // single failed logon, forever. Relevant e.g. for a shared NAT/office IP where
        // occasional typos from different accounts land on the same per-IP counter.
        private void ClearInMemoryStateForExpiredTarget(string? expiredTarget)
        {
            if (string.IsNullOrWhiteSpace(expiredTarget))
                return;

            bool isSubnet = expiredTarget.Contains("/", StringComparison.Ordinal);

            lock (bansLock)
            {
                if (isSubnet)
                    subnetBans.Remove(expiredTarget);
                else
                    bans.Remove(expiredTarget);
            }

            if (!isSubnet)
            {
                lock (failedAttemptsLock)
                {
                    failedAttempts.Remove(expiredTarget);
                }
            }
        }

        // Catches every way a block can disappear from block_list.log that the per-line
        // expiry check above doesn't: most notably the monitor GUI's manual unblock, which
        // edits the file directly (removing the line outright, not via an "Until" that just
        // passed) and then signals the service to resync — it never calls
        // ClearInMemoryStateForExpiredTarget itself. Without this, a manually-unblocked IP's
        // failed-attempt count would sit at/above the threshold forever, ready to re-trigger
        // a ban on the very next single failed logon.
        private void ReconcileBanStateAgainstBlockList(IReadOnlyCollection<string> currentlyBlockedTargets)
        {
            var currentSet = new HashSet<string>(currentlyBlockedTargets, StringComparer.OrdinalIgnoreCase);
            List<string> staleDirectBans;

            lock (bansLock)
            {
                staleDirectBans = bans.Keys.Where(ip => !currentSet.Contains(ip)).ToList();
                foreach (var ip in staleDirectBans)
                    bans.Remove(ip);

                var staleSubnetBans = subnetBans.Keys.Where(subnet => !currentSet.Contains(subnet)).ToList();
                foreach (var subnet in staleSubnetBans)
                    subnetBans.Remove(subnet);
            }

            if (staleDirectBans.Count > 0)
            {
                lock (failedAttemptsLock)
                {
                    foreach (var ip in staleDirectBans)
                        failedAttempts.Remove(ip);
                }
            }
        }

        private void UpdateFirewallRuleFromBlockList()
        {
            try
            {
                var whitelist = LoadWhitelistSet();
                List<string> blockedTargets = new List<string>();
                bool blockListPruned = false;
                bool expiredPruned = false;
                DateTime now = DateTime.Now;
                int defaultTtlMinutes = Math.Max(1, blockMinutes);

                if (File.Exists(blockListLogPath))
                {
                    lock (logLock)
                    {
                        var lines = File.ReadAllLines(blockListLogPath).ToList();
                        var keptLines = new List<string>(lines.Count);

                        foreach (var line in lines)
                        {
                            if (string.IsNullOrWhiteSpace(line))
                                continue;

                            // Expiration: prefer explicit "Until", otherwise fallback to timestamp + default TTL.
                            if (TryParseUntilFromBlockLogLine(line, out DateTime untilLocal))
                            {
                                if (now > untilLocal)
                                {
                                    expiredPruned = true;
                                    ClearInMemoryStateForExpiredTarget(ExtractBlockedTargetFromLine(line));
                                    continue;
                                }
                            }
                            else if (TryParseBlockLogTimestamp(line, out DateTime ts))
                            {
                                if (now - ts > TimeSpan.FromMinutes(defaultTtlMinutes))
                                {
                                    expiredPruned = true;
                                    ClearInMemoryStateForExpiredTarget(ExtractBlockedTargetFromLine(line));
                                    continue; // expired block entry
                                }
                            }

                            string target = ExtractBlockedTargetFromLine(line);
                            if (!string.IsNullOrWhiteSpace(target) &&
                                !target.Contains("/", StringComparison.Ordinal) &&
                                whitelist.Contains(target))
                            {
                                blockListPruned = true;
                                continue; // whitelist has priority; remove from block list file
                            }

                            if (!string.IsNullOrWhiteSpace(target) &&
                                target.Contains("/", StringComparison.Ordinal) &&
                                SubnetContainsWhitelistedIp(target, whitelist))
                            {
                                blockListPruned = true;
                                continue; // do not keep subnet block that overlaps explicit whitelist
                            }

                            keptLines.Add(line);
                            if (!string.IsNullOrWhiteSpace(target) && !blockedTargets.Contains(target))
                                blockedTargets.Add(target);
                        }

                        if (blockListPruned || expiredPruned)
                            File.WriteAllLines(blockListLogPath, keptLines);
                    }
                }

                if (blockListPruned)
                    WriteLog("Pruned whitelisted IPs from block_list.log");
                if (expiredPruned)
                    WriteLog($"Pruned expired IPs from block_list.log (default TTL={defaultTtlMinutes}m)");

                // Safety net beyond the per-line expiry handling above: whatever line is no
                // longer present in block_list.log — because it expired *or* because it was
                // removed by someone/something other than this loop (e.g. the monitor GUI's
                // manual unban, which edits the file directly and then just asks for a
                // resync) — should not leave a stale ban or attempt count sitting in memory.
                ReconcileBanStateAgainstBlockList(blockedTargets);

                // Normalize targets for netsh ("/24" -> "x.x.x.0-x.x.x.255") and split them
                // into the fixed RDP_BLOCK_0..RDP_BLOCK_{N-1} buckets, so a new ban only
                // rewrites the one small rule it belongs to instead of one giant combined list.
                var targetsByBucket = new List<string>[FirewallBuckets.Count];
                for (int i = 0; i < targetsByBucket.Length; i++)
                    targetsByBucket[i] = new List<string>();

                foreach (var t in blockedTargets)
                {
                    if (string.IsNullOrWhiteSpace(t))
                        continue;

                    string normalized = t;
                    if (t.Contains("/", StringComparison.Ordinal) && TryParseSubnet24(t, out byte[] netBytes))
                        normalized = $"{netBytes[0]}.{netBytes[1]}.{netBytes[2]}.0-{netBytes[0]}.{netBytes[1]}.{netBytes[2]}.255";

                    int bucket = FirewallBuckets.IndexFor(t);
                    var list = targetsByBucket[bucket];
                    if (!list.Contains(normalized, StringComparer.OrdinalIgnoreCase))
                        list.Add(normalized);
                }

                // Bypass the "nothing changed" cache periodically so the rules self-heal
                // if something external (GPO refresh, manual netsh/PowerShell edit) drifted
                // them away from what block_list.log says should be blocked.
                bool forceReconcile = DateTime.UtcNow - lastBucketReconcileUtc > BucketReconcileInterval;
                if (forceReconcile)
                    lastBucketReconcileUtc = DateTime.UtcNow;

                for (int bucket = 0; bucket < targetsByBucket.Length; bucket++)
                {
                    string remoteIpList = targetsByBucket[bucket].Count == 0
                        ? "255.255.255.255"
                        : string.Join(",", targetsByBucket[bucket].Distinct(StringComparer.OrdinalIgnoreCase));

                    ApplyFirewallBucket(bucket, remoteIpList, targetsByBucket[bucket].Count, forceReconcile);
                }
            }
            catch (Exception ex)
            {
                WriteLog($"Error updating firewall rule from blocklist: {ex.Message}");
            }
        }

        private readonly string?[] lastAppliedBucketRemoteIp = new string?[FirewallBuckets.Count];
        private DateTime lastBucketReconcileUtc = DateTime.MinValue;
        private static readonly TimeSpan BucketReconcileInterval = TimeSpan.FromMinutes(15);

        private void ApplyFirewallBucket(int bucket, string remoteIpList, int targetCount, bool forceReconcile)
        {
            string ruleName = FirewallBuckets.RuleName(bucket);

            if (!forceReconcile && string.Equals(lastAppliedBucketRemoteIp[bucket], remoteIpList, StringComparison.OrdinalIgnoreCase))
                return; // nothing changed for this bucket since the last successful sync

            try
            {
                bool ruleExists = DoesFirewallRuleExist(ruleName);

                string netshVerb = ruleExists
                    ? $"advfirewall firewall set rule name=\"{ruleName}\" new remoteip=\"{remoteIpList}\""
                    : $"advfirewall firewall add rule name=\"{ruleName}\" dir=in action=block protocol=any remoteip=\"{remoteIpList}\" profile=any enable=yes";

                var psi = new ProcessStartInfo
                {
                    FileName = "netsh.exe",
                    Arguments = netshVerb,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using (var p = Process.Start(psi))
                {
                    if (p == null)
                    {
                        WriteLog($"{ruleName} netsh failed: process start returned null");
                        return;
                    }

                    string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                    p.WaitForExit(15000);
                    if (p.ExitCode == 0 || output.IndexOf("Ok", StringComparison.OrdinalIgnoreCase) >= 0 || output.IndexOf("ОК", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        lastAppliedBucketRemoteIp[bucket] = remoteIpList;
                        WriteLog($"{ruleName} {(ruleExists ? "updated" : "created")}: count={targetCount}, chars={remoteIpList.Length}");
                    }
                    else
                    {
                        WriteLog($"{ruleName} netsh failed (exit {p.ExitCode}, chars={remoteIpList.Length}): {output}");
                    }
                }
            }
            catch (Exception ex)
            {
                WriteLog($"Error updating {ruleName} via netsh: {ex.Message}");
            }
        }

        private bool DoesFirewallRuleExist(string ruleName)
        {
            try
            {
                var checkPsi = new ProcessStartInfo
                {
                    FileName = "netsh.exe",
                    Arguments = $"advfirewall firewall show rule name=\"{ruleName}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using (var p = Process.Start(checkPsi))
                {
                    if (p == null)
                        return false;

                    p.WaitForExit(5000);
                    return p.ExitCode == 0;
                }
            }
            catch
            {
                return false;
            }
        }

        private bool TryParseUntilFromBlockLogLine(string line, out DateTime untilLocal)
        {
            untilLocal = default;
            if (string.IsNullOrWhiteSpace(line))
                return false;

            int idx = line.IndexOf("Until:", StringComparison.OrdinalIgnoreCase);
            if (idx < 0)
                return false;

            string tail = line.Substring(idx + 6).Trim();
            if (tail.Contains("|"))
                tail = tail.Split('|')[0].Trim();

            return DateTime.TryParseExact(
                tail,
                "yyyy-MM-dd HH:mm:ss",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeLocal,
                out untilLocal);
        }

        private bool RunPowerShell(string script)
        {
            string _;
            return RunPowerShell(script, out _);
        }

        private bool RunPowerShell(string script, out string output)
        {
            output = string.Empty;
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{script}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using (var p = Process.Start(psi))
                {
                    if (p == null)
                        return false;

                    output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                    p.WaitForExit(10000);
                    return p.ExitCode == 0;
                }
            }
            catch { return false; }
        }

        private void WriteLog(string message)
        {
            try
            {
                string logPath = Path.Combine(logDirectory, "service.log");
                lock (logLock)
                {
                    string logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}";
                    File.AppendAllText(logPath, logEntry + Environment.NewLine, Encoding.UTF8);
                }
            }
            catch { }
        }

        // Locks the service's data directory down to SYSTEM + Administrators only.
        // Previously this granted Builtin\Users Modify rights on config.json/whiteList.log/
        // block_list.log, which let ANY authenticated local/RDP account (i.e. the exact
        // population this service defends against) rewrite the whitelist, erase active bans,
        // or repoint the Telegram bot/chat to one they control — a full, silent bypass that
        // needed no admin rights. Only SYSTEM (the service) and local Administrators (the
        // monitor GUI, which is meant to be run elevated) should be able to touch this data.
        private void EnsureSecureAcl(string dir)
        {
            try
            {
                var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

                var di = new DirectoryInfo(dir);
                var ds = di.GetAccessControl();

                // Stop inheriting the looser default ProgramData ACL and drop whatever
                // rules (inherited or explicit) currently apply, then set an explicit,
                // minimal ACL.
                ds.SetAccessRuleProtection(true, false);
                foreach (FileSystemAccessRule existingRule in ds.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    try { ds.RemoveAccessRule(existingRule); } catch { }
                }

                ds.AddAccessRule(new FileSystemAccessRule(
                    systemSid,
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));

                ds.AddAccessRule(new FileSystemAccessRule(
                    adminsSid,
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));

                di.SetAccessControl(ds);

                // Files created before this fix shipped may still carry the old, looser ACL
                // directly on them (not just inherited) — re-apply explicitly.
                string[] paths =
                {
                    accessLogPath,
                    blockListLogPath,
                    whitelistPath,
                    configPath,
                    Path.Combine(dir, "service.log"),
                    Path.Combine(dir, "current_log.log"),
                    Path.Combine(dir, "bootstrap.log")
                };

                foreach (var p in paths)
                {
                    try
                    {
                        if (!File.Exists(p))
                            continue;

                        var fi = new FileInfo(p);
                        var fs = fi.GetAccessControl();
                        fs.SetAccessRuleProtection(true, false);
                        foreach (FileSystemAccessRule existingRule in fs.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                        {
                            try { fs.RemoveAccessRule(existingRule); } catch { }
                        }

                        fs.AddAccessRule(new FileSystemAccessRule(systemSid, FileSystemRights.FullControl, AccessControlType.Allow));
                        fs.AddAccessRule(new FileSystemAccessRule(adminsSid, FileSystemRights.FullControl, AccessControlType.Allow));
                        fi.SetAccessControl(fs);
                    }
                    catch { }
                }

                WriteLog("ACL: restricted RDPSecurityService data directory to SYSTEM + Administrators only.");
            }
            catch (Exception ex)
            {
                try { WriteLog("ACL hardening error: " + ex.Message); } catch { }
            }
        }

        private HashSet<string> LoadWhitelistSet()
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (File.Exists(whitelistPath))
            {
                lock (logLock)
                {
                    foreach (string raw in File.ReadAllLines(whitelistPath))
                    {
                        if (string.IsNullOrWhiteSpace(raw))
                            continue;

                        string line = raw.Trim();
                        int i = line.IndexOf("IP:", StringComparison.OrdinalIgnoreCase);
                        if (i >= 0)
                            line = line.Substring(i + 3).Trim();

                        if (System.Net.IPAddress.TryParse(line, out _))
                            set.Add(line);
                    }
                }
            }

            foreach (var ip in GetLocalAutoWhitelistIps())
                set.Add(ip);

            return set;
        }

        private string? ExtractBlockedTargetFromLine(string line)
        {
            if (string.IsNullOrWhiteSpace(line))
                return null;

            int ipIdx = line.IndexOf("BLOCKED IP:", StringComparison.OrdinalIgnoreCase);
            if (ipIdx >= 0)
            {
                string ip = line.Substring(ipIdx + 11).Split('|')[0].Trim();
                return System.Net.IPAddress.TryParse(ip, out _) ? ip : null;
            }

            int netIdx = line.IndexOf("BLOCKED NET:", StringComparison.OrdinalIgnoreCase);
            if (netIdx >= 0)
            {
                string subnet = line.Substring(netIdx + 12).Split('|')[0].Trim();
                return TryParseSubnet24(subnet, out _) ? subnet : null;
            }

            return null;
        }

        private string? ExtractBlockedIpFromLine(string line)
        {
            string? target = ExtractBlockedTargetFromLine(line);
            if (string.IsNullOrWhiteSpace(target) || target.Contains("/", StringComparison.Ordinal))
                return null;

            return target;
        }

        private bool TryParseBlockLogTimestamp(string line, out DateTime timestampLocal)
        {
            timestampLocal = default;
            if (string.IsNullOrWhiteSpace(line))
                return false;

            int open = line.IndexOf('[');
            int close = line.IndexOf(']');
            if (open < 0 || close <= open + 1)
                return false;

            string ts = line.Substring(open + 1, close - open - 1).Trim();
            return DateTime.TryParseExact(
                ts,
                "yyyy-MM-dd HH:mm:ss",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeLocal,
                out timestampLocal);
        }

        private void LoadOrCreateConfig()
        {
            try
            {
                lock (configLock)
                {
                    ServiceConfig? cfg = null;
                    bool shouldRewriteConfig = false;
                    if (File.Exists(configPath))
                    {
                        try
                        {
                            string json = ConfigCrypto.ReadConfigText(configPath);
                            cfg = JsonSerializer.Deserialize<ServiceConfig>(json, ServiceConfigJson.Options);
                        }
                        catch (Exception ex)
                        {
                            WriteLog($"Config parse error: {ex.Message}");
                        }
                    }

                    if (cfg == null)
                    {
                        cfg = ServiceConfig.CreateDefault();
                        shouldRewriteConfig = true;
                        ConfigCrypto.WriteConfigText(configPath, JsonSerializer.Serialize(cfg, ServiceConfigJson.Options));
                    }

                    if (cfg.Telegram == null)
                    {
                        cfg.Telegram = new TelegramConfig { Enabled = false, BotToken = "", ChatId = "" };
                        shouldRewriteConfig = true;
                    }

                    cfg.Telegram.LimitedPhones ??= new List<string>();

                    if (cfg.AntiBrute == null)
                    {
                        cfg.AntiBrute = AntiBruteConfig.CreateDefault();
                        shouldRewriteConfig = true;
                    }

                    if (cfg.AntiBrute?.IpAbuse == null)
                    {
                        cfg.AntiBrute ??= AntiBruteConfig.CreateDefault();
                        cfg.AntiBrute.IpAbuse = IpAbuseConfig.CreateDefault();
                        shouldRewriteConfig = true;
                    }

                    var levels = (cfg.Levels ?? new List<BlockLevel>())
                        .Where(l => l != null && l.Attempts > 0 && l.BlockMinutes > 0)
                        .OrderBy(l => l.Attempts)
                        .Select(l => new BlockLevel { Attempts = l.Attempts, BlockMinutes = l.BlockMinutes })
                        .ToList();

                    if (levels.Count == 0)
                    {
                        levels = ServiceConfig.CreateDefault().Levels;
                        cfg.Levels = levels;
                        shouldRewriteConfig = true;
                    }

                    blockLevels = levels;

                    // For legacy entries without explicit Until, use the smallest configured block duration.
                    failedAttemptsThreshold = levels[0].Attempts;
                    blockMinutes = levels[0].BlockMinutes;

                    int port = cfg.Port.HasValue ? cfg.Port.Value : DEFAULT_RDP_PORT;
                    rdpPort = Math.Max(1, port);

                    int windowDays = cfg.FailedAttemptsWindowDays.HasValue ? cfg.FailedAttemptsWindowDays.Value : 1;
                    failedAttemptsWindowDays = Math.Max(1, windowDays);
                    if (!cfg.FailedAttemptsWindowDays.HasValue || cfg.FailedAttemptsWindowDays.Value != failedAttemptsWindowDays)
                    {
                        cfg.FailedAttemptsWindowDays = failedAttemptsWindowDays;
                        shouldRewriteConfig = true;
                    }

                    // Load Telegram configuration
                    telegramConfig = cfg.Telegram ?? new TelegramConfig { Enabled = false, BotToken = "", ChatId = "" };
                    uiLanguage = string.Equals(cfg.UiLanguage, "EN", StringComparison.OrdinalIgnoreCase) ? "EN" : "UA";
                    if (!string.Equals(cfg.UiLanguage, uiLanguage, StringComparison.OrdinalIgnoreCase))
                    {
                        cfg.UiLanguage = uiLanguage;
                        shouldRewriteConfig = true;
                    }

                    // Load anti-brute configuration
                    antiBruteConfig = NormalizeAntiBruteConfig(cfg.AntiBrute);
                    ipAbuseWindowMinutes = Math.Max(1, antiBruteConfig.IpAbuse.WindowMinutes);
                    ipAbuseDistinctUsersThreshold = Math.Max(2, antiBruteConfig.IpAbuse.DistinctUsersThreshold);

                    if (shouldRewriteConfig)
                        ConfigCrypto.WriteConfigText(configPath, JsonSerializer.Serialize(cfg, ServiceConfigJson.Options));
                }
            }
            catch (Exception ex)
            {
                WriteLog($"Config load error: {ex.Message}");
                failedAttemptsThreshold = DEFAULT_FAILED_ATTEMPTS_THRESHOLD;
                blockMinutes = DEFAULT_BLOCK_MINUTES;
                blockLevels = new List<BlockLevel> { new BlockLevel { Attempts = 3, BlockMinutes = 20 } };
                antiBruteConfig = AntiBruteConfig.CreateDefault();
            }
        }

        private AntiBruteConfig NormalizeAntiBruteConfig(AntiBruteConfig? cfg)
        {
            cfg ??= AntiBruteConfig.CreateDefault();

            cfg.Spray ??= SprayConfig.CreateDefault();
            cfg.Spray.WindowMinutes = Math.Max(1, cfg.Spray.WindowMinutes);
            cfg.Spray.UniqueIpsThreshold = Math.Max(2, cfg.Spray.UniqueIpsThreshold);
            cfg.Spray.BlockMinutes = Math.Max(1, cfg.Spray.BlockMinutes);

            cfg.Recurrence ??= RecurrenceConfig.CreateDefault();
            cfg.Recurrence.LookbackHours = Math.Max(1, cfg.Recurrence.LookbackHours);
            cfg.Recurrence.StepMultiplier = Math.Max(0.0, cfg.Recurrence.StepMultiplier);
            cfg.Recurrence.MaxMultiplier = Math.Max(1.0, cfg.Recurrence.MaxMultiplier);

            cfg.Subnet ??= SubnetConfig.CreateDefault();
            cfg.Subnet.WindowMinutes = Math.Max(1, cfg.Subnet.WindowMinutes);
            cfg.Subnet.UniqueIpsThreshold = Math.Max(2, cfg.Subnet.UniqueIpsThreshold);
            cfg.Subnet.BlockMinutes = Math.Max(1, cfg.Subnet.BlockMinutes);

            cfg.IpAbuse ??= IpAbuseConfig.CreateDefault();
            cfg.IpAbuse.WindowMinutes = Math.Max(1, cfg.IpAbuse.WindowMinutes);
            cfg.IpAbuse.DistinctUsersThreshold = Math.Max(2, cfg.IpAbuse.DistinctUsersThreshold);

            cfg.SubnetUserSpray ??= SubnetUserSprayConfig.CreateDefault();
            cfg.SubnetUserSpray.WindowMinutes = Math.Max(1, cfg.SubnetUserSpray.WindowMinutes);
            cfg.SubnetUserSpray.UniqueIpsInSubnetThreshold = Math.Max(2, cfg.SubnetUserSpray.UniqueIpsInSubnetThreshold);
            cfg.SubnetUserSpray.BlockMinutes = Math.Max(1, cfg.SubnetUserSpray.BlockMinutes);

            return cfg;
        }

        private BlockLevel? GetLevelForAttempts(int attempts)
        {
            if (attempts <= 0)
                return null;

            // Highest level that matches current attempts count (or lower)
            // This way, if we missed some attempts due to polling intervals, we still apply the right (strongest) ban.
            var levels = blockLevels;
            BlockLevel? match = null;
            for (int i = 0; i < levels.Count; i++)
            {
                var l = levels[i];
                if (attempts >= l.Attempts)
                    match = l;
            }
            return match;
        }

        private bool ShouldApplyBan(string ip, int attempts, BlockLevel level, DateTime nowLocal)
        {
            try
            {
                lock (bansLock)
                {
                    if (bans.TryGetValue(ip, out BanState? s))
                    {
                        if (nowLocal <= s.UntilLocal)
                        {
                            // Already banned; only extend if a higher level is reached.
                            return level.Attempts > s.AppliedAttempts;
                        }

                        // expired in-memory state; allow a new ban
                        bans.Remove(ip);
                    }
                }

                // Not banned: apply when we reached the first level or any higher one.
                return true;
            }
            catch
            {
                return true;
            }
        }
    }

    public class ServiceConfig
    {
        [JsonPropertyName("port")]
        public int? Port { get; set; }

        [JsonPropertyName("uiLanguage")]
        public string UiLanguage { get; set; } = "UA";

        [JsonPropertyName("levels")]
        public List<BlockLevel> Levels { get; set; } = new List<BlockLevel>();

        // How many days a single failed-logon attempt "counts" towards the per-IP thresholds
        // in Levels above, before it ages out. A real automated brute-force burst finishes in
        // seconds/minutes, so this doesn't help an attacker; it only stops unrelated typos by
        // different people behind a shared NAT/office IP, spread across days, from adding up
        // into a false-positive lockout of everyone behind that IP.
        [JsonPropertyName("failedAttemptsWindowDays")]
        public int? FailedAttemptsWindowDays { get; set; }

        [JsonPropertyName("telegram")]
        public TelegramConfig? Telegram { get; set; }

        [JsonPropertyName("antiBrute")]
        public AntiBruteConfig? AntiBrute { get; set; }

        public static ServiceConfig CreateDefault()
        {
            return new ServiceConfig
            {
                Port = 3389,
                Levels = new List<BlockLevel>
                {
                    new BlockLevel { Attempts = 3, BlockMinutes = 30 },
                    new BlockLevel { Attempts = 5, BlockMinutes = 180 },
                    new BlockLevel { Attempts = 7, BlockMinutes = 2880 }
                },
                FailedAttemptsWindowDays = 1,
                Telegram = new TelegramConfig
                {
                    Enabled = false,
                    BotToken = "",
                    ChatId = "",
                    MessageTemplates = new Dictionary<string, string>
                    {
                        ["level1"] = "🟡 RDP Alert LEVEL 1\n\nIP: {ip}\nAttempts: {attempts}\nBan: {duration} min",
                        ["level2"] = "🟠 RDP Alert LEVEL 2\n\nIP: {ip}\nAttempts: {attempts}\nBan: {duration} min",
                        ["level3"] = "🔴 RDP Alert LEVEL 3\n\nIP: {ip}\nAttempts: {attempts}\nBan: {duration} min",
                        ["default"] = "🚨 RDP Security Alert\n\nBlocked IP: {ip}\nAttempts: {attempts}\nBan: {duration} min"
                    }
                },
                UiLanguage = "UA",
                AntiBrute = AntiBruteConfig.CreateDefault()
            };
        }
    }

    public class AntiBruteConfig
    {
        [JsonPropertyName("enabled")]
        public bool Enabled { get; set; } = true;

        [JsonPropertyName("spray")]
        public SprayConfig Spray { get; set; } = SprayConfig.CreateDefault();

        [JsonPropertyName("recurrence")]
        public RecurrenceConfig Recurrence { get; set; } = RecurrenceConfig.CreateDefault();

        [JsonPropertyName("subnet")]
        public SubnetConfig Subnet { get; set; } = SubnetConfig.CreateDefault();

        [JsonPropertyName("ipAbuse")]
        public IpAbuseConfig IpAbuse { get; set; } = IpAbuseConfig.CreateDefault();

        [JsonPropertyName("subnetUserSpray")]
        public SubnetUserSprayConfig SubnetUserSpray { get; set; } = SubnetUserSprayConfig.CreateDefault();

        public static AntiBruteConfig CreateDefault()
        {
            return new AntiBruteConfig
            {
                Enabled = true,
                Spray = SprayConfig.CreateDefault(),
                Recurrence = RecurrenceConfig.CreateDefault(),
                Subnet = SubnetConfig.CreateDefault(),
                IpAbuse = IpAbuseConfig.CreateDefault(),
                SubnetUserSpray = SubnetUserSprayConfig.CreateDefault()
            };
        }
    }

    // Same login attacked from several distinct IPs inside one /24 within a short window.
    // Subnet-clustering on top of a repeated login is a much stronger brute-force signal
    // than either fact alone, so this fires on far fewer attempts (default: 2) than the
    // plain cross-internet spray check (SprayConfig, default: 4) — it only bans the specific
    // attacking IPs it saw, not the whole /24 (that escalation stays with SubnetConfig).
    public class SubnetUserSprayConfig
    {
        [JsonPropertyName("enabled")]
        public bool Enabled { get; set; } = true;

        [JsonPropertyName("windowMinutes")]
        public int WindowMinutes { get; set; } = 10;

        [JsonPropertyName("uniqueIpsInSubnetThreshold")]
        public int UniqueIpsInSubnetThreshold { get; set; } = 2;

        [JsonPropertyName("blockMinutes")]
        public int BlockMinutes { get; set; } = 120;

        public static SubnetUserSprayConfig CreateDefault()
        {
            return new SubnetUserSprayConfig
            {
                Enabled = true,
                WindowMinutes = 10,
                UniqueIpsInSubnetThreshold = 2,
                BlockMinutes = 120
            };
        }
    }

    public class IpAbuseConfig
    {
        [JsonPropertyName("windowMinutes")]
        public int WindowMinutes { get; set; } = 10;

        [JsonPropertyName("distinctUsersThreshold")]
        public int DistinctUsersThreshold { get; set; } = 3;

        public static IpAbuseConfig CreateDefault()
        {
            return new IpAbuseConfig
            {
                WindowMinutes = 10,
                DistinctUsersThreshold = 3
            };
        }
    }

    public class SprayConfig
    {
        [JsonPropertyName("enabled")]
        public bool Enabled { get; set; } = true;

        [JsonPropertyName("windowMinutes")]
        public int WindowMinutes { get; set; } = 10;

        [JsonPropertyName("uniqueIpsThreshold")]
        public int UniqueIpsThreshold { get; set; } = 4;

        [JsonPropertyName("blockMinutes")]
        public int BlockMinutes { get; set; } = 240;

        public static SprayConfig CreateDefault()
        {
            return new SprayConfig
            {
                Enabled = true,
                WindowMinutes = 10,
                UniqueIpsThreshold = 4,
                BlockMinutes = 240
            };
        }
    }

    public class RecurrenceConfig
    {
        [JsonPropertyName("enabled")]
        public bool Enabled { get; set; } = true;

        [JsonPropertyName("lookbackHours")]
        public int LookbackHours { get; set; } = 24;

        [JsonPropertyName("stepMultiplier")]
        public double StepMultiplier { get; set; } = 0.5;

        [JsonPropertyName("maxMultiplier")]
        public double MaxMultiplier { get; set; } = 4.0;

        public static RecurrenceConfig CreateDefault()
        {
            return new RecurrenceConfig
            {
                Enabled = true,
                LookbackHours = 24,
                StepMultiplier = 0.5,
                MaxMultiplier = 4.0
            };
        }
    }

    public class SubnetConfig
    {
        [JsonPropertyName("enabled")]
        public bool Enabled { get; set; } = true;

        [JsonPropertyName("windowMinutes")]
        public int WindowMinutes { get; set; } = 30;

        [JsonPropertyName("uniqueIpsThreshold")]
        public int UniqueIpsThreshold { get; set; } = 3;

        [JsonPropertyName("blockMinutes")]
        public int BlockMinutes { get; set; } = 240;

        public static SubnetConfig CreateDefault()
        {
            return new SubnetConfig
            {
                Enabled = true,
                WindowMinutes = 30,
                UniqueIpsThreshold = 3,
                BlockMinutes = 240
            };
        }
    }

    public class TelegramConfig
    {
        [JsonPropertyName("enabled")]
        public bool Enabled { get; set; }

        [JsonPropertyName("botToken")]
        public string BotToken { get; set; } = "";

        [JsonPropertyName("chatId")]
        public string ChatId { get; set; } = "";

        [JsonPropertyName("hereProbeEnabled")]
        public bool HereProbeEnabled { get; set; } = false;

        [JsonPropertyName("hereProbePublicUrl")]
        public string HereProbePublicUrl { get; set; } = "";

        [JsonPropertyName("hereProbeListenPrefix")]
        public string HereProbeListenPrefix { get; set; } = "http://+:18088/";

        [JsonPropertyName("messageTemplates")]
        public Dictionary<string, string> MessageTemplates { get; set; } = new Dictionary<string, string>();

        [JsonPropertyName("limitedPhones")]
        public List<string> LimitedPhones { get; set; } = new List<string>();

        // IP that the "Unblock me" button / /unbanme unblocks. Empty by default (feature
        // disabled) — each deployment sets its own here, this is not meant to ship with a
        // real address baked in.
        [JsonPropertyName("selfUnbanIp")]
        public string SelfUnbanIp { get; set; } = "";
    }

    public class BlockLevel
    {
        [JsonPropertyName("attempts")]
        public int Attempts { get; set; }

        [JsonPropertyName("blockMinutes")]
        public int BlockMinutes { get; set; }
    }

    internal static class ServiceConfigJson
    {
        public static readonly JsonSerializerOptions Options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true
        };
    }


