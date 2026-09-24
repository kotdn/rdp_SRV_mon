using System.IO.Compression;
using System.Text.Json;
using System.Text.Json.Serialization;

if (args.Length == 0)
{
    PrintUsage();
    return 2;
}

string zipPath = args[0];
if (!File.Exists(zipPath))
{
    Console.Error.WriteLine($"ERROR: ZIP not found: {zipPath}");
    return 1;
}

try
{
    string json = ReadSupportReportJsonFromZip(zipPath);
    var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
    SupportStatsReport? report = JsonSerializer.Deserialize<SupportStatsReport>(json, options);

    if (report == null)
    {
        Console.Error.WriteLine("ERROR: Failed to parse support-report.json");
        return 1;
    }

    PrintReport(report, zipPath);
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"ERROR: {ex.Message}");
    return 1;
}

static void PrintUsage()
{
    Console.WriteLine("ZipReportReader.exe <path-to-report-zip>");
    Console.WriteLine();
    Console.WriteLine("Example:");
    Console.WriteLine("  ZipReportReader.exe C:\\Reports\\rdp-security-stats-20260419-123000-SRV01.zip");
}

static string ReadSupportReportJsonFromZip(string zipPath)
{
    using ZipArchive archive = ZipFile.OpenRead(zipPath);
    ZipArchiveEntry? entry = archive.GetEntry("support-report.json");
    if (entry == null)
        throw new InvalidDataException("support-report.json not found in ZIP");

    using Stream stream = entry.Open();
    using var reader = new StreamReader(stream);
    return reader.ReadToEnd();
}

static void PrintReport(SupportStatsReport report, string zipPath)
{
    Console.WriteLine("=== RDP Support Report ===");
    Console.WriteLine($"ZIP: {zipPath}");
    Console.WriteLine($"Report ID: {report.ReportId}");
    Console.WriteLine($"Generated: {report.GeneratedLocal}");
    Console.WriteLine($"Machine: {report.MachineName}");
    Console.WriteLine($"User: {report.UserName}");
    Console.WriteLine($"OS: {report.OsVersion}");
    Console.WriteLine($"Monitor Version: {report.MonitorVersion}");
    Console.WriteLine($"Service Status: {report.ServiceStatus}");
    Console.WriteLine();

    Console.WriteLine("Statistics:");
    Console.WriteLine($"- Access attempts total: {report.AccessAttemptsTotal}");
    Console.WriteLine($"- Access attempts last 24h: {report.AccessAttemptsLast24h}");
    Console.WriteLine($"- Active blocked targets: {report.ActiveBlockedTargets}");
    Console.WriteLine($"- Active blocked direct IPs: {report.ActiveBlockedDirectIps}");
    Console.WriteLine($"- Active blocked subnets: {report.ActiveBlockedSubnets}");
    Console.WriteLine($"- Firewall remote target count: {report.FirewallRemoteTargetCount}");
    Console.WriteLine($"- Whitelist entries: {report.WhitelistEntries}");
    Console.WriteLine();

    Console.WriteLine("Top blocked targets:");
    if (report.TopBlockedTargets.Count == 0)
    {
        Console.WriteLine("- (none)");
    }
    else
    {
        foreach (SupportTopBlockedTarget target in report.TopBlockedTargets)
            Console.WriteLine($"- {target.Target}: {target.Hits}");
    }
}

public sealed class SupportStatsReport
{
    [JsonPropertyName("reportId")]
    public string ReportId { get; set; } = string.Empty;

    [JsonPropertyName("generatedLocal")]
    public string GeneratedLocal { get; set; } = string.Empty;

    [JsonPropertyName("machineName")]
    public string MachineName { get; set; } = string.Empty;

    [JsonPropertyName("userName")]
    public string UserName { get; set; } = string.Empty;

    [JsonPropertyName("osVersion")]
    public string OsVersion { get; set; } = string.Empty;

    [JsonPropertyName("monitorVersion")]
    public string MonitorVersion { get; set; } = string.Empty;

    [JsonPropertyName("serviceStatus")]
    public string ServiceStatus { get; set; } = string.Empty;

    [JsonPropertyName("accessAttemptsTotal")]
    public int AccessAttemptsTotal { get; set; }

    [JsonPropertyName("accessAttemptsLast24h")]
    public int AccessAttemptsLast24h { get; set; }

    [JsonPropertyName("activeBlockedTargets")]
    public int ActiveBlockedTargets { get; set; }

    [JsonPropertyName("activeBlockedDirectIps")]
    public int ActiveBlockedDirectIps { get; set; }

    [JsonPropertyName("activeBlockedSubnets")]
    public int ActiveBlockedSubnets { get; set; }

    [JsonPropertyName("firewallRemoteTargetCount")]
    public int FirewallRemoteTargetCount { get; set; }

    [JsonPropertyName("whitelistEntries")]
    public int WhitelistEntries { get; set; }

    [JsonPropertyName("topBlockedTargets")]
    public List<SupportTopBlockedTarget> TopBlockedTargets { get; set; } = new();
}

public sealed class SupportTopBlockedTarget
{
    [JsonPropertyName("target")]
    public string Target { get; set; } = string.Empty;

    [JsonPropertyName("hits")]
    public int Hits { get; set; }
}
