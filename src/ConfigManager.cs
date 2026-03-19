using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace CfDnsSync;

public class AppConfig
{
    public string CloudflareZoneId { get; set; } = "";
    public string DnsDomain { get; set; } = "corp.example.com";
    public string DnsServer { get; set; } = "localhost";
    public int SyncIntervalMinutes { get; set; } = 5;
    public int WebDashboardPort { get; set; } = 8765;
    public string WebDashboardBindAddress { get; set; } = "127.0.0.1";

    // Record types to sync
    public bool SyncARecords { get; set; } = true;
    public bool SyncCnameRecords { get; set; } = true;
    public bool SyncMxRecords { get; set; } = true;
    public bool SyncTxtRecords { get; set; } = true;
    public bool SyncSrvRecords { get; set; } = true;

    // Filtering options
    public bool SkipProxiedARecords { get; set; } = true;
    public bool SkipSslValidationCnames { get; set; } = true;

    // Patterns for CNAME records to INCLUDE (empty = allow all non-SSL-validation)
    public List<string> CnameAllowPatterns { get; set; } = new();

    // Explicit list of record names to never touch on DC (protected from overwrite)
    public List<string> ProtectedRecords { get; set; } = new()
    {
        // AD service records - never overwrite
        "_ldap._tcp",
        "_kerberos._tcp",
        "_kerberos._udp",
        "_kpasswd._tcp",
        "_kpasswd._udp",
        "_gc._tcp",
        "DomainDnsZones",
        "ForestDnsZones",
        "gc._msdcs"
    };

    public string LogDirectory { get; set; } = "logs";
    public int MaxLogAgeDays { get; set; } = 30;

    // Orphan record handling
    /// <summary>
    /// How many consecutive sync cycles a CF-managed record must be absent from CF
    /// before it is deleted from the DC. Default: 3.
    /// </summary>
    public int OrphanDeleteAfterCycles { get; set; } = 3;

    // Web dashboard authentication
    /// <summary>AD group whose members are allowed to access the web dashboard. Default: Domain Admins.</summary>
    public string AllowedAdGroup { get; set; } = "Domain Admins";

    // HTTPS settings
    /// <summary>
    /// Thumbprint of a certificate in LocalMachine\My store to use for HTTPS.
    /// Run on DC: Get-ChildItem Cert:\LocalMachine\My | Select Subject,Thumbprint
    /// If empty, a self-signed certificate is auto-generated on first start.
    /// </summary>
    public string CertificateThumbprint { get; set; } = "";

    /// <summary>CN / SAN for the auto-generated self-signed cert (e.g. dc01.corp.example.com).
    /// Should match the hostname you use to access the dashboard.</summary>
    public string CertificateCn { get; set; } = "";

    /// <summary>
    /// When true, the sync service runs in simulation mode — it computes all changes
    /// that would be made but does not apply any of them to the DC DNS.
    /// Enabled by default to require explicit opt-in before making real DNS changes.
    /// Disable in Settings once you have reviewed the planned changes.
    /// </summary>
    public bool DryRunMode { get; set; } = true;

    /// <summary>
    /// How many days to keep entries in record_modes.json after they were last seen.
    /// Entries not seen for longer than this (both CF and DC managed) will be purged.
    /// Set to 0 to disable cleanup. Default: 90 days.
    /// </summary>
    public int RecordModesRetentionDays { get; set; } = 90;

    /// <summary>
    /// List of record names (relative to zone) that the sync service will never touch.
    /// Useful for records that cannot be synced correctly (e.g. dotted-name TXT records
    /// that Windows DNS returns inconsistently via PowerShell).
    /// Example: ["cf2024-1._domainkey", "6a3npyaamutb6azq3pub7nc6wgfu7j4u._domainkey"]
    /// </summary>
    public List<string> SkippedRecords { get; set; } = new();
}

public class ConfigManager
{
    private readonly ILogger<ConfigManager> _logger;
    private AppConfig _config;
    private readonly string _configPath;

    public ConfigManager(ILogger<ConfigManager> logger)
    {
        _logger = logger;
        var baseDir = AppContext.BaseDirectory;
        _configPath = Path.Combine(baseDir, "config.json");
        _config = LoadOrCreate();
    }

    public AppConfig Config => _config;

    private AppConfig LoadOrCreate()
    {
        if (File.Exists(_configPath))
        {
            try
            {
                var json = File.ReadAllText(_configPath);
                var cfg = JsonSerializer.Deserialize<AppConfig>(json, JsonOptions);
                if (cfg != null)
                {
                    _logger?.LogInformation("Config loaded from {Path}", _configPath);
                    return cfg;
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to parse config.json, using defaults");
            }
        }

        var defaults = new AppConfig();
        Save(defaults);
        return defaults;
    }

    public void Save(AppConfig cfg)
    {
        var json = JsonSerializer.Serialize(cfg, JsonOptions);
        File.WriteAllText(_configPath, json);
        _config = cfg;
        _logger?.LogInformation("Config saved to {Path}", _configPath);
    }

    public void Reload()
    {
        _config = LoadOrCreate();
    }

    public void RunInteractiveSetup()
    {
        Console.WriteLine("=== CfDnsSync Interactive Setup ===");
        Console.WriteLine();

        var cfg = _config;

        Console.Write($"Cloudflare Zone ID [{cfg.CloudflareZoneId}]: ");
        var input = Console.ReadLine()?.Trim();
        if (!string.IsNullOrEmpty(input)) cfg.CloudflareZoneId = input;

        Console.Write($"DNS Domain [{cfg.DnsDomain}]: ");
        input = Console.ReadLine()?.Trim();
        if (!string.IsNullOrEmpty(input)) cfg.DnsDomain = input;

        Console.Write($"DNS Server (hostname or IP of DC) [{cfg.DnsServer}]: ");
        input = Console.ReadLine()?.Trim();
        if (!string.IsNullOrEmpty(input)) cfg.DnsServer = input;

        Console.Write($"Sync interval in minutes [{cfg.SyncIntervalMinutes}]: ");
        input = Console.ReadLine()?.Trim();
        if (!string.IsNullOrEmpty(input) && int.TryParse(input, out var interval))
            cfg.SyncIntervalMinutes = interval;

        Console.Write($"Web dashboard port [{cfg.WebDashboardPort}]: ");
        input = Console.ReadLine()?.Trim();
        if (!string.IsNullOrEmpty(input) && int.TryParse(input, out var port))
            cfg.WebDashboardPort = port;

        Save(cfg);
        Console.WriteLine();
        Console.WriteLine("Setup complete. Config saved.");
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };
}
