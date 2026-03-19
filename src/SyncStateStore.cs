using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace CfDnsSync;

public class SyncStateStore
{
    private readonly ILogger<SyncStateStore> _logger;
    private readonly string _stateDir;
    private readonly string _historyFile;
    private readonly object _lock = new();

    private SyncHistory _history;

    public SyncStateStore(ILogger<SyncStateStore> logger, ConfigManager config)
    {
        _logger = logger;
        var baseDir = AppContext.BaseDirectory;
        _stateDir = Path.Combine(baseDir, config.Config.LogDirectory);
        Directory.CreateDirectory(_stateDir);
        _historyFile = Path.Combine(_stateDir, "sync_history.json");
        _history = Load();
    }

    public SyncResult? LastResult => _history.Results.Count > 0
        ? _history.Results[^1]
        : null;

    public IReadOnlyList<SyncResult> RecentResults => _history.Results.AsReadOnly();

    public SyncResult? RunningSync { get; private set; }

    public void MarkStarted(SyncResult result)
    {
        RunningSync = result;
    }

    public void MarkCompleted(SyncResult result)
    {
        result.CompletedAt = DateTime.UtcNow;
        RunningSync = null;

        lock (_lock)
        {
            _history.Results.Add(result);
            // Keep last 500 results
            while (_history.Results.Count > 500)
                _history.Results.RemoveAt(0);

            if (result.Success)
                _history.LastSuccessfulSync = result.CompletedAt;

            Save();
        }

        // Write detailed log entry
        WriteLogEntry(result);
    }

    private void WriteLogEntry(SyncResult result)
    {
        try
        {
            var logFile = Path.Combine(_stateDir,
                $"sync_{result.StartedAt:yyyyMMdd}.log");

            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"[{result.StartedAt:yyyy-MM-dd HH:mm:ss} UTC] Sync started");
            sb.AppendLine($"  Status   : {(result.Success ? "SUCCESS" : "FAILED")}");
            if (!result.Success)
                sb.AppendLine($"  Error    : {result.ErrorMessage}");
            sb.AppendLine($"  Duration : {result.Duration?.TotalSeconds:F1}s");
            sb.AppendLine($"  Fetched  : {result.RecordsFetched} records from Cloudflare");
            sb.AppendLine($"  Filtered : {result.RecordsFiltered} excluded by rules");
            sb.AppendLine($"  Added    : {result.RecordsAdded}");
            sb.AppendLine($"  Updated  : {result.RecordsUpdated}");
            sb.AppendLine($"  Skipped  : {result.RecordsSkipped} (already up-to-date)");

            if (result.Changes.Count > 0)
            {
                sb.AppendLine("  Changes:");
                foreach (var c in result.Changes)
                    sb.AppendLine($"    + {c}");
            }

            if (result.Warnings.Count > 0)
            {
                sb.AppendLine("  Warnings:");
                foreach (var w in result.Warnings)
                    sb.AppendLine($"    ! {w}");
            }

            sb.AppendLine();
            File.AppendAllText(logFile, sb.ToString());

            // Rotate old logs
            var maxAge = TimeSpan.FromDays(30);
            foreach (var f in Directory.GetFiles(_stateDir, "sync_*.log"))
            {
                var fi = new FileInfo(f);
                if (DateTime.UtcNow - fi.LastWriteTimeUtc > maxAge)
                {
                    File.Delete(f);
                    _logger.LogDebug("Deleted old log file: {File}", f);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to write log entry");
        }
    }

    private SyncHistory Load()
    {
        if (!File.Exists(_historyFile))
            return new SyncHistory();
        try
        {
            var json = File.ReadAllText(_historyFile);
            return JsonSerializer.Deserialize<SyncHistory>(json, JsonOpts) ?? new SyncHistory();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not load sync history, starting fresh");
            return new SyncHistory();
        }
    }

    private void Save()
    {
        try
        {
            var json = JsonSerializer.Serialize(_history, JsonOpts);
            File.WriteAllText(_historyFile, json);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not save sync history");
        }
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private class SyncHistory
    {
        public DateTime? LastSuccessfulSync { get; set; }
        public List<SyncResult> Results { get; set; } = new();
    }
}
