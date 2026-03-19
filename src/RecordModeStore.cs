using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace CfDnsSync;

public enum RecordOwnership
{
    /// <summary>Record is managed by Cloudflare and synced to DC. Deleted from DC if removed from CF.</summary>
    CfManaged,
    /// <summary>Record is owned by DC and must never be touched by the sync service.</summary>
    DcManaged,
    /// <summary>Record exists on both sides but ownership not yet decided — requires user action in UI.</summary>
    Conflict
}

public class RecordModeEntry
{
    public string Key { get; set; } = "";                  // Same as DnsRecord.UniqueKey
    public RecordOwnership Ownership { get; set; }
    public DateTime FirstSeen { get; set; } = DateTime.UtcNow;
    public DateTime LastSeen { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// How many consecutive sync cycles the CF-managed record has been absent from Cloudflare.
    /// When this reaches OrphanDeleteAfterCycles the record is removed from DC.
    /// </summary>
    public int OrphanCycleCount { get; set; } = 0;

    /// <summary>True if the record is gone from CF but still on DC (pending deletion).</summary>
    public bool IsOrphan { get; set; } = false;

    /// <summary>The last known content/IP/target from Cloudflare.</summary>
    public string? LastKnownContent { get; set; }
}

/// <summary>
/// Persists and manages per-record ownership decisions (DC managed vs CF managed vs Conflict).
/// Stored in record_modes.json next to the service binary.
/// </summary>
public class RecordModeStore
{
    private readonly ILogger<RecordModeStore> _logger;
    private readonly string _filePath;
    private readonly object _lock = new();
    private Dictionary<string, RecordModeEntry> _modes;

    public RecordModeStore(ILogger<RecordModeStore> logger, ConfigManager config)
    {
        _logger = logger;
        _filePath = Path.Combine(AppContext.BaseDirectory, "record_modes.json");
        _modes = Load();
    }

    // ── Public API ────────────────────────────────────────────────────────────

    public IReadOnlyDictionary<string, RecordModeEntry> All => _modes;

    public RecordModeEntry? Get(string key) =>
        _modes.TryGetValue(key, out var e) ? e : null;

    public RecordOwnership GetOwnership(string key)
    {
        if (_modes.TryGetValue(key, out var e)) return e.Ownership;
        return RecordOwnership.CfManaged; // default for unknown records from CF
    }

    /// <summary>
    /// Called after each sync: reconcile known CF records vs DC records.
    /// Adds new entries, detects conflicts, marks orphans.
    /// </summary>
    public List<string> Reconcile(
        List<DnsRecord> cfRecords,
        Dictionary<string, DnsRecord> dcRecords,
        int orphanDeleteAfterCycles,
        int retentionDays = 90)
    {
        var conflicts = new List<string>();
        var cfKeys = cfRecords.Select(r => r.UniqueKey).ToHashSet();
        var dcKeys = dcRecords.Keys.ToHashSet();
        var now = DateTime.UtcNow;

        lock (_lock)
        {
            // 1. Process CF records
            foreach (var rec in cfRecords)
            {
                var key = rec.UniqueKey;

                if (_modes.TryGetValue(key, out var existing))
                {
                    existing.LastSeen = now;
                    existing.LastKnownContent = rec.Content;
                    existing.IsOrphan = false;
                    existing.OrphanCycleCount = 0;
                }
                else if (dcRecords.ContainsKey(key))
                {
                    var dcRec = dcRecords[key];
                    // Same type + same value → auto CF Managed (record already synced or matches)
                    // Different value → Conflict (requires manual resolution)
                    // Values match AND types match → safe to auto-assign CF Managed
                    var valuesMatch = string.Equals(
                        rec.Content?.Trim().TrimEnd('.'),
                        dcRec.Content?.Trim().TrimEnd('.'),
                        StringComparison.OrdinalIgnoreCase) && rec.Type == dcRec.Type;

                    if (valuesMatch)
                    {
                        _modes[key] = new RecordModeEntry
                        {
                            Key = key,
                            Ownership = RecordOwnership.CfManaged,
                            FirstSeen = now,
                            LastSeen = now,
                            LastKnownContent = rec.Content
                        };
                        _logger.LogInformation("Auto CF Managed (values match): {Key}", key);
                    }
                    else
                    {
                        _modes[key] = new RecordModeEntry
                        {
                            Key = key,
                            Ownership = RecordOwnership.Conflict,
                            FirstSeen = now,
                            LastSeen = now,
                            LastKnownContent = rec.Content
                        };
                        conflicts.Add(key);
                        _logger.LogWarning("Conflict detected for {Key} — CF: '{CfVal}' vs DC: '{DcVal}'",
                            key, rec.Content, dcRec.Content);
                    }
                }
                else
                {
                    // Only on CF — default CF managed
                    _modes[key] = new RecordModeEntry
                    {
                        Key = key,
                        Ownership = RecordOwnership.CfManaged,
                        FirstSeen = now,
                        LastSeen = now,
                        LastKnownContent = rec.Content
                    };
                }
            }

            // 2. Process DC-only records
            foreach (var key in dcKeys)
            {
                if (!cfKeys.Contains(key) && !_modes.ContainsKey(key))
                {
                    _modes[key] = new RecordModeEntry
                    {
                        Key = key,
                        Ownership = RecordOwnership.DcManaged,
                        FirstSeen = now,
                        LastSeen = now
                    };
                }
            }

            // 3. Handle CF-managed records that disappeared from CF
            foreach (var entry in _modes.Values.Where(e =>
                e.Ownership == RecordOwnership.CfManaged && !cfKeys.Contains(e.Key)))
            {
                entry.IsOrphan = true;
                entry.OrphanCycleCount++;
                _logger.LogWarning(
                    "Orphan record {Key}: missing from CF for {Count}/{Max} cycles",
                    entry.Key, entry.OrphanCycleCount, orphanDeleteAfterCycles);
            }

            // Purge stale entries that haven't been seen for more than retentionDays
            if (retentionDays > 0)
            {
                var cutoff = now.AddDays(-retentionDays);
                var staleKeys = _modes.Values
                    .Where(e => e.LastSeen < cutoff)
                    .Select(e => e.Key)
                    .ToList();

                if (staleKeys.Count > 0)
                {
                    foreach (var k in staleKeys)
                        _modes.Remove(k);
                    _logger.LogInformation(
                        "Purged {Count} stale entries from record_modes.json (last seen > {Days} days ago)",
                        staleKeys.Count, retentionDays);
                }
            }

            Save();
        }

        return conflicts;
    }

    /// <summary>
    /// Returns CF-managed records that have been orphaned long enough to be deleted.
    /// </summary>
    public List<RecordModeEntry> GetRecordsToDelete(int orphanDeleteAfterCycles) =>
        _modes.Values
            .Where(e => e.Ownership == RecordOwnership.CfManaged
                     && e.IsOrphan
                     && e.OrphanCycleCount >= orphanDeleteAfterCycles)
            .ToList();

    public void SetOwnership(string key, RecordOwnership ownership)
    {
        lock (_lock)
        {
            if (_modes.TryGetValue(key, out var entry))
            {
                entry.Ownership = ownership;
                if (ownership != RecordOwnership.CfManaged)
                {
                    entry.IsOrphan = false;
                    entry.OrphanCycleCount = 0;
                }
            }
            else
            {
                _modes[key] = new RecordModeEntry
                {
                    Key = key,
                    Ownership = ownership,
                    FirstSeen = DateTime.UtcNow,
                    LastSeen = DateTime.UtcNow
                };
            }
            Save();
        }
    }

    public void Remove(string key)
    {
        lock (_lock)
        {
            _modes.Remove(key);
            Save();
        }
    }

    // ── Persistence ──────────────────────────────────────────────────────────

    private Dictionary<string, RecordModeEntry> Load()
    {
        if (!File.Exists(_filePath))
        {
            // Try backup if main file missing
            var bakPath = _filePath + ".bak";
            if (File.Exists(bakPath))
            {
                _logger.LogWarning("record_modes.json missing, restoring from backup");
                try { File.Copy(bakPath, _filePath); }
                catch { return new(); }
            }
            else return new();
        }

        try
        {
            var json = File.ReadAllText(_filePath);
            var list = JsonSerializer.Deserialize<List<RecordModeEntry>>(json, JsonOpts);
            return list?.ToDictionary(e => e.Key) ?? new();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load record_modes.json — trying backup");
            // Try backup
            var bakPath = _filePath + ".bak";
            if (File.Exists(bakPath))
            {
                try
                {
                    var json = File.ReadAllText(bakPath);
                    var list = JsonSerializer.Deserialize<List<RecordModeEntry>>(json, JsonOpts);
                    if (list != null)
                    {
                        _logger.LogInformation("Restored {Count} entries from record_modes.json.bak", list.Count);
                        return list.ToDictionary(e => e.Key);
                    }
                }
                catch { }
            }
            _logger.LogWarning("Could not restore from backup either, starting fresh");
            return new();
        }
    }

    private void Save()
    {
        try
        {
            var json = JsonSerializer.Serialize(_modes.Values.ToList(), JsonOpts);

            // Atomic write: write to temp file then rename to prevent corruption
            var tmpPath = _filePath + ".tmp";
            File.WriteAllText(tmpPath, json);
            File.Move(tmpPath, _filePath, overwrite: true);

            // Keep one backup (.bak) rotated on each save
            var bakPath = _filePath + ".bak";
            if (File.Exists(_filePath))
            {
                try { File.Copy(_filePath, bakPath, overwrite: true); }
                catch { /* backup is best-effort */ }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to save record_modes.json");
        }
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };
}
