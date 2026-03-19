namespace CfDnsSync;

public enum DnsRecordType
{
    A,
    CNAME,
    MX,
    TXT,
    SRV
}

public class DnsRecord
{
    public string Name { get; set; } = "";          // Relative to zone, e.g. "api" or "@" for apex
    public DnsRecordType Type { get; set; }
    public string Content { get; set; } = "";        // IP, target hostname, TXT value, etc.
    public int Ttl { get; set; } = 300;
    public int? Priority { get; set; }               // MX / SRV priority
    public int? Weight { get; set; }                 // SRV weight
    public int? Port { get; set; }                   // SRV port
    public string? CloudflareId { get; set; }        // CF record ID (for tracking)
    public bool CfProxied { get; set; }              // Whether CF proxy is enabled

    // For MX: Name = zone apex "@", Content = mail server FQDN, Priority = MX priority
    // For SRV: Name = "_service._proto", Content = target, Priority/Weight/Port set

    /// <summary>
    /// Returns a stable key for deduplication: Type + normalized name + content
    /// </summary>
    public string UniqueKey
    {
        get
        {
            var c = Content?.ToLowerInvariant() ?? "";
            // Normalize TXT: strip surrounding quotes so DC (with quotes) and CF (without) match
            if (Type == DnsRecordType.TXT)
            {
                c = c.Trim();
                if (c.StartsWith('"') && c.EndsWith('"') && c.Length >= 2)
                    c = c[1..^1];
            }
            return $"{Type}|{Name.ToLowerInvariant()}|{c}";
        }
    }

    public override string ToString() =>
        $"[{Type}] {Name} -> {Content}" +
        (Priority.HasValue ? $" (priority={Priority})" : "") +
        (CfProxied ? " [proxied]" : "");
}

public class SyncResult
{
    public DateTime StartedAt { get; set; } = DateTime.UtcNow;
    public DateTime? CompletedAt { get; set; }
    public bool Success { get; set; }
    public bool IsDryRun { get; set; }
    public string? ErrorMessage { get; set; }

    public int RecordsFetched { get; set; }
    public int RecordsFiltered { get; set; }   // excluded by rules
    public int RecordsAdded { get; set; }
    public int RecordsUpdated { get; set; }
    public int RecordsDeleted { get; set; }
    public int RecordsSkipped { get; set; }    // already up to date

    // In dry-run mode: what would have been done
    public int WouldAdd { get; set; }
    public int WouldUpdate { get; set; }
    public int WouldDelete { get; set; }
    public List<string> PlannedChanges { get; set; } = new();

    public List<string> Changes { get; set; } = new();
    public List<string> Warnings { get; set; } = new();

    public TimeSpan? Duration => CompletedAt.HasValue
        ? CompletedAt.Value - StartedAt
        : null;
}
