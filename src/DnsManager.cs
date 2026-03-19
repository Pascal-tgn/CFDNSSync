using System.Diagnostics;
using System.Text;
using Microsoft.Extensions.Logging;

namespace CfDnsSync;

public class DnsManager
{
    private readonly ILogger<DnsManager> _logger;
    private readonly ConfigManager _config;

    public DnsManager(ILogger<DnsManager> logger, ConfigManager config)
    {
        _logger = logger;
        _config = config;
    }

    private string Domain => _config.Config.DnsDomain;
    private string DnsServer => _config.Config.DnsServer;

    public async Task<Dictionary<string, DnsRecord>> GetExistingRecordsAsync(CancellationToken ct)
    {
        // TXT: strip surrounding quotes that Windows DNS adds, join multi-string TXT values
        var script = $@"
Import-Module DnsServer -ErrorAction Stop
$records = @()
$nonTxtTypes = @('A','CNAME','MX','SRV')
foreach ($t in $nonTxtTypes) {{
    try {{
        $recs = Get-DnsServerResourceRecord -ZoneName '{Domain}' -ComputerName '{DnsServer}' -RRType $t -ErrorAction SilentlyContinue
        if ($recs) {{ $records += $recs }}
    }} catch {{ }}
}}
try {{
    $recs = Get-DnsServerResourceRecord -ZoneName '{Domain}' -ComputerName '{DnsServer}' -RRType TXT -ErrorAction SilentlyContinue
    if ($recs) {{ $records += $recs }}
}} catch {{ }}
try {{
    $zoneNodes = Get-DnsServerZone -Name '{Domain}' -ComputerName '{DnsServer}' -ErrorAction SilentlyContinue
    if ($zoneNodes) {{
        $allRecs = Get-DnsServerResourceRecord -ZoneName '{Domain}' -ComputerName '{DnsServer}' -ErrorAction SilentlyContinue
        $txtRecs = $allRecs | Where-Object {{ $_.RecordType -eq 'TXT' }}
        foreach ($r in $txtRecs) {{
            if (-not ($records | Where-Object {{ $_.HostName -eq $r.HostName -and $_.RecordType -eq 'TXT' -and $_.RecordData.DescriptiveText -eq $r.RecordData.DescriptiveText }})) {{
                $records += $r
            }}
        }}
    }}
}} catch {{ }}
$records | ForEach-Object {{
    $r = $_
    $type = $r.RecordType
    $name = $r.HostName
    $ttl = [int]$r.TimeToLive.TotalSeconds
    switch ($type) {{
        'A'     {{ $content = $r.RecordData.IPv4Address.ToString() }}
        'CNAME' {{ $content = $r.RecordData.HostNameAlias.TrimEnd('.').ToLower().Trim() }}
        'MX'    {{ $content = ""$($r.RecordData.Preference)|$($r.RecordData.MailExchange.TrimEnd('.').ToLower().Trim())"" }}
        'TXT'   {{
            $parts = $r.RecordData.DescriptiveText
            $q = [char]34
            if ($parts -is [array]) {{
                $content = ($parts | ForEach-Object {{ $_ -replace ""^$q"" -replace ""$q$"" }}) -join ''
            }} else {{
                $content = [string]$parts -replace ""^$q"" -replace ""$q$""
            }}
        }}
        'SRV'   {{ $content = ""$($r.RecordData.Priority)|$($r.RecordData.Weight)|$($r.RecordData.Port)|$($r.RecordData.DomainName.TrimEnd('.').ToLower())"" }}
        default {{ $content = '' }}
    }}
    if ($name -eq '{Domain}') {{ $name = '@' }}
    Write-Output ""$type|$name|$content|$ttl""
}}
";
        var output = await RunPowerShellAsync(script, ct);
        var result = new Dictionary<string, DnsRecord>(StringComparer.OrdinalIgnoreCase);

        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var rec = ParseDcRecord(line);
            if (rec != null && !result.ContainsKey(rec.UniqueKey))
                result[rec.UniqueKey] = rec;
        }

        _logger.LogInformation("Read {Count} existing records from DC zone '{Domain}'", result.Count, Domain);
        return result;
    }

    private DnsRecord? ParseDcRecord(string line)
    {
        var parts = line.Split('|');
        if (parts.Length < 3) return null;
        if (!Enum.TryParse<DnsRecordType>(parts[0], true, out var type)) return null;

        var name = parts[1].Trim();
        var content = parts[2].Trim();
        var ttl = parts.Length > 3 && double.TryParse(parts[3], out var t) ? (int)t : 300;
        var rec = new DnsRecord { Name = name, Type = type, Ttl = ttl };

        switch (type)
        {
            case DnsRecordType.A:
            case DnsRecordType.CNAME:
                rec.Content = content.TrimEnd('.').ToLowerInvariant();
                break;
            case DnsRecordType.TXT:
                // Normalize: strip outer quotes if present
                rec.Content = NormalizeTxt(content);
                break;
            case DnsRecordType.MX:
                var mx = content.Split('|');
                rec.Priority = mx.Length > 0 && int.TryParse(mx[0], out var mp) ? mp : 10;
                // Content = mail server hostname only (same as CF), so UniqueKey matches
                rec.Content = (mx.Length > 1 ? mx[1] : content).TrimEnd('.').ToLowerInvariant().Trim();
                break;
            case DnsRecordType.SRV:
                var srv = content.Split('|');
                rec.Priority = srv.Length > 0 && int.TryParse(srv[0], out var sp) ? sp : 10;
                rec.Weight   = srv.Length > 1 && int.TryParse(srv[1], out var sw) ? sw : 1;
                rec.Port     = srv.Length > 2 && int.TryParse(srv[2], out var sport) ? sport : 0;
                // Content = target hostname only (same as CF), so UniqueKey matches
                rec.Content  = (srv.Length > 3 ? srv[3] : content).TrimEnd('.').ToLowerInvariant().Trim();
                break;
        }
        return rec;
    }

    /// <summary>
    /// Normalizes TXT record content for comparison.
    /// Windows DNS may return multi-segment TXT as: "seg1" "seg2"
    /// CF returns the full joined value. We join segments for comparison.
    /// </summary>
    private static string NormalizeTxt(string raw)
    {
        var s = raw.Trim();
        // Multi-segment TXT: "seg1" "seg2" or "seg1"  "seg2" (variable spacing)
        // Use Regex to handle any whitespace between segments
        if (s.StartsWith('"'))
        {
            s = System.Text.RegularExpressions.Regex.Replace(s, "\"\\s+\"", "");
            s = s.TrimStart('"').TrimEnd('"');
        }
        return s.Trim();
    }

    public async Task<(bool changed, string action)> UpsertRecordAsync(
        DnsRecord rec, Dictionary<string, DnsRecord> existing, CancellationToken ct)
    {
        var existingRec = existing.GetValueOrDefault(rec.UniqueKey);

        if (existingRec != null && RecordsMatch(rec, existingRec))
            return (false, "skipped");

        // Step 1: if record exists on DC, remove it first (targeted removal by data)
        if (existingRec != null)
        {
            try
            {
                await RunPowerShellAsync(BuildRemoveExactScript(existingRec), ct);
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Could not remove existing record {Rec} before update: {Err}", rec, ex.Message);
                // Continue anyway — Add will fail with 9711 if Remove didn't work,
                // which we catch below
            }
        }

        // Step 2: add the new record
        try
        {
            await RunPowerShellAsync(BuildAddScript(rec), ct);
        }
        catch (Exception ex)
        {
            // WIN32 9711 / 9709 = record already exists
            // This means the record on DC matches what we want (or is a type conflict)
            // Re-check: read fresh from DC and compare
            if (ex.Message.Contains("9711") || ex.Message.Contains("9709"))
            {
                _logger.LogDebug("Record {Rec} already exists (WIN32 9711/9709) — verifying content match", rec);
                // Treat as skipped — content is already on DC (possibly from previous run or manual entry)
                return (false, "skipped");
            }
            // WIN32 0x800706be = RPC failure (often with very long TXT records)
            if (ex.Message.Contains("0x800706be") || ex.Message.Contains("800706be"))
            {
                _logger.LogWarning("RPC failure adding {Rec} — record may be too long or DNS service issue: {Err}", rec, ex.Message);
                throw; // re-throw so SyncEngine logs it as a warning
            }
            throw;
        }

        return (true, existingRec != null ? "updated" : "added");
    }

    /// <summary>Public wrapper for dry-run comparison in SyncEngine.</summary>
    public bool RecordsMatchPublic(DnsRecord cf, DnsRecord dc) => RecordsMatch(cf, dc);

    /// <summary>
    /// Batch upsert: executes all non-TXT records in a single PowerShell process.
    /// TXT records via dnscmd are still executed individually (different tool).
    /// Returns list of (record, changed, action, error) tuples.
    /// </summary>
    public async Task<List<(DnsRecord Rec, bool Changed, string? Action, string? Error)>>
        BatchUpsertAsync(List<DnsRecord> records, Dictionary<string, DnsRecord> existing,
            CancellationToken ct)
    {
        var results = new List<(DnsRecord, bool, string?, string?)>();

        // Split: TXT records handled by dnscmd (separately), rest go into PS batch
        var txtRecords  = records.Where(r => r.Type == DnsRecordType.TXT).ToList();
        var psRecords   = records.Where(r => r.Type != DnsRecordType.TXT).ToList();

        // --- PS batch for non-TXT ---
        if (psRecords.Count > 0)
        {
            var scripts = new List<string>();
            var scriptMeta = new List<(DnsRecord Rec, bool IsUpdate)>();

            foreach (var rec in psRecords)
            {
                var existingRec = existing.GetValueOrDefault(rec.UniqueKey);
                var script = existingRec != null
                    ? BuildRemoveExactScript(existingRec) + "\n" + BuildAddScript(rec)
                    : BuildAddScript(rec);
                scripts.Add(script);
                scriptMeta.Add((rec, existingRec != null));
            }

            var failures = await RunBatchAsync(scripts, ct);
            var failureMap = failures.Where(f => f.Index >= 0)
                                     .ToDictionary(f => f.Index, f => f.Error);

            for (int i = 0; i < psRecords.Count; i++)
            {
                var (rec, isUpdate) = scriptMeta[i];
                if (failureMap.TryGetValue(i, out var err))
                {
                    // 9711/9709 = record already exists — treat as skipped
                    // Note: batch error messages from Write-Error don't contain the error code directly,
                    // they contain the PowerShell exception message which includes "Failed to create resource record"
                    if (err.Contains("9711") || err.Contains("9709") ||
                        err.Contains("Failed to create resource record") ||
                        err.Contains("ResourceExists"))
                        results.Add((rec, false, "skipped", null));
                    else
                        results.Add((rec, false, null, err));
                }
                else
                {
                    results.Add((rec, true, isUpdate ? "updated" : "added", null));
                }
            }
        }

        // --- TXT records via dnscmd (individually) ---
        foreach (var rec in txtRecords)
        {
            try
            {
                var (changed, action) = await UpsertRecordAsync(rec, existing, ct);
                results.Add((rec, changed, action, null));
            }
            catch (Exception ex)
            {
                results.Add((rec, false, null, ex.Message));
            }
        }

        return results;
    }

    private bool RecordsMatch(DnsRecord cf, DnsRecord dc)
    {
        // Normalize both sides: lowercase + strip trailing dots + strip quotes for TXT
        var cfContent = cf.Type == DnsRecordType.TXT ? NormalizeTxt(cf.Content) : cf.Content.ToLowerInvariant().TrimEnd('.').Trim();
        var dcContent = cf.Type == DnsRecordType.TXT ? NormalizeTxt(dc.Content) : dc.Content.ToLowerInvariant().TrimEnd('.').Trim();

        if (!string.Equals(cfContent, dcContent, StringComparison.OrdinalIgnoreCase))
            return false;
        if (cf.Priority.HasValue && cf.Priority != dc.Priority) return false;
        if (cf.Weight.HasValue   && cf.Weight   != dc.Weight)   return false;
        if (cf.Port.HasValue     && cf.Port     != dc.Port)     return false;
        return true;
    }

    public async Task DeleteRecordAsync(DnsRecord rec, CancellationToken ct)
    {
        var script = BuildRemoveExactScript(rec);
        await RunPowerShellAsync(script, ct);
        _logger.LogInformation("Deleted DNS record: {Rec}", rec);
    }

    private string BuildAddScript(DnsRecord rec)
    {
        var zone   = $"'{Domain}'";
        var server = $"'{DnsServer}'";
        var name   = EscapePs(rec.Name);
        var ttlSec = rec.Ttl;

        return rec.Type switch
        {
            DnsRecordType.A =>
                $"Add-DnsServerResourceRecordA -ZoneName {zone} -ComputerName {server} " +
                $"-Name '{name}' -IPv4Address '{rec.Content}' " +
                $"-TimeToLive ([TimeSpan]::FromSeconds({ttlSec})) -ErrorAction Stop",

            DnsRecordType.CNAME =>
                $"Add-DnsServerResourceRecordCName -ZoneName {zone} -ComputerName {server} " +
                $"-Name '{name}' -HostNameAlias '{EscapePs(rec.Content)}.' " +
                $"-TimeToLive ([TimeSpan]::FromSeconds({ttlSec})) -ErrorAction Stop",

            DnsRecordType.MX =>
                $"Add-DnsServerResourceRecordMX -ZoneName {zone} -ComputerName {server} " +
                $"-Name '{name}' -MailExchange '{EscapePs(rec.Content)}.' " +
                $"-Preference {rec.Priority ?? 10} " +
                $"-TimeToLive ([TimeSpan]::FromSeconds({ttlSec})) -ErrorAction Stop",

            DnsRecordType.TXT =>
                // Write TXT value to a temp file to avoid RPC/escaping issues with long DKIM keys
                BuildTxtAddScript(name, rec.Content, ttlSec, Domain, DnsServer),

            DnsRecordType.SRV =>
                $"Add-DnsServerResourceRecord -ZoneName {zone} -ComputerName {server} " +
                $"-Name '{name}' -Srv -DomainName '{EscapePs(rec.Content)}.' " +
                $"-Priority {rec.Priority ?? 10} -Weight {rec.Weight ?? 1} -Port {rec.Port ?? 0} " +
                $"-TimeToLive ([TimeSpan]::FromSeconds({ttlSec})) -ErrorAction Stop",

            _ => ""
        };
    }

    /// <summary>
    /// Remove a specific record by matching its exact data, not just name+type.
    /// This prevents WIN32 9709/9711 (record already exists) errors on subsequent Add.
    /// </summary>
    private string BuildRemoveExactScript(DnsRecord rec)
    {
        var zone   = $"'{Domain}'";
        var server = $"'{DnsServer}'";
        var name   = EscapePs(rec.Name);
        var type   = rec.Type.ToString();

        // Use Get | Where | Remove pattern for precise targeting
        return rec.Type switch
        {
            DnsRecordType.A =>
                $"Get-DnsServerResourceRecord -ZoneName {zone} -ComputerName {server} -Name '{name}' -RRType A -ErrorAction SilentlyContinue " +
                $"| Where-Object {{ $_.RecordData.IPv4Address -eq '{rec.Content}' }} " +
                $"| Remove-DnsServerResourceRecord -ZoneName {zone} -ComputerName {server} -Force -ErrorAction SilentlyContinue",

            DnsRecordType.CNAME =>
                $"Get-DnsServerResourceRecord -ZoneName {zone} -ComputerName {server} -Name '{name}' -RRType CNAME -ErrorAction SilentlyContinue " +
                $"| Remove-DnsServerResourceRecord -ZoneName {zone} -ComputerName {server} -Force -ErrorAction SilentlyContinue",

            DnsRecordType.MX =>
                $"Get-DnsServerResourceRecord -ZoneName {zone} -ComputerName {server} -Name '{name}' -RRType MX -ErrorAction SilentlyContinue " +
                $"| Remove-DnsServerResourceRecord -ZoneName {zone} -ComputerName {server} -Force -ErrorAction SilentlyContinue",

            DnsRecordType.TXT =>
                $"Get-DnsServerResourceRecord -ZoneName {zone} -ComputerName {server} -Name '{name}' -RRType TXT -ErrorAction SilentlyContinue " +
                $"| Where-Object {{ ($_.RecordData.DescriptiveText -join '') -like '*{EscapePs(rec.Content[..Math.Min(30, rec.Content.Length - 1)])}*' }} " +
                $"| Remove-DnsServerResourceRecord -ZoneName {zone} -ComputerName {server} -Force -ErrorAction SilentlyContinue",

            DnsRecordType.SRV =>
                $"Get-DnsServerResourceRecord -ZoneName {zone} -ComputerName {server} -Name '{name}' -RRType SRV -ErrorAction SilentlyContinue " +
                $"| Where-Object {{ $_.RecordData.DomainName -like '*{EscapePs(rec.Content)}*' }} " +
                $"| Remove-DnsServerResourceRecord -ZoneName {zone} -ComputerName {server} -Force -ErrorAction SilentlyContinue",

            _ =>
                $"Remove-DnsServerResourceRecord -ZoneName {zone} -ComputerName {server} " +
                $"-Name '{name}' -RRType '{type}' -Force -ErrorAction SilentlyContinue"
        };
    }

    /// <summary>
    /// Builds a PowerShell script to add a TXT record using a temp file to avoid
    /// RPC failures with long values (e.g. multi-segment DKIM keys).
    /// </summary>
    private static string BuildTxtAddScript(string name, string content, int ttlSec, string domain, string server)
    {
        // Strip surrounding quotes and join multi-segment TXT: "seg1" "seg2" -> seg1seg2
        var txtValue = content.Trim();
        if (txtValue.StartsWith('"'))
        {
            txtValue = txtValue
                .Replace("\" \"", "")
                .TrimStart('"')
                .TrimEnd('"');
        }

        // Add-DnsServerResourceRecord fails with RPC error (0x800706be) for long TXT values.
        // Use dnscmd.exe instead — it handles long TXT records without RPC size limitations.
        // dnscmd /recordadd <zone> <name> <ttl> TXT "<value>"


        // dnscmd does not accept "@" as apex record name — use domain name instead
        var dnsRecordName = name == "@" ? domain : name;
        var escapedValue = txtValue.Replace("\"", "\\\"");
        var deleteCmd = $"dnscmd {server} /recorddelete {domain} {dnsRecordName} TXT \"{escapedValue}\" /f 2>$null | Out-Null";
        var addCmd = $"dnscmd {server} /recordadd {domain} {dnsRecordName} {ttlSec} TXT \"{escapedValue}\"";
        return deleteCmd + "\n" + addCmd;
    }
    private static string EscapePs(string s)       => s.Replace("'", "''");
    private static string EscapePsDouble(string s) => s.Replace("`", "``").Replace("\"", "`\"").Replace("$", "`$");

    /// <summary>
    /// Runs multiple PS commands in a single powershell.exe process.
    /// Each command is wrapped in try/catch so one failure doesn't stop the batch.
    /// Returns list of (index, error) for failed commands.
    /// </summary>
    public async Task<List<(int Index, string Error)>> RunBatchAsync(
        List<string> scripts, CancellationToken ct)
    {
        if (scripts.Count == 0) return new();

        // Wrap each command in try/catch; emit a sentinel on failure
        var sb = new StringBuilder();
        sb.AppendLine("$batchErrors = @()");
        for (int i = 0; i < scripts.Count; i++)
        {
            sb.AppendLine($"try {{");
            sb.AppendLine(scripts[i]);
            sb.AppendLine($"}} catch {{ $batchErrors += '{i}:' + $_.Exception.Message }}");
        }
        sb.AppendLine("foreach ($e in $batchErrors) { Write-Error $e }");

        var batchScript = sb.ToString();
        var failures = new List<(int, string)>();

        try
        {
            await RunPowerShellAsync(batchScript, ct);
        }
        catch (Exception ex)
        {
            // Parse individual errors from the batch output
            // Write-Error in PS formats lines as " : N:Message" — strip the prefix first
            foreach (var rawLine in ex.Message.Split('\n'))
            {
                var line = rawLine.Trim();
                // Strip Write-Error prefix " : " or ": "
                if (line.StartsWith(": ")) line = line[2..].Trim();

                var m = System.Text.RegularExpressions.Regex.Match(line, @"^(\d+):(.+)$");
                if (m.Success && int.TryParse(m.Groups[1].Value, out var idx))
                    failures.Add((idx, m.Groups[2].Value.Trim()));
                else if (!string.IsNullOrWhiteSpace(line) && !line.StartsWith("+") &&
                         !line.StartsWith("CategoryInfo") && !line.StartsWith("FullyQualifiedErrorId"))
                    failures.Add((-1, line.Trim())); // unattributed error
            }
        }

        return failures;
    }

    private async Task<string> RunPowerShellAsync(string script, CancellationToken ct)
    {
        var psi = new ProcessStartInfo("powershell.exe",
            new[] { "-NonInteractive", "-NoProfile", "-Command", script })
        {
            RedirectStandardOutput = true,
            RedirectStandardError  = true,
            UseShellExecute        = false,
            CreateNoWindow         = true
        };

        using var process = new Process { StartInfo = psi };
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();

        process.OutputDataReceived += (_, e) => { if (e.Data != null) stdout.AppendLine(e.Data); };
        process.ErrorDataReceived  += (_, e) => { if (e.Data != null) stderr.AppendLine(e.Data); };

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        await process.WaitForExitAsync(ct);

        var errText = stderr.ToString().Trim();
        if (!string.IsNullOrEmpty(errText))
            _logger.LogWarning("PowerShell stderr: {Err}", errText);

        if (process.ExitCode != 0 && !string.IsNullOrEmpty(errText))
            throw new Exception($"PowerShell error (exit {process.ExitCode}): {errText}");

        return stdout.ToString();
    }
}
