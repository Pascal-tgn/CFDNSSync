using Microsoft.Extensions.Logging;

namespace CfDnsSync;

public class SyncEngine
{
    private readonly ILogger<SyncEngine> _logger;
    private readonly CloudflareClient _cf;
    private readonly DnsManager _dns;
    private readonly SyncStateStore _state;
    private readonly ConfigManager _config;
    private readonly RecordModeStore _modes;

    // Prevents concurrent sync cycles (e.g. scheduled + manual trigger at the same time)
    private readonly SemaphoreSlim _syncLock = new(1, 1);

    public SyncEngine(
        ILogger<SyncEngine> logger,
        CloudflareClient cf,
        DnsManager dns,
        SyncStateStore state,
        ConfigManager config,
        RecordModeStore modes)
    {
        _logger = logger;
        _cf = cf;
        _dns = dns;
        _state = state;
        _config = config;
        _modes = modes;
    }

    public async Task RunSyncAsync(CancellationToken ct)
    {
        // Prevent concurrent runs — if a sync is already running, skip this request
        if (!await _syncLock.WaitAsync(0, ct))
        {
            _logger.LogInformation("Sync already in progress — skipping concurrent request");
            return;
        }

        var isDryRun = _config.Config.DryRunMode;
        var result = new SyncResult { StartedAt = DateTime.UtcNow, IsDryRun = isDryRun };
        _state.MarkStarted(result);
        _logger.LogInformation("Starting DNS sync cycle (mode: {Mode})",
            isDryRun ? "DRY RUN — no changes will be applied" : "LIVE");

        try
        {
            var cfg = _config.Config;

            // 1. Fetch filtered records from Cloudflare
            var cfRecords = await _cf.FetchFilteredRecordsAsync(ct);
            result.RecordsFetched = cfRecords.Count;

            // Sanity check: if Cloudflare returned 0 records, something is wrong
            // (API error, expired token, wrong Zone ID). Abort to prevent orphan deletion
            // of all CF-managed records from DC.
            if (cfRecords.Count == 0)
            {
                result.Success = false;
                result.ErrorMessage = "Cloudflare returned 0 records — aborting sync to prevent accidental orphan deletion. " +
                    "Check Zone ID, API token, and Cloudflare connectivity.";
                _logger.LogError(result.ErrorMessage);
                return;
            }

            // 2. Read current DC state
            var dcRecords = await _dns.GetExistingRecordsAsync(ct);

            // 3. Reconcile mode store (detect conflicts, mark orphans)
            var conflicts = _modes.Reconcile(cfRecords, dcRecords, cfg.OrphanDeleteAfterCycles, cfg.RecordModesRetentionDays);
            if (conflicts.Count > 0)
            {
                foreach (var c in conflicts)
                    result.Warnings.Add($"Conflict (manual resolution required): {c}");
            }

            // 4. Process CF records — only those that are CF managed
            // Collect records that need changes, then batch-execute in one PS process
            var toUpsert = new List<DnsRecord>();

            foreach (var rec in cfRecords)
            {
                ct.ThrowIfCancellationRequested();
                var ownership = _modes.GetOwnership(rec.UniqueKey);

                if (ownership == RecordOwnership.DcManaged)
                {
                    result.RecordsSkipped++;
                    _logger.LogDebug("DC managed — skipping: {Rec}", rec);
                    continue;
                }
                if (ownership == RecordOwnership.Conflict)
                {
                    result.RecordsSkipped++;
                    _logger.LogDebug("Conflict unresolved — skipping: {Rec}", rec);
                    continue;
                }

                var existingRec = dcRecords.GetValueOrDefault(rec.UniqueKey);
                if (existingRec != null && _dns.RecordsMatchPublic(rec, existingRec))
                {
                    result.RecordsSkipped++;
                    continue;
                }

                if (isDryRun)
                {
                    var wouldAction = existingRec == null ? "add" : "update";
                    var desc = $"[WOULD {wouldAction.ToUpper()}] {rec}";
                    result.PlannedChanges.Add(desc);
                    _logger.LogInformation("Dry-run planned: {Desc}", desc);
                    if (wouldAction == "add") result.WouldAdd++;
                    else result.WouldUpdate++;
                }
                else
                {
                    toUpsert.Add(rec);
                }
            }

            // Execute all upserts in a single batched PS call (non-dry-run only)
            if (toUpsert.Count > 0)
            {
                var upsertResults = await _dns.BatchUpsertAsync(toUpsert, dcRecords, ct);
                foreach (var (rec, changed, action, error) in upsertResults)
                {
                    if (error != null)
                    {
                        result.Warnings.Add($"Failed to upsert {rec}: {error}");
                        _logger.LogWarning("Failed to upsert record: {Rec} — {Err}", rec, error);
                    }
                    else if (changed)
                    {
                        var desc = $"[{action!.ToUpper()}] {rec}";
                        result.Changes.Add(desc);
                        _logger.LogInformation("DNS change: {Desc}", desc);
                        if (action == "added") result.RecordsAdded++;
                        else if (action == "updated") result.RecordsUpdated++;
                    }
                    else
                    {
                        result.RecordsSkipped++;
                    }
                }
            }

            // 5. Handle orphan deletions
            var toDelete = _modes.GetRecordsToDelete(cfg.OrphanDeleteAfterCycles);
            foreach (var orphan in toDelete)
            {
                ct.ThrowIfCancellationRequested();
                var dcRec = dcRecords.GetValueOrDefault(orphan.Key);
                if (dcRec == null)
                {
                    if (!isDryRun) _modes.Remove(orphan.Key);
                    continue;
                }

                if (isDryRun)
                {
                    var desc = $"[WOULD DELETE] {dcRec} (orphaned — absent from CF for {orphan.OrphanCycleCount} cycles)";
                    result.PlannedChanges.Add(desc);
                    result.WouldDelete++;
                    _logger.LogInformation("Dry-run planned: {Desc}", desc);
                    continue;
                }

                try
                {
                    await _dns.DeleteRecordAsync(dcRec, ct);
                    var desc = $"[DELETED] {dcRec} (orphaned — absent from CF for {orphan.OrphanCycleCount} cycles)";
                    result.Changes.Add(desc);
                    result.RecordsDeleted++;
                    _logger.LogInformation("Orphan deleted: {Rec}", dcRec);
                    _modes.Remove(orphan.Key);
                }
                catch (Exception ex)
                {
                    result.Warnings.Add($"Failed to delete orphan {dcRec}: {ex.Message}");
                    _logger.LogWarning(ex, "Failed to delete orphan: {Rec}", dcRec);
                }
            }

            result.Success = true;
            if (isDryRun)
                _logger.LogInformation(
                    "Dry-run done: would +{Add} ~{Upd} -{Del}, skip:{Skip} — no changes applied",
                    result.WouldAdd, result.WouldUpdate, result.WouldDelete, result.RecordsSkipped);
            else
                _logger.LogInformation(
                    "Sync done: +{Added} ~{Updated} -{Deleted} skip:{Skipped} warn:{Warnings}",
                    result.RecordsAdded, result.RecordsUpdated, result.RecordsDeleted,
                    result.RecordsSkipped, result.Warnings.Count);
        }
        catch (OperationCanceledException)
        {
            result.Success = false;
            result.ErrorMessage = "Sync cancelled";
            throw;
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.ErrorMessage = ex.Message;
            _logger.LogError(ex, "Sync failed: {Message}", ex.Message);
        }
        finally
        {
            _state.MarkCompleted(result);
            _syncLock.Release();
        }
    }
}
