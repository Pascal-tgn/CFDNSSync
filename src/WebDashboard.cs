using System.DirectoryServices.AccountManagement;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CfDnsSync;

/// <summary>
/// Embedded HTTPS server with NTLM Windows Authentication.
/// Uses a certificate from the LocalMachine\My store (by thumbprint) or auto-generates a self-signed cert.
/// Only members of the configured AD group can access the dashboard.
/// </summary>
public class WebDashboard : BackgroundService
{
    private readonly ILogger<WebDashboard> _logger;
    private readonly SyncStateStore _state;
    private readonly ConfigManager _config;
    private readonly SyncEngine _engine;
    private readonly RecordModeStore _modes;
    private readonly CloudflareClient _cf;
    private readonly DnsManager _dns;

    private DateTime _lastManualSync = DateTime.MinValue;
    private const int ManualSyncCooldownSeconds = 60;

    public WebDashboard(ILogger<WebDashboard> logger, SyncStateStore state, ConfigManager config,
        SyncEngine engine, RecordModeStore modes, CloudflareClient cf, DnsManager dns)
    {
        _logger = logger; _state = state; _config = config;
        _engine = engine; _modes = modes; _cf = cf; _dns = dns;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var cfg = _config.Config;

        // --- Setup certificate ---
        X509Certificate2? cert = GetOrCreateCertificate(cfg);
        if (cert == null)
        {
            _logger.LogError("Could not obtain a TLS certificate. Web dashboard will not start.");
            return;
        }

        // HttpListener requires https://+:port/ syntax — 0.0.0.0 is not supported
        var prefix = $"https://+:{cfg.WebDashboardPort}/";

        // Verify SSL binding exists — must be registered once manually by an admin.
        // The service cannot do this itself (LocalSystem lacks the required permissions).
        var bindingOk = await CheckSslBindingExistsAsync(cfg.WebDashboardPort, stoppingToken);
        if (!bindingOk)
        {
            _logger.LogError(
                "No SSL certificate binding found for port {Port}. " +
                "Run this command once as Administrator on the DC, then restart the service: " +
                "netsh http add sslcert ipport=0.0.0.0:{Port} certhash={Thumb} " +
                "appid={{00112233-4455-6677-8899-aabbccddeeff}} certstorename=MY",
                cfg.WebDashboardPort, cfg.WebDashboardPort, cert.Thumbprint);
            return;
        }

        var listener = new HttpListener();
        listener.Prefixes.Add(prefix);
        listener.AuthenticationSchemes = AuthenticationSchemes.Ntlm;

        try
        {
            listener.Start();
            _logger.LogInformation("Web dashboard on https://<hostname>:{Port} (HTTPS/NTLM, group: {Group})",
                cfg.WebDashboardPort, cfg.AllowedAdGroup);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start web dashboard on {Prefix}", prefix);
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var ctx = await listener.GetContextAsync().WaitAsync(stoppingToken);
                _ = Task.Run(() => HandleRequestAsync(ctx), stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                if (!stoppingToken.IsCancellationRequested)
                    _logger.LogWarning(ex, "Web dashboard request error");
            }
        }

        listener.Stop();
    }

    // ── Certificate helpers ───────────────────────────────────────────────────

    private X509Certificate2? GetOrCreateCertificate(AppConfig cfg)
    {
        // 1. Try thumbprint from config
        if (!string.IsNullOrWhiteSpace(cfg.CertificateThumbprint))
        {
            // Do NOT use 'using' here — disposing the store disposes the cert's private key,
            // which causes HttpListener to fail with error 50 (The request is not supported).
            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            var certs = store.Certificates.Find(
                X509FindType.FindByThumbprint, cfg.CertificateThumbprint.Replace(" ", ""), false);
            if (certs.Count > 0)
            {
                _logger.LogInformation("Using certificate: {Subject}", certs[0].Subject);
                // Export and re-import with persistent machine key to ensure private key survives
                var storedPfx = certs[0].Export(X509ContentType.Pfx);
                var reloadedCert = new X509Certificate2(storedPfx,
                    (string?)null,
                    X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
                store.Close();
                return reloadedCert;
            }
            store.Close();
            _logger.LogWarning("Certificate with thumbprint {T} not found, falling back to self-signed",
                cfg.CertificateThumbprint);
        }

        // 2. Try to reuse existing self-signed cert we created before
        using var store2 = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store2.Open(OpenFlags.ReadWrite);
        var existing = store2.Certificates.Find(
            X509FindType.FindBySubjectName, "CfDnsSync", false);
        if (existing.Count > 0 && existing[0].NotAfter > DateTime.UtcNow.AddDays(7))
        {
            _logger.LogInformation("Reusing existing self-signed certificate (expires {Exp})",
                existing[0].NotAfter.ToShortDateString());
            return existing[0];
        }

        // 3. Generate new self-signed certificate
        var cn = !string.IsNullOrWhiteSpace(cfg.CertificateCn)
            ? cfg.CertificateCn
            : Environment.MachineName;

        _logger.LogInformation("Generating self-signed certificate for CN={CN}", cn);

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest($"CN={cn}", rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        req.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false)); // TLS Server

        // Add SAN for both CN and machine name
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName(cn);
        if (!cn.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase))
            sanBuilder.AddDnsName(Environment.MachineName);
        req.CertificateExtensions.Add(sanBuilder.Build());

        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(2));

        // Export and re-import with private key marked as exportable into LocalMachine store
        var pfxBytes = cert.Export(X509ContentType.Pfx, "");
        var importedCert = new X509Certificate2(pfxBytes, "",
            X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

        store2.Add(importedCert);
        _logger.LogInformation("Self-signed certificate installed. Thumbprint: {T}", importedCert.Thumbprint);
        _logger.LogWarning("Self-signed cert: browsers will show a security warning. " +
            "To use your domain CA cert, set CertificateThumbprint in config.json.");

        return importedCert;
    }

    /// <summary>
    /// Checks whether an SSL certificate binding already exists in HTTP.sys for the given port.
    /// The binding must be registered once manually by an administrator using:
    /// netsh http add sslcert ipport=0.0.0.0:{port} certhash={thumb} appid={guid} certstorename=MY
    /// </summary>
    private async Task<bool> CheckSslBindingExistsAsync(int port, CancellationToken ct)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("netsh",
                $"http show sslcert ipport=0.0.0.0:{port}")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = new System.Diagnostics.Process { StartInfo = psi };
            var sb = new StringBuilder();
            p.OutputDataReceived += (_, e) => { if (e.Data != null) sb.AppendLine(e.Data); };
            p.Start();
            p.BeginOutputReadLine();
            await p.WaitForExitAsync(ct);
            var output = sb.ToString();
            // "Certificate Hash" appears in output only when a binding exists
            return output.Contains("Certificate Hash", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not check SSL binding, assuming it exists");
            return true; // optimistic — let HttpListener try and fail with a clear error
        }
    }

    // ── Auth ──────────────────────────────────────────────────────────────────

    private bool IsAuthorized(HttpListenerContext ctx)
    {
        try
        {
            var identity = ctx.User?.Identity as WindowsIdentity;
            if (identity == null || !identity.IsAuthenticated) return false;

            var group = _config.Config.AllowedAdGroup;
            var principal = new WindowsPrincipal(identity);
            if (principal.IsInRole(group)) return true;

            try
            {
                using var pctx = new PrincipalContext(ContextType.Domain);
                using var user = UserPrincipal.FindByIdentity(pctx, identity.Name);
                if (user != null)
                {
                    using var grp = GroupPrincipal.FindByIdentity(pctx, group);
                    if (grp != null && user.IsMemberOf(grp)) return true;
                }
            }
            catch { }

            _logger.LogWarning("Access denied: {User} is not in group '{Group}'",
                identity.Name, group);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Auth check failed");
            return false;
        }
    }

    // ── Router ────────────────────────────────────────────────────────────────

    private async Task HandleRequestAsync(HttpListenerContext ctx)
    {
        var path   = ctx.Request.Url?.AbsolutePath ?? "/";
        var method = ctx.Request.HttpMethod;

        try
        {
            if (path == "/favicon.ico") { ctx.Response.StatusCode = 204; ctx.Response.Close(); return; }

            if (!IsAuthorized(ctx))
            {
                ctx.Response.StatusCode = 403;
                await ServeTextAsync(ctx, "403 Forbidden — access restricted to members of " + _config.Config.AllowedAdGroup);
                return;
            }

            switch (path)
            {
                case "/" or "/index.html":
                    await ServeHtmlAsync(ctx, BuildSpaHtml()); break;
                case "/api/status"   when method == "GET":  await ServeJsonAsync(ctx, BuildStatusJson()); break;
                case "/api/history"  when method == "GET":  await ServeJsonAsync(ctx, BuildHistoryJson()); break;
                case "/api/sync"     when method == "POST": await HandleManualSyncAsync(ctx); break;
                case "/api/restart"  when method == "POST": await HandleRestartAsync(ctx); break;
                case "/api/records"  when method == "GET":  await HandleGetRecordsAsync(ctx); break;
                case "/api/records/ownership" when method == "POST": await HandleSetOwnershipAsync(ctx); break;
                case "/api/diff"     when method == "GET":  await HandleGetDiffAsync(ctx); break;
                case "/api/config"   when method == "GET":  await ServeJsonAsync(ctx, BuildConfigJson()); break;
                case "/api/config"   when method == "POST": await HandleSaveConfigAsync(ctx); break;
                default: ctx.Response.StatusCode = 404; ctx.Response.Close(); break;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error handling {Method} {Path}", method, path);
            try { ctx.Response.StatusCode = 500; ctx.Response.Close(); } catch { }
        }
    }

    // ── API handlers ──────────────────────────────────────────────────────────

    private async Task HandleRestartAsync(HttpListenerContext ctx)
    {
        await ServeJsonAsync(ctx, "{\"restarting\":true}");
        _logger.LogInformation("Service restart requested via web dashboard.");
        // Use PowerShell Restart-Service in a detached process.
        // This is safer than "sc stop && sc start" because Restart-Service
        // handles the stop/start atomically and survives the parent process dying.
        _ = Task.Run(async () =>
        {
            await Task.Delay(500); // let HTTP response flush before we die
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName  = "powershell.exe",
                    Arguments = "-NonInteractive -NoProfile -Command \"Restart-Service CfDnsSync\"",
                    UseShellExecute        = false,
                    CreateNoWindow         = true,
                    RedirectStandardOutput = false,
                    RedirectStandardError  = false
                });
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to restart service: {Err}", ex.Message);
            }
        });
    }

    private async Task HandleManualSyncAsync(HttpListenerContext ctx)
    {
        var now = DateTime.UtcNow;
        var secondsSinceLast = (now - _lastManualSync).TotalSeconds;
        if (secondsSinceLast < ManualSyncCooldownSeconds)
        {
            var remaining = (int)(ManualSyncCooldownSeconds - secondsSinceLast);
            ctx.Response.StatusCode = 429;
            await ServeJsonAsync(ctx,
                $"{{\"error\":\"Rate limited. Wait {remaining}s before triggering another manual sync.\"}}");
            return;
        }
        _lastManualSync = now;
        _ = Task.Run(async () =>
        {
            try { await _engine.RunSyncAsync(CancellationToken.None); }
            catch (Exception ex) { _logger.LogWarning(ex, "Manual sync error"); }
        });
        await ServeJsonAsync(ctx, "{\"triggered\":true}");
    }

    private async Task HandleGetRecordsAsync(HttpListenerContext ctx)
    {
        // Fetch live CF and DC data to show in Records tab
        List<DnsRecord> cfRecords = new();
        Dictionary<string, DnsRecord> dcRecords = new();
        try { cfRecords = await _cf.FetchFilteredRecordsAsync(CancellationToken.None); } catch { }
        try { dcRecords = await _dns.GetExistingRecordsAsync(CancellationToken.None); } catch { }

        var cfByKey = cfRecords.ToDictionary(r => r.UniqueKey);

        var allModes = _modes.All;
        var records = allModes.Values.Select(e =>
        {
            var cf = cfByKey.GetValueOrDefault(e.Key);
            var dc = dcRecords.GetValueOrDefault(e.Key);
            return new
            {
                key = e.Key,
                ownership = e.Ownership.ToString(),
                isOrphan = e.IsOrphan,
                orphanCycleCount = e.OrphanCycleCount,
                orphanDeleteAfter = _config.Config.OrphanDeleteAfterCycles,
                lastKnownContent = e.LastKnownContent,
                lastSeen = e.LastSeen,
                // Include live CF and DC data for Conflict display
                cfContent  = cf?.Content,
                cfTtl      = cf?.Ttl,
                cfPriority = cf?.Priority,
                dcContent  = dc?.Content,
                dcTtl      = dc?.Ttl,
                dcPriority = dc?.Priority
            };
        });
        await ServeJsonAsync(ctx, Serialize(records));
    }

    private async Task HandleSetOwnershipAsync(HttpListenerContext ctx)
    {
        using var reader = new StreamReader(ctx.Request.InputStream);
        var body = await reader.ReadToEndAsync();
        var req = JsonSerializer.Deserialize<OwnershipRequest>(body, JsonOpts);
        if (req == null || string.IsNullOrEmpty(req.Key))
        { ctx.Response.StatusCode = 400; await ServeJsonAsync(ctx, "{\"error\":\"Missing key\"}"); return; }
        if (!Enum.TryParse<RecordOwnership>(req.Ownership, true, out var ownership))
        { ctx.Response.StatusCode = 400; await ServeJsonAsync(ctx, "{\"error\":\"Invalid ownership value\"}"); return; }
        _modes.SetOwnership(req.Key, ownership);
        _logger.LogInformation("User set ownership of {Key} to {Ownership}", req.Key, ownership);
        await ServeJsonAsync(ctx, "{\"ok\":true}");
    }

    private async Task HandleGetDiffAsync(HttpListenerContext ctx)
    {
        try
        {
            var cfTask = _cf.FetchFilteredRecordsAsync(CancellationToken.None);
            var dcTask = _dns.GetExistingRecordsAsync(CancellationToken.None);
            await Task.WhenAll(cfTask, dcTask);

            var cfByKey = (await cfTask).ToDictionary(r => r.UniqueKey);
            var dcByKey = await dcTask;
            var allKeys = cfByKey.Keys.Union(dcByKey.Keys).ToHashSet();
            var mode    = _modes.All;

            var diff = allKeys.Select(key =>
            {
                var cf  = cfByKey.GetValueOrDefault(key);
                var dc  = dcByKey.GetValueOrDefault(key);
                var m   = mode.GetValueOrDefault(key);
                string status;
                if (cf != null && dc != null)
                    status = string.Equals(cf.Content, dc.Content, StringComparison.OrdinalIgnoreCase) ? "match" : "mismatch";
                else
                    status = cf != null ? "cf_only" : "dc_only";
                return new
                {
                    key, status,
                    ownership = m?.Ownership.ToString() ?? "unknown",
                    isOrphan  = m?.IsOrphan ?? false,
                    cf = cf == null ? null : (object)new { cf.Name, type = cf.Type.ToString(), cf.Content, cf.Ttl, cf.Priority },
                    dc = dc == null ? null : (object)new { dc.Name, type = dc.Type.ToString(), dc.Content, dc.Ttl, dc.Priority }
                };
            }).OrderBy(d => d.key);

            await ServeJsonAsync(ctx, Serialize(diff));
        }
        catch (Exception ex)
        {
            ctx.Response.StatusCode = 500;
            await ServeJsonAsync(ctx, Serialize(new { error = ex.Message }));
        }
    }

    private async Task HandleSaveConfigAsync(HttpListenerContext ctx)
    {
        try
        {
            using var reader = new StreamReader(ctx.Request.InputStream);
            var body   = await reader.ReadToEndAsync();
            var newCfg = JsonSerializer.Deserialize<AppConfig>(body, JsonOpts)
                         ?? throw new Exception("Invalid config JSON");

            if (string.IsNullOrWhiteSpace(newCfg.CloudflareZoneId)) throw new Exception("CloudflareZoneId is required");
            if (string.IsNullOrWhiteSpace(newCfg.DnsDomain))        throw new Exception("DnsDomain is required");
            if (newCfg.SyncIntervalMinutes < 1 || newCfg.SyncIntervalMinutes > 1440)
                throw new Exception("SyncIntervalMinutes must be 1–1440");
            if (newCfg.WebDashboardPort < 1024 || newCfg.WebDashboardPort > 65535)
                throw new Exception("WebDashboardPort must be 1024–65535");
            if (newCfg.OrphanDeleteAfterCycles < 1)
                throw new Exception("OrphanDeleteAfterCycles must be >= 1");

            _config.Save(newCfg);
            _logger.LogInformation("Config updated via web UI by {User}", ctx.User?.Identity?.Name ?? "unknown");
            await ServeJsonAsync(ctx, "{\"ok\":true,\"message\":\"Config saved. Restart service to apply port/cert/group changes.\"}");
        }
        catch (Exception ex)
        {
            ctx.Response.StatusCode = 400;
            await ServeJsonAsync(ctx, Serialize(new { error = ex.Message }));
        }
    }

    // ── JSON builders ─────────────────────────────────────────────────────────

    private string BuildStatusJson() => Serialize(new
    {
        running    = _state.RunningSync != null,
        isDryRun   = _config.Config.DryRunMode,
        lastSync = _state.LastResult == null ? null : (object)new
        {
            _state.LastResult.StartedAt,
            _state.LastResult.CompletedAt,
            _state.LastResult.Success,
            _state.LastResult.IsDryRun,
            _state.LastResult.ErrorMessage,
            _state.LastResult.RecordsFetched,
            _state.LastResult.RecordsAdded,
            _state.LastResult.RecordsUpdated,
            _state.LastResult.RecordsDeleted,
            _state.LastResult.RecordsSkipped,
            _state.LastResult.WouldAdd,
            _state.LastResult.WouldUpdate,
            _state.LastResult.WouldDelete,
            changes        = _state.LastResult.Changes,
            plannedChanges = _state.LastResult.PlannedChanges,
            warnings       = _state.LastResult.Warnings,
            durationMs     = _state.LastResult.Duration?.TotalMilliseconds
        },
        config = new
        {
            domain             = _config.Config.DnsDomain,
            zoneId             = _config.Config.CloudflareZoneId,
            intervalMinutes    = _config.Config.SyncIntervalMinutes,
            orphanDeleteAfterCycles = _config.Config.OrphanDeleteAfterCycles,
            allowedAdGroup     = _config.Config.AllowedAdGroup
        }
    });

    private string BuildHistoryJson() => Serialize(
        _state.RecentResults.OrderByDescending(r => r.StartedAt).Take(100).Select(r => new
        {
            r.StartedAt, r.Success, r.ErrorMessage,
            added    = r.RecordsAdded,
            updated  = r.RecordsUpdated,
            deleted  = r.RecordsDeleted,
            skipped  = r.RecordsSkipped,
            warnings = r.Warnings.Count,
            changes  = r.Changes,
            durationMs = r.Duration?.TotalMilliseconds
        }));

    private string BuildConfigJson() => Serialize(_config.Config);

    // ── SPA HTML ──────────────────────────────────────────────────────────────

    private string BuildSpaHtml() => """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'><rect width='64' height='64' rx='12' fill='%23F6821F'/><circle cx='32' cy='32' r='18' fill='none' stroke='white' stroke-width='2'/><ellipse cx='32' cy='32' rx='9' ry='18' fill='none' stroke='white' stroke-width='2'/><line x1='14' y1='32' x2='50' y2='32' stroke='white' stroke-width='2'/><line x1='16' y1='22' x2='48' y2='22' stroke='white' stroke-width='1.5'/><line x1='16' y1='42' x2='48' y2='42' stroke='white' stroke-width='1.5'/></svg>">
<title>CfDnsSync</title>
<title>CfDnsSync</title>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg: #0d0f1a; --bg2: #161927; --bg3: #1e2236; --border: #2a2f4a;
  --text: #d4d8f0; --text2: #8890b0; --text3: #555c7a;
  --blue: #6e8fff; --green: #4ecf8a; --red: #e05555;
  --yellow: #f0c060; --orange: #f09060; --purple: #a078f0;
}
html, body { height: 100%; background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; }
button { cursor: pointer; font-family: inherit; }
.app { display: flex; flex-direction: column; height: 100%; }
.header { background: var(--bg2); border-bottom: 1px solid var(--border); padding: 0 20px; display: flex; align-items: center; height: 52px; }
.logo { font-size: 1rem; font-weight: 700; color: var(--blue); margin-right: 28px; }
.logo span { color: var(--text2); font-weight: 400; }
.tabs { display: flex; height: 100%; gap: 2px; }
.tab { padding: 0 18px; height: 100%; display: flex; align-items: center; color: var(--text2); border-bottom: 2px solid transparent; cursor: pointer; font-size: .85rem; transition: all .15s; }
.tab:hover { color: var(--text); }
.tab.active { color: var(--blue); border-bottom-color: var(--blue); }
.header-right { margin-left: auto; display: flex; align-items: center; gap: 10px; }
.status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--text3); }
.status-dot.ok { background: var(--green); }
.status-dot.error { background: var(--red); }
.status-dot.running { background: var(--blue); animation: pulse 1s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
.hdr-label { font-size: .78rem; color: var(--text2); }
.main { flex: 1; overflow-y: auto; padding: 24px; }
.page { display: none; }
.page.active { display: block; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 20px; }
.card { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; }
.card-label { font-size: .72rem; text-transform: uppercase; letter-spacing: .6px; color: var(--text2); margin-bottom: 5px; }
.card-value { font-size: 1.5rem; font-weight: 700; }
.c-blue { color: var(--blue); } .c-green { color: var(--green); } .c-red { color: var(--red); }
.c-yellow { color: var(--yellow); } .c-text { color: var(--text); font-size: 1rem !important; }
.section { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 16px; overflow: visible; }
.section-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px; padding-bottom: 10px; border-bottom: 1px solid var(--border); }
.section-title { font-size: .8rem; font-weight: 600; text-transform: uppercase; letter-spacing: .6px; color: var(--text2); }
.btn { padding: 7px 16px; border-radius: 6px; border: 1px solid var(--border); background: var(--bg3); color: var(--blue); font-size: .82rem; font-weight: 600; transition: all .15s; }
.btn:hover { background: #252840; border-color: var(--blue); }
.btn:active { transform: scale(.97); }
.btn-sm { padding: 4px 10px; font-size: .75rem; }
.btn-green { color: var(--green); border-color: #1e4030; }
.btn-green:hover { background: #1a2e28; border-color: var(--green); }
.changes { list-style: none; font-family: 'Cascadia Code','Consolas',monospace; font-size: .78rem; max-height: 260px; overflow-y: auto; }
.changes li { padding: 3px 8px; border-radius: 3px; margin-bottom: 2px; }
.ch-added { background: #162a1f; color: var(--green); }
.ch-updated { background: #152030; color: var(--blue); }
.ch-deleted { background: #2a1515; color: var(--red); }
.ch-warning { background: #2a2010; color: var(--yellow); }
.ch-none { color: var(--text3); font-style: italic; }
.tbl-wrap { overflow-x: auto; overflow-y: auto; max-height: calc(100vh - 220px); scrollbar-width: none; -ms-overflow-style: none; }
.tbl-wrap::-webkit-scrollbar { display: none; }
.tbl-wrap table thead th { position: sticky; top: 0; z-index: 2; background: var(--bg); box-shadow: 0 1px 0 var(--border); }
table { width: 100%; border-collapse: collapse; font-size: .8rem; }
th { text-align: left; padding: 8px 12px; background: var(--bg); color: var(--text2); font-weight: 500; border-bottom: 1px solid var(--border); }
td { padding: 7px 12px; border-bottom: 1px solid #1a1e30; vertical-align: middle; }
tr:hover td { background: #191c2e; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: .72rem; font-weight: 600; }
.badge-cf { background: #152030; color: var(--blue); }
.badge-dc { background: #1e2a14; color: var(--green); }
.badge-conflict { background: #2e1e08; color: var(--orange); }
.badge-match { background: #152a1a; color: var(--green); }
.badge-mismatch { background: #2a1e10; color: var(--orange); }
.badge-cf-only { background: #152030; color: var(--blue); }
.badge-dc-only { background: #1e2a14; color: var(--green); }
.badge-orphan { background: #2a1515; color: var(--red); }
.toggle-wrap { display: flex; gap: 4px; align-items: center; }
.toggle-btn { padding: 3px 9px; border-radius: 4px; border: 1px solid var(--border); background: transparent; color: var(--text3); font-size: .72rem; transition: all .15s; cursor: pointer; }
.toggle-btn.active-cf { background: #152030; color: var(--blue); border-color: var(--blue); }
.toggle-btn.active-dc { background: #1e2a14; color: var(--green); border-color: var(--green); }
/* Diff column headers */
.th-cf { background: #0e1a28 !important; color: var(--blue) !important; }
.th-dc { background: #0e1e14 !important; color: var(--green) !important; }
.td-cf { background: #0a1018; }
.td-dc { background: #0a140e; }
.td-miss { color: var(--text3); font-style: italic; }
/* Conflict detail rows */
.conflict-detail { background: #1a1208; }
.conflict-detail td { padding: 4px 12px 8px; }
.conflict-side { display: inline-block; padding: 2px 8px; border-radius: 4px; font-family: monospace; font-size: .77rem; margin: 2px 4px 2px 0; }
.cs-cf { background: #152030; color: var(--blue); }
.cs-dc { background: #1e2a14; color: var(--green); }
/* Filter bar */
.filter-bar { display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; align-items: center; }
.filter-input { background: var(--bg); border: 1px solid var(--border); border-radius: 5px; padding: 5px 10px; color: var(--text); font-size: .8rem; }
.filter-select { background: var(--bg); border: 1px solid var(--border); border-radius: 5px; padding: 5px 8px; color: var(--text); font-size: .8rem; }
/* Settings form */
.form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.form-group { display: flex; flex-direction: column; gap: 5px; }
.form-group.full { grid-column: 1 / -1; }
label { font-size: .78rem; color: var(--text2); font-weight: 500; }
input[type=text], input[type=number] { background: var(--bg); border: 1px solid var(--border); border-radius: 5px; padding: 7px 10px; color: var(--text); font-size: .85rem; font-family: inherit; transition: border-color .15s; }
input:focus { outline: none; border-color: var(--blue); }
input.err { border-color: var(--red); }
.field-err { font-size: .73rem; color: var(--red); }
.hint { font-size: .72rem; color: var(--text3); }
.toggle-check { display: flex; align-items: center; gap: 8px; }
.toggle-check input[type=checkbox] { width: 15px; height: 15px; accent-color: var(--blue); }
.save-row { display: flex; align-items: center; gap: 12px; margin-top: 8px; }
.save-msg.ok { color: var(--green); font-size: .8rem; }
.save-msg.err { color: var(--red); font-size: .8rem; }
/* Records table — auto-layout, fits window width, data columns truncate */
#rec-table { table-layout: auto; width: 100%; }
#rec-table td:nth-child(1) { max-width: 180px; }
#rec-table td:nth-child(5), #rec-table td:nth-child(6) { max-width: 1px; width: 20%; }
.rec-val { font-family: 'Cascadia Code','Consolas',monospace; font-size:.77rem; display:block;
           white-space:nowrap; overflow:hidden; text-overflow:ellipsis; cursor:default; }
/* Docs */
.docs { max-width: 860px; }
.docs h1 { font-size: 1.4rem; font-weight: 700; color: var(--text); margin-bottom: 6px; }
.docs h2 { font-size: 1rem; font-weight: 700; color: var(--blue); margin: 28px 0 10px; padding-bottom: 6px; border-bottom: 1px solid var(--border); }
.docs h3 { font-size: .88rem; font-weight: 700; color: var(--text); margin: 18px 0 8px; }
.docs p  { line-height: 1.65; color: var(--text2); margin-bottom: 10px; font-size: .85rem; }
.docs ul, .docs ol { padding-left: 20px; margin-bottom: 10px; }
.docs li { line-height: 1.65; color: var(--text2); font-size: .85rem; margin-bottom: 3px; }
.docs code { background: var(--bg3); border: 1px solid var(--border); border-radius: 3px; padding: 1px 6px; font-family: 'Cascadia Code','Consolas',monospace; font-size: .82rem; color: var(--blue); }
.docs pre { background: var(--bg3); border: 1px solid var(--border); border-radius: 6px; padding: 14px 16px; overflow-x: auto; margin-bottom: 14px; }
.docs pre code { background: none; border: none; padding: 0; font-size: .8rem; color: var(--text); white-space: pre; }
.docs .note { background: #1a2030; border-left: 3px solid var(--blue); border-radius: 0 6px 6px 0; padding: 10px 14px; margin-bottom: 14px; }
.docs .warn { background: #2a1e08; border-left: 3px solid var(--yellow); border-radius: 0 6px 6px 0; padding: 10px 14px; margin-bottom: 14px; }
.docs .warn p, .docs .note p { margin: 0; }
.docs .toc { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 14px 18px; margin-bottom: 24px; display: inline-block; min-width: 240px; }
.docs .toc-title { font-size: .75rem; text-transform: uppercase; letter-spacing: .6px; color: var(--text2); font-weight: 600; margin-bottom: 8px; }
.docs .toc a { display: block; color: var(--text2); font-size: .82rem; padding: 2px 0; text-decoration: none; }
.docs .toc a:hover { color: var(--blue); }
.docs .toc .toc-sub { padding-left: 14px; }
.docs table { font-size: .8rem; margin-bottom: 14px; }
.docs th { background: var(--bg3); }
.docs td { vertical-align: top; }
.docs .step { display: flex; gap: 14px; margin-bottom: 16px; align-items: flex-start; }
.docs .step-num { min-width: 28px; height: 28px; border-radius: 50%; background: var(--blue); color: #fff; font-weight: 700; font-size: .8rem; display: flex; align-items: center; justify-content: center; flex-shrink: 0; margin-top: 1px; }
.docs .step-body { flex: 1; }
.docs .step-body p { margin: 4px 0 0; }
</style>
</head>
<body>
<div class="app">
  <div class="header">
    <div class="logo">CfDnsSync</div>
    <div class="tabs">
      <div class="tab active" data-tab="dashboard">Dashboard</div>
      <div class="tab" data-tab="records">Records</div>
      <div class="tab" data-tab="diff">Diff</div>
      <div class="tab" data-tab="settings">Settings</div>
      <div class="tab" data-tab="docs">Documentation</div>
    </div>
    <div class="header-right">
      <div class="status-dot" id="hdr-dot"></div>
      <span class="hdr-label" id="hdr-label">Loading...</span>
    </div>
  </div>

  <div class="main">

    <!-- DASHBOARD -->
    <div class="page active" id="page-dashboard">
      <!-- Dry-run banner — shown only when dryRunMode=true -->
      <div id="dry-run-banner" style="display:none;background:#7c4a00;border:1px solid #e09000;border-radius:7px;padding:12px 18px;margin-bottom:14px;display:flex;align-items:center;gap:12px">
        <span style="font-size:1.3rem">⚠️</span>
        <div>
          <strong style="color:#ffc04d">DRY RUN MODE — No DNS changes are being applied</strong>
          <div style="font-size:.82rem;color:#e0b060;margin-top:3px">
            Review the planned changes below, then go to <strong>Settings</strong> and uncheck <em>Dry Run Mode</em> to enable real synchronization.
          </div>
        </div>
      </div>
      <div class="cards">
        <div class="card"><div class="card-label">Domain</div><div class="card-value c-text" id="d-domain">-</div></div>
        <div class="card"><div class="card-label">Last Sync</div><div class="card-value c-text" id="d-last-sync" style="font-size:.85rem">-</div></div>
        <div class="card" id="d-card-added"><div class="card-label" id="d-lbl-added">Added</div><div class="card-value c-green" id="d-added">-</div></div>
        <div class="card" id="d-card-updated"><div class="card-label" id="d-lbl-updated">Updated</div><div class="card-value c-blue" id="d-updated">-</div></div>
        <div class="card" id="d-card-deleted"><div class="card-label" id="d-lbl-deleted">Deleted</div><div class="card-value c-red" id="d-deleted">-</div></div>
        <div class="card"><div class="card-label">Warnings</div><div class="card-value c-yellow" id="d-warnings">-</div></div>
      </div>
      <div class="section">
        <div class="section-header">
          <span class="section-title" id="d-changes-title">Last Sync Changes</span>
          <button class="btn" id="sync-btn" onclick="triggerSync()">Sync Now</button>
        </div>
        <ul class="changes" id="d-changes"><li class="ch-none">No data yet</li></ul>
      </div>
      <div class="section">
        <div class="section-header"><span class="section-title">Sync History (last 100)</span></div>
        <div class="tbl-wrap">
          <table>
            <thead><tr><th id="d-history-tz-header">Time</th><th>Status</th><th>Added</th><th>Updated</th><th>Deleted</th><th>Warn</th><th>Duration</th><th>Changes</th></tr></thead>
            <tbody id="d-history"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- RECORDS -->
    <div class="page" id="page-records">
      <div class="section">
        <div class="section-header">
          <span class="section-title">All Records</span>
          <button class="btn btn-sm" onclick="loadRecords()">Refresh</button>
        </div>
        <div class="filter-bar">
          <input class="filter-input" id="rec-search" placeholder="Filter by name..." oninput="renderRecords()">
          <select class="filter-select" id="rec-type" onchange="renderRecords()">
            <option value="">All types</option>
            <option>A</option><option>CNAME</option><option>MX</option><option>TXT</option><option>SRV</option>
          </select>
          <select class="filter-select" id="rec-ownership" onchange="renderRecords()">
            <option value="">All ownership</option>
            <option value="CfManaged">CF Managed</option>
            <option value="DcManaged">DC Managed</option>
            <option value="Conflict">Conflict</option>
          </select>
          <select class="filter-select" id="rec-orphan" onchange="renderRecords()">
            <option value="">All</option>
            <option value="orphan">Orphans only</option>
          </select>
        </div>
        <div class="tbl-wrap">
          <table id="rec-table">
            <thead>
              <tr>
                <th>Name</th><th>Type</th><th>Ownership</th><th>Status</th>
                <th class="th-cf">Cloudflare Data</th><th class="th-dc">DC Data</th>
                <th>Orphan cycles</th><th>Actions</th>
              </tr>
            </thead>
            <tbody id="rec-tbody"><tr><td colspan="8" style="color:var(--text3)">Loading...</td></tr></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- DIFF -->
    <div class="page" id="page-diff">
      <div class="section">
        <div class="section-header">
          <span class="section-title">Live Diff: Cloudflare vs DC</span>
          <button class="btn btn-sm" onclick="loadDiff()">Refresh (live fetch)</button>
        </div>
        <div class="filter-bar">
          <input class="filter-input" id="diff-search" placeholder="Filter by name..." oninput="renderDiff()">
          <select class="filter-select" id="diff-status" onchange="renderDiff()">
            <option value="">All statuses</option>
            <option value="match">Match</option>
            <option value="mismatch">Mismatch</option>
            <option value="cf_only">CF only</option>
            <option value="dc_only">DC only</option>
          </select>
        </div>
        <div id="diff-loading" style="color:var(--text3);padding:12px">Click Refresh to load live diff...</div>
        <div class="tbl-wrap" id="diff-wrap" style="display:none">
          <table>
            <thead>
              <tr>
                <th>Record</th><th>Status</th><th>Ownership</th>
                <th class="th-cf">Cloudflare Data</th>
                <th class="th-dc">DC Data</th>
              </tr>
            </thead>
            <tbody id="diff-tbody"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- SETTINGS -->
    <div class="page" id="page-settings">
      <div class="section">
        <div class="section-header"><span class="section-title">Service Configuration</span></div>
        <form id="cfg-form" onsubmit="saveConfig(event)">
          <div class="form-grid">
            <div class="form-group">
              <label>Cloudflare Zone ID *</label>
              <input type="text" id="cfg-zoneId" required>
              <span class="hint">Cloudflare dashboard -> Overview -> Zone ID (right column)</span>
              <div class="field-err" id="err-zoneId"></div>
            </div>
            <div class="form-group">
              <label>DNS Domain *</label>
              <input type="text" id="cfg-dnsDomain" required>
              <div class="field-err" id="err-dnsDomain"></div>
            </div>
            <div class="form-group">
              <label>DNS Server (DC hostname or IP)</label>
              <input type="text" id="cfg-dnsServer">
            </div>
            <div class="form-group">
              <label>Sync Interval (minutes)</label>
              <input type="number" id="cfg-syncInterval" min="1" max="1440">
              <div class="field-err" id="err-syncInterval"></div>
            </div>
            <div class="form-group">
              <label>Web Dashboard Port</label>
              <input type="number" id="cfg-dashPort" min="1024" max="65535">
              <div class="field-err" id="err-dashPort"></div>
            </div>
            <div class="form-group">
              <label>Web Dashboard Bind Address</label>
              <input type="text" id="cfg-bindAddr">
              <span class="hint">Use 0.0.0.0 for remote access</span>
            </div>
            <div class="form-group">
              <label>Orphan delete after N cycles</label>
              <input type="number" id="cfg-orphanCycles" min="1">
              <span class="hint">CF-managed records missing from CF for this many cycles will be deleted from DC</span>
              <div class="field-err" id="err-orphanCycles"></div>
            </div>
            <div class="form-group">
              <label>Record Mode Retention (days)</label>
              <input type="number" id="cfg-retention" min="0" max="3650">
              <span class="hint">Entries in record_modes.json not seen for this many days will be purged. Set to 0 to disable. Default: 90.</span>
            </div>
            <div class="form-group">
              <label>Allowed AD Group</label>
              <input type="text" id="cfg-adGroup">
              <span class="hint">Group allowed to access this dashboard</span>
            </div>
            <div class="form-group">
              <label>TLS Certificate Thumbprint</label>
              <input type="text" id="cfg-certThumb" placeholder="Leave empty for auto self-signed">
              <span class="hint">Run: Get-ChildItem Cert:\LocalMachine\My | Select Subject,Thumbprint</span>
            </div>
            <div class="form-group">
              <label>Certificate CN / Hostname</label>
              <input type="text" id="cfg-certCn" placeholder="e.g. dc01.corp.example.com">
              <span class="hint">Used for auto-generated self-signed cert SAN</span>
            </div>
            <div class="form-group full">
              <label style="margin-bottom:8px">Record types to sync</label>
              <div style="display:flex;gap:18px;flex-wrap:wrap">
                <label class="toggle-check"><input type="checkbox" id="cfg-syncA"> A records</label>
                <label class="toggle-check"><input type="checkbox" id="cfg-syncCname"> CNAME records</label>
                <label class="toggle-check"><input type="checkbox" id="cfg-syncMx"> MX records</label>
                <label class="toggle-check"><input type="checkbox" id="cfg-syncTxt"> TXT records</label>
                <label class="toggle-check"><input type="checkbox" id="cfg-syncSrv"> SRV records</label>
              </div>
            </div>
            <div class="form-group full">
              <label style="margin-bottom:8px">Filtering options</label>
              <div style="display:flex;gap:18px;flex-wrap:wrap">
                <label class="toggle-check"><input type="checkbox" id="cfg-skipProxied"> Skip CF-proxied A records</label>
                <label class="toggle-check"><input type="checkbox" id="cfg-skipSsl"> Skip SSL validation CNAMEs</label>
              </div>
            </div>
            <div class="form-group full" style="background:rgba(255,160,0,.07);border:1px solid rgba(255,160,0,.3);border-radius:7px;padding:12px 14px">
              <label style="color:#ffc04d;font-weight:600;margin-bottom:8px">⚠️ Sync Mode</label>
              <label class="toggle-check">
                <input type="checkbox" id="cfg-dryRun" onchange="onDryRunChange(this)">
                <span>Dry Run Mode — simulate sync without applying changes to DC DNS</span>
              </label>
              <div style="font-size:.8rem;color:var(--text2);margin-top:6px">
                Enabled by default. Uncheck to allow real DNS changes. Review planned changes in the Dashboard tab first.
              </div>
            </div>
            <div class="form-group full">
              <label>Skipped Records (one per line)</label>
              <textarea id="cfg-skippedRecords" rows="4"
                style="background:var(--bg);border:1px solid var(--border);border-radius:5px;padding:7px 10px;color:var(--text);font-size:.82rem;font-family:'Cascadia Code',monospace;resize:vertical;width:100%"
                placeholder="selector1._domainkey&#10;selector2._domainkey"></textarea>
              <span class="hint">Records the service will never sync (dotted-name TXT records that Windows DNS cannot handle reliably). One name per line, relative to zone (without domain suffix).</span>
            </div>
          </div>
          <div class="save-row" style="margin-top:16px">
            <button type="submit" class="btn btn-green">Save Configuration</button>
            <button type="button" class="btn" style="background:var(--red);color:#fff;margin-left:10px"
              onclick="restartService()" id="restart-btn">Restart Service</button>
            <span id="restart-status" style="margin-left:12px;font-size:.82rem;color:var(--text2)"></span>
            <span class="save-msg" id="cfg-save-msg"></span>
          </div>
          <p style="color:var(--text3);font-size:.75rem;margin-top:8px">
            Port, bind address, cert, and AD group changes require a service restart.
          </p>
        </form>
      </div>
    </div>

    <!-- DOCS -->
    <div class="page" id="page-docs">
      <div class="docs">
        <h1>CfDnsSync — Documentation</h1>
        <p>One-way DNS sync service: pulls public records from Cloudflare and writes them to a Windows Server Active Directory DNS zone.</p>

        <div class="toc">
          <div class="toc-title">Contents</div>
          <a href="#overview">Overview &amp; Architecture</a>
          <a href="#requirements">Requirements</a>
          <a href="#install">Installation</a>
          <div class="toc-sub"><a href="#install-build">1. Build</a></div>
          <div class="toc-sub"><a href="#install-cf-token">2. Cloudflare API Token</a></div>
          <div class="toc-sub"><a href="#install-deploy">3. Deploy to DC</a></div>
          <div class="toc-sub"><a href="#install-cert">4. TLS Certificate</a></div>
          <a href="#config">Configuration Reference</a>
          <a href="#records">Record Ownership</a>
          <a href="#orphans">Orphan Handling</a>
          <a href="#dashboard">Dashboard Guide</a>
          <a href="#cli">CLI Commands</a>
          <a href="#service">Service Management</a>
          <a href="#logs">Logs &amp; Troubleshooting</a>
          <a href="#uninstall">Uninstall</a>
        </div>

        <!-- OVERVIEW -->
        <h2 id="overview">Overview &amp; Architecture</h2>
        <p>CfDnsSync solves a common split-DNS problem: you have an Active Directory domain controller that is authoritative for your internal zone, and a separate Cloudflare zone for external DNS. Records created in Cloudflare are not resolvable from the internal network because the DC does not know about them.</p>
        <p>Direct two-way sync is not an option: it could corrupt AD-integrated DNS zones and expose internal-only records to the public. CfDnsSync takes a one-way approach — it reads from Cloudflare and writes to the DC, never the other way around.</p>
        <pre><code>Cloudflare DNS API ──(read-only)──► CfDnsSync ──(write-only)──► Local DC DNS
                                         │
                               Web Dashboard (HTTPS)
                              https://&lt;DC-hostname&gt;:8765</code></pre>

        <h3>What Gets Synced</h3>
        <table>
          <thead><tr><th>Type</th><th>Rule</th></tr></thead>
          <tbody>
            <tr><td><code>A</code></td><td>Only <code>cf-proxied: false</code> records — real server IPs. Cloudflare Anycast IPs (proxied) are excluded as they are meaningless internally.</td></tr>
            <tr><td><code>CNAME</code></td><td>Functional CNAMEs (autodiscover, enterpriseenrollment, mail services, etc.). SSL validation CNAMEs matching <code>_hex32chars.subdomain</code> are excluded automatically.</td></tr>
            <tr><td><code>MX</code></td><td>All MX records.</td></tr>
            <tr><td><code>TXT</code></td><td>SPF, DKIM, DMARC, and domain verification records.</td></tr>
            <tr><td><code>SRV</code></td><td>Lync / Teams SRV records and others.</td></tr>
            <tr><td><code>NS</code>, <code>SOA</code></td><td>Never synced — would break the AD domain.</td></tr>
          </tbody>
        </table>

        <h3>Protected Records</h3>
        <p>The following record names are hard-protected and will never be modified or deleted by the sync, regardless of what exists in Cloudflare:</p>
        <pre><code>_ldap._tcp, _kerberos._tcp, _kerberos._udp, _kpasswd._tcp, _kpasswd._udp,
_gc._tcp, DomainDnsZones, ForestDnsZones, gc._msdcs</code></pre>
        <p>You can extend this list in Settings under <em>protectedRecords</em>.</p>

        <!-- REQUIREMENTS -->
        <h2 id="requirements">Requirements</h2>
        <ul>
          <li>Windows Server 2022 (Domain Controller with DNS role)</li>
          <li>Domain Admin privileges (for DNS management via PowerShell <code>DnsServer</code> module)</li>
          <li>Cloudflare account with API Token (Zone DNS Read)</li>
          <li>No .NET runtime installation needed on the DC — the binary is self-contained</li>
        </ul>

        <!-- INSTALLATION -->
        <h2 id="install">Installation</h2>

        <h3 id="install-build">Step 1 — Build</h3>
        <p>On any Windows machine with .NET 8 SDK installed:</p>
        <pre><code># Add NuGet source if not already present
dotnet nuget add source https://api.nuget.org/v3/index.json --name nuget.org

# Build self-contained single executable
dotnet publish ".\CfDnsSync.csproj" -c Release -r win-x64 --self-contained true ^
  -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -o ".\publish"</code></pre>
        <p>Output: <code>publish\CfDnsSync.exe</code> (~80 MB, no runtime required on target).</p>

        <h3 id="install-cf-token">Step 2 — Create Cloudflare API Token</h3>
        <div class="step"><div class="step-num">1</div><div class="step-body"><strong>Open Cloudflare Dashboard</strong> → My Profile → API Tokens → Create Token</div></div>
        <div class="step"><div class="step-num">2</div><div class="step-body"><strong>Use Custom Token</strong>. Set permissions: <code>Zone</code> → <code>DNS</code> → <strong>Read</strong>. Zone Resources: Include → Specific zone → your domain.</div></div>
        <div class="step"><div class="step-num">3</div><div class="step-body"><strong>Copy the token</strong> — you will need it during setup. It is shown only once.</div></div>
        <div class="step"><div class="step-num">4</div><div class="step-body"><strong>Find your Zone ID</strong> — it is shown on the Cloudflare dashboard Overview page, in the right column.</div></div>

        <h3 id="install-deploy">Step 3 — Deploy to DC</h3>
        <p>Copy <code>CfDnsSync.exe</code> and <code>Install-CfDnsSync.ps1</code> to the Domain Controller (e.g. <code>C:\Temp\</code>).</p>
        <p>Open <strong>PowerShell as Administrator</strong> on the DC and run:</p>
        <pre><code>cd C:\Temp
.\Install-CfDnsSync.ps1</code></pre>
        <p>The installer will:</p>
        <ul>
          <li>Copy binaries to <code>C:\Services\CfDnsSync\</code></li>
          <li>Register the Windows Service (<code>CfDnsSync</code>) with auto-start and recovery rules</li>
          <li>Run interactive config wizard (Zone ID, domain, sync interval, etc.)</li>
          <li>Encrypt and store your Cloudflare API token (two options):
              <ul style="margin-top:6px">
                <li><strong>Option A — token.txt (recommended for first run):</strong> Place a file named <code>token.txt</code> in <code>C:\Services\CfDnsSync\</code> containing just the API token. On next service start, the token is automatically encrypted with DPAPI and the plaintext file is deleted.</li>
                <li><strong>Option B — interactive:</strong> Run <code>CfDnsSync.exe setup-token</code> from the service account context and enter the token when prompted.</li>
              </ul>
            </li>
        </ul>
        <p>Then start the service:</p>
        <pre><code>Start-Service CfDnsSync</code></pre>
        <p>On first start the service generates a self-signed TLS certificate and registers it with HTTP.sys. Open the dashboard at <code>https://&lt;DC-hostname&gt;:8765</code>.</p>

        <h3 id="install-cert">Step 4 — TLS Certificate (optional)</h3>
        <p>By default the service auto-generates a self-signed certificate valid for 2 years. Browsers will show a security warning, which is acceptable for an admin-only internal tool.</p>
        <p>To use a certificate from the domain CA instead:</p>
        <pre><code># On the DC, request a cert from the domain CA
$cert = Get-Certificate -Template WebServer -DnsName dc01.corp.example.com `
        -CertStoreLocation Cert:\LocalMachine\My

# Copy the thumbprint
$cert.Certificate.Thumbprint</code></pre>
        <p>Paste the thumbprint into <strong>Settings → TLS Certificate Thumbprint</strong> and restart the service. The browser warning will disappear for domain-joined machines.</p>
        <div class="note"><p>The DC already has its own CA. If the WebServer certificate template is not published, ask your PKI admin to enable it, or duplicate and publish a custom template.</p></div>

        <!-- CONFIG -->
        <h2 id="config">Configuration Reference</h2>
        <p>Configuration is stored in <code>config.json</code> next to the executable. It can be edited via the <strong>Settings</strong> tab in the dashboard, or directly in the file (requires service restart for most changes).</p>
        <table>
          <thead><tr><th>Field</th><th>Default</th><th>Description</th></tr></thead>
          <tbody>
            <tr><td><code>cloudflareZoneId</code></td><td><em>required</em></td><td>Your Cloudflare Zone ID (from CF dashboard Overview page)</td></tr>
            <tr><td><code>dnsDomain</code></td><td><code>corp.example.com</code></td><td>The DNS zone name on the DC</td></tr>
            <tr><td><code>dnsServer</code></td><td><code>localhost</code></td><td>Hostname or IP of the DC running DNS. Use <code>localhost</code> when the service runs on the DC itself.</td></tr>
            <tr><td><code>syncIntervalMinutes</code></td><td><code>5</code></td><td>How often to pull from Cloudflare and update DC (1–1440)</td></tr>
            <tr><td><code>webDashboardPort</code></td><td><code>8765</code></td><td>HTTPS port for the dashboard</td></tr>
            <tr><td><code>webDashboardBindAddress</code></td><td><code>0.0.0.0</code></td><td>Listen on all interfaces. Use <code>127.0.0.1</code> to restrict to localhost only.</td></tr>
            <tr><td><code>allowedAdGroup</code></td><td><code>Domain Admins</code></td><td>AD group allowed to access the dashboard (NTLM authentication)</td></tr>
            <tr><td><code>certificateThumbprint</code></td><td><em>empty</em></td><td>Thumbprint of cert in <code>LocalMachine\My</code>. Leave empty for auto self-signed.</td></tr>
            <tr><td><code>certificateCn</code></td><td><em>empty</em></td><td>CN / SAN for the auto-generated cert. Defaults to machine hostname.</td></tr>
            <tr><td><code>orphanDeleteAfterCycles</code></td><td><code>3</code></td><td>CF-managed records absent from Cloudflare for this many cycles will be deleted from DC</td></tr>
            <tr><td><code>recordModesRetentionDays</code></td><td><code>90</code></td><td>Entries in record_modes.json not seen for this many days are purged. Set to 0 to disable.</td></tr>
            <tr><td><code>skipProxiedARecords</code></td><td><code>true</code></td><td>Exclude A records with CF proxy enabled (Anycast IPs)</td></tr>
            <tr><td><code>skipSslValidationCnames</code></td><td><code>true</code></td><td>Exclude SSL validation CNAMEs (<code>_hex32.subdomain</code> pattern)</td></tr>
            <tr><td><code>dryRunMode</code></td><td><code>true</code></td><td><strong>Dry Run Mode.</strong> When true, the service simulates all sync operations without applying any changes to DC DNS. Enabled by default — set to false in Settings once you have reviewed the planned changes.</td></tr>
            <tr><td><code>skippedRecords</code></td><td><code>[]</code></td><td>Record names to skip entirely — never synced, never deleted. Use for dotted-name TXT records (e.g. DKIM selectors like <code>cf2024-1._domainkey</code>) that Windows DNS cannot read back reliably via PowerShell.</td></tr>
            <tr><td><code>protectedRecords</code></td><td><em>AD list</em></td><td>Record names never touched by the sync service</td></tr>
          </tbody>
        </table>

        <!-- RECORD OWNERSHIP -->
        <h2 id="records">Record Ownership (DC Managed vs CF Managed)</h2>
        <p>Every DNS record in the zone is assigned an ownership mode. This controls whether the sync service is allowed to modify or delete it.</p>
        <table>
          <thead><tr><th>Mode</th><th>Behaviour</th></tr></thead>
          <tbody>
            <tr><td><span class="badge badge-cf">CF Managed</span></td><td>Record is owned by Cloudflare. The service keeps it in sync: creates it, updates it when CF changes, and deletes it from DC after the orphan grace period if it disappears from CF.</td></tr>
            <tr><td><span class="badge badge-dc">DC Managed</span></td><td>Record is owned by the DC. The service never touches it — no updates, no deletions. Use this for internal-only records that should not be overwritten.</td></tr>
            <tr><td><span class="badge badge-conflict">Conflict</span></td><td>Record exists on both sides but with <strong>different values or types</strong>. The service skips it until you manually resolve the ownership in the Records tab.</td></tr>
          </tbody>
        </table>
        <h3>Auto-detection logic (runs on each sync cycle)</h3>
        <ul>
          <li>Record only in Cloudflare → automatically <span class="badge badge-cf">CF Managed</span></li>
          <li>Record only on DC → automatically <span class="badge badge-dc">DC Managed</span></li>
          <li>Record on both sides, <strong>same type and same value</strong> → automatically <span class="badge badge-cf">CF Managed</span> (record already in sync)</li>
          <li>Record on both sides, <strong>different type or different value</strong> → flagged as <span class="badge badge-conflict">Conflict</span>, requires manual resolution</li>
        </ul>
        <div class="note"><p>Common conflict cases: a record exists as an A record on the DC but as a CNAME in Cloudflare (e.g. <code>mail</code>, <code>www</code>). In this case, set the record to <span class="badge badge-dc">DC Managed</span> to preserve the DC version, or manually delete the DC record to let CF re-create it as CNAME.</p></div>
        <h3>Changing ownership</h3>
        <p>Go to the <strong>Records</strong> tab, find the record, and click the <strong>CF</strong> or <strong>DC</strong> toggle button. The change takes effect immediately in the next sync cycle.</p>
        <h3>Error handling</h3>
        <h3>Skipped Records</h3>
        <p>Some DNS records cannot be reliably synced due to limitations of the Windows DNS PowerShell module. Specifically, TXT records on nodes with dots in the name (e.g. DKIM selectors like <code>cf2024-1._domainkey</code>) are added successfully via <code>dnscmd</code> but cannot be read back by <code>Get-DnsServerResourceRecord</code>, causing the service to re-add them on every cycle.</p>
        <p>Add such records to <strong>Settings &rarr; Skipped Records</strong> and the service will not attempt to sync them at all. They must be managed manually on the DC.</p>
        <h2 id="dryrun">Dry Run Mode</h2>
        <p>By default, the service starts in <strong>Dry Run Mode</strong>. In this mode, every sync cycle runs the full reconciliation logic — fetching records from Cloudflare, comparing with the DC zone, and computing all required changes — but does not apply any changes to the DNS server.</p>
        <p>The Dashboard shows planned changes marked as <strong>[WOULD ADD]</strong>, <strong>[WOULD UPDATE]</strong>, and <strong>[WOULD DELETE]</strong> with updated stat cards. A yellow banner at the top of the Dashboard indicates that dry run is active.</p>
        <p>Once you are satisfied with the planned changes, go to <strong>Settings</strong>, uncheck <em>Dry Run Mode</em>, and save. The service will immediately start applying real changes from the next sync cycle. A confirmation dialog will appear before disabling dry run to prevent accidental activation.</p>
        <div class="note"><p>If you redeploy the service or reset <code>config.json</code>, it will return to Dry Run Mode automatically. This is intentional — it prevents unintended DNS changes after updates.</p></div>
        <h3>Built-in safeguards</h3>
        <ul>
          <li><strong>Race condition protection:</strong> A semaphore prevents concurrent sync cycles. If a sync is already running, additional requests are dropped.</li>
          <li><strong>Empty response protection:</strong> If Cloudflare returns 0 records, the sync aborts and orphan deletion is skipped — preventing accidental wipe of all CF-managed records.</li>
          <li><strong>Manual sync rate limiting:</strong> Sync Now is rate-limited to once per 60 seconds.</li>
          <li><strong>Atomic state writes:</strong> <code>record_modes.json</code> is written atomically with a <code>.bak</code> backup that auto-restores on corruption.</li>
          <li><strong>CF API retry:</strong> Cloudflare API calls retry up to 3 times with exponential backoff.</li>
          <li><strong>Startup validation:</strong> Zone ID, token existence and permissions are validated before the first sync. Failure stops the worker with a clear Event Log entry.</li>
        </ul>
        <p>The service uses smart error handling when writing to DC DNS:</p>
        <ul>
          <li>If adding a record fails with <code>WIN32 9711</code> or <code>9709</code> (record already exists) — the service treats it as already in sync and skips without logging a warning. This prevents noise from records that are correctly present on DC.</li>
          <li>If adding fails with <code>HRESULT 0x800706be</code> (RPC failure, usually with very long TXT records like DKIM keys) — the error is logged as a warning for investigation.</li>
          <li>All other errors are logged as warnings with full PowerShell output for troubleshooting.</li>
        </ul>

        <!-- ORPHAN HANDLING -->
        <h2 id="orphans">Orphan Record Handling</h2>
        <p>When a CF-managed record disappears from Cloudflare (e.g. it was deleted), the service does not delete it from the DC immediately. Instead it marks it as an <span class="badge badge-orphan">Orphan</span> and increments a cycle counter on every sync.</p>
        <p>Once the counter reaches <code>orphanDeleteAfterCycles</code> (default: 3), the record is deleted from the DC automatically.</p>
        <div class="warn"><p>This grace period protects against accidental deletions from temporary Cloudflare API issues or misconfiguration. If you see an orphan that should be deleted immediately, you can trigger a manual sync or reduce the orphan cycle count in Settings.</p></div>
        <p>Orphans are visible in the <strong>Records</strong> tab with a counter badge showing current cycles / threshold.</p>

        <!-- DASHBOARD GUIDE -->
        <h2 id="dashboard">Dashboard Guide</h2>
        <h3>Dashboard tab</h3>
        <p>Shows real-time sync status, statistics for the last sync cycle (records added/updated/deleted/warnings), full change log, and a table of the last 100 sync runs. The <strong>Sync Now</strong> button triggers an immediate sync cycle outside the normal schedule.</p>
        <h3>Records tab</h3>
        <p>Displays all known DNS records with their current ownership mode and live CF/DC data. Use the filters to narrow by name, type, ownership, or orphan status. Toggle ownership per record using the CF/DC buttons. Conflict records require resolution here before the sync will process them.</p>
        <h3>Diff tab</h3>
        <p>Performs a live fetch from both Cloudflare and the DC and shows a side-by-side comparison. Useful for verifying that a sync cycle completed correctly or for spotting mismatches. Note: this makes a live API call to Cloudflare on every refresh.</p>
        <p>Status badges: <span class="badge badge-match">Match</span> — identical on both sides. <span class="badge badge-mismatch">Mismatch</span> — exists on both but content differs. <span class="badge badge-cf-only">CF only</span> — not yet synced to DC. <span class="badge badge-dc-only">DC only</span> — DC-managed or orphan.</p>
        <h3>Settings tab</h3>
        <p>Edit all configuration fields with validation. Changes are saved immediately to <code>config.json</code>. Fields marked with a restart notice require a service restart to apply.</p>

        <!-- CLI -->
        <h2 id="cli">CLI Commands</h2>
        <p>Run from the install directory (<code>C:\Services\CfDnsSync\</code>) in an elevated PowerShell:</p>
        <table>
          <thead><tr><th>Command</th><th>Description</th></tr></thead>
          <tbody>
            <tr><td><code>CfDnsSync.exe</code></td><td>Normal operation — run as Windows Service</td></tr>
            <tr><td><code>CfDnsSync.exe setup-token</code></td><td>Re-encrypt and save a new Cloudflare API token</td></tr>
            <tr><td><code>CfDnsSync.exe setup-config</code></td><td>Interactive configuration wizard</td></tr>
            <tr><td><code>CfDnsSync.exe sync-now</code></td><td>Run one sync cycle and exit (useful for testing)</td></tr>
          </tbody>
        </table>

        <!-- SERVICE MANAGEMENT -->
        <h2 id="service">Service Management</h2>
        <pre><code># Check status
Get-Service CfDnsSync

# Start / Stop / Restart
Start-Service CfDnsSync
Stop-Service CfDnsSync
Restart-Service CfDnsSync

# View recent Windows Event Log entries
Get-EventLog -LogName Application -Source CfDnsSync -Newest 50

# Check SSL cert registration
netsh http show sslcert ipport=0.0.0.0:8765</code></pre>

        <!-- LOGS -->
        <h2 id="logs">Logs &amp; Troubleshooting</h2>
        <p>Log files are written to <code>C:\Services\CfDnsSync\logs\sync_YYYYMMDD.log</code> and automatically purged after 30 days. Each entry includes timestamps, record-level changes, and any PowerShell errors from the DNS operations.</p>
        <h3>Common issues</h3>
        <table>
          <thead><tr><th>Symptom</th><th>Cause</th><th>Fix</th></tr></thead>
          <tbody>
            <tr><td>Service fails to start, no dashboard</td><td>Port 8765 already in use, or SSL cert registration failed</td><td>Check <code>netsh http show sslcert</code> and <code>netstat -ano | findstr 8765</code></td></tr>
            <tr><td>Browser shows certificate warning</td><td>Self-signed certificate</td><td>Normal for self-signed. To remove: request cert from domain CA and enter thumbprint in Settings.</td></tr>
            <tr><td>Dashboard returns 403</td><td>User not in the configured AD group</td><td>Check <code>allowedAdGroup</code> in Settings. Verify group membership on DC.</td></tr>
            <tr><td>Same record added every cycle</td><td>TXT content mismatch (quoting difference between CF and DC)</td><td>Fixed in v1.1 — update to latest build. Check the Diff tab to confirm values match.</td></tr>
            <tr><td><code>WIN32 9709 / 9711</code> errors</td><td>Record already exists when trying to add</td><td>Fixed in v1.1 — update to latest build. Uses precise Get/Where/Remove before Add.</td></tr>
            <tr><td>Sync shows 0 records fetched</td><td>Invalid Zone ID or API token lacks permissions</td><td>Run <code>CfDnsSync.exe setup-token</code> to re-enter token. Verify Zone ID in Cloudflare dashboard.</td></tr>
            <tr><td>Records not appearing in DC DNS</td><td>Record is DC Managed or Conflict status</td><td>Check Records tab — set to CF Managed if it should be synced.</td></tr>
          </tbody>
        </table>

        <!-- UNINSTALL -->
        <h2 id="uninstall">Uninstall</h2>
        <pre><code># Stop and remove the service
Stop-Service CfDnsSync
sc.exe delete CfDnsSync

# Remove SSL cert binding
netsh http delete sslcert ipport=0.0.0.0:8765

# Remove files
Remove-Item -Recurse "C:\Services\CfDnsSync"</code></pre>
        <div class="note"><p>DNS records that were synced to the DC will remain after uninstall. You can clean them up manually via DNS Manager or by running <code>Remove-DnsServerResourceRecord</code> in PowerShell before uninstalling.</p></div>
      </div>
    </div>

  </div>
</div>

<script>
let statusData = null, recordsData = [], diffData = [];

// Tabs
document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  document.querySelectorAll('.page').forEach(x => x.classList.remove('active'));
  t.classList.add('active');
  document.getElementById('page-' + t.dataset.tab).classList.add('active');
  if (t.dataset.tab === 'records' && !recordsData.length) loadRecords();
  if (t.dataset.tab === 'settings') loadConfig();
}));

// Dashboard
async function loadStatus() {
  const d = await fetch('/api/status').then(r => r.json());
  statusData = d;
  const { lastSync: last, running, config, isDryRun } = d;
  const dot = document.getElementById('hdr-dot'), lbl = document.getElementById('hdr-label');
  if (running) { dot.className = 'status-dot running'; lbl.textContent = 'Syncing...'; }
  else if (!last) { dot.className = 'status-dot'; lbl.textContent = 'No sync yet'; }
  else if (last.success) { dot.className = 'status-dot ok'; lbl.textContent = isDryRun ? 'DRY RUN' : 'OK'; }
  else { dot.className = 'status-dot error'; lbl.textContent = 'Error'; }

  // Dry-run banner
  const banner = document.getElementById('dry-run-banner');
  if (banner) banner.style.display = isDryRun ? 'flex' : 'none';

  if (config) document.getElementById('d-domain').textContent = config.domain || '-';
  if (last) {
    document.getElementById('d-last-sync').textContent = new Date(last.startedAt).toLocaleString();

    // Adapt stat cards for dry-run vs live
    const dryRun = last.isDryRun;
    document.getElementById('d-lbl-added').textContent   = dryRun ? 'Would Add'    : 'Added';
    document.getElementById('d-lbl-updated').textContent = dryRun ? 'Would Update' : 'Updated';
    document.getElementById('d-lbl-deleted').textContent = dryRun ? 'Would Delete' : 'Deleted';
    document.getElementById('d-added').textContent   = dryRun ? (last.wouldAdd    ?? 0) : (last.recordsAdded   ?? 0);
    document.getElementById('d-updated').textContent = dryRun ? (last.wouldUpdate ?? 0) : (last.recordsUpdated ?? 0);
    document.getElementById('d-deleted').textContent = dryRun ? (last.wouldDelete ?? 0) : (last.recordsDeleted ?? 0);
    document.getElementById('d-warnings').textContent = last.warnings?.length ?? 0;

    // Changes / planned changes list
    document.getElementById('d-changes-title').textContent = dryRun ? 'Planned Changes (Dry Run)' : 'Last Sync Changes';
    const ul = document.getElementById('d-changes');
    ul.innerHTML = '';
    const ch = dryRun ? (last.plannedChanges ?? []) : (last.changes ?? []);
    const wa = last.warnings ?? [];
    if (!ch.length && !wa.length) {
      ul.innerHTML = dryRun
        ? '<li class="ch-none">No changes would be made — zone is already in sync</li>'
        : '<li class="ch-none">No changes in last sync</li>';
      return;
    }
    ch.forEach(c => {
      const li = document.createElement('li');
      if (c.startsWith('[WOULD ADD]'))    li.className = 'ch-added';
      else if (c.startsWith('[WOULD DELETE]')) li.className = 'ch-deleted';
      else if (c.startsWith('[WOULD UPDATE]')) li.className = 'ch-updated';
      else if (c.startsWith('[ADDED]'))    li.className = 'ch-added';
      else if (c.startsWith('[DELETED]')) li.className = 'ch-deleted';
      else li.className = 'ch-updated';
      li.textContent = c; ul.appendChild(li);
    });
    wa.forEach(w => { const li = document.createElement('li'); li.className = 'ch-warning'; li.textContent = 'Warning: ' + w; ul.appendChild(li); });
  }
}

async function loadHistory() {
  const rows = await fetch('/api/history').then(r => r.json());
  const tbody = document.getElementById('d-history');
  tbody.innerHTML = '';
  // Set timezone abbreviation in header
  const tzHdr = document.getElementById('d-history-tz-header');
  if (tzHdr) {
    const tzAbbr = new Intl.DateTimeFormat('en', { timeZoneName: 'short' })
      .formatToParts(new Date()).find(p => p.type === 'timeZoneName')?.value || 'Local';
    tzHdr.textContent = `Time (${tzAbbr})`;
  }
  if (!rows.length) { tbody.innerHTML = '<tr><td colspan="8" style="color:var(--text3)">No history yet</td></tr>'; return; }
  rows.forEach(row => {
    const tr = document.createElement('tr');
    const dur = row.durationMs ? (row.durationMs/1000).toFixed(1)+'s' : '-';
    const st  = row.success ? '<span style="color:var(--green)">OK</span>'
                            : '<span style="color:var(--red)">' + esc(row.errorMessage || 'Error') + '</span>';
    const chBtn = row.changes?.length ? `<button class="btn btn-sm" onclick="showChanges(${JSON.stringify(row.changes)})">View</button>` : '-';
    tr.innerHTML = `<td>${new Date(row.startedAt).toLocaleString()}</td><td>${st}</td>
      <td style="color:var(--green)">${row.added}</td><td style="color:var(--blue)">${row.updated}</td>
      <td style="color:var(--red)">${row.deleted}</td><td style="color:var(--yellow)">${row.warnings}</td>
      <td>${dur}</td><td>${chBtn}</td>`;
    tbody.appendChild(tr);
  });
}

async function triggerSync() {
  const btn = document.getElementById('sync-btn');
  btn.disabled = true; btn.textContent = 'Running...';
  await fetch('/api/sync', { method: 'POST' });
  setTimeout(async () => { await refresh(); btn.disabled = false; btn.textContent = 'Sync Now'; }, 800);
}

// Records
async function loadRecords() {
  document.getElementById('rec-tbody').innerHTML = '<tr><td colspan="8" style="color:var(--text3)">Loading live data...</td></tr>';
  recordsData = await fetch('/api/records').then(r => r.json());
  renderRecords();
}

function renderRecords() {
  const search = document.getElementById('rec-search').value.toLowerCase();
  const typeF  = document.getElementById('rec-type').value;
  const ownF   = document.getElementById('rec-ownership').value;
  const orphF  = document.getElementById('rec-orphan').value;

  const filtered = recordsData.filter(rec => {
    if (search && !rec.key.toLowerCase().includes(search)) return false;
    if (typeF  && !rec.key.toUpperCase().startsWith(typeF + '|')) return false;
    if (ownF   && rec.ownership !== ownF) return false;
    if (orphF === 'orphan' && !rec.isOrphan) return false;
    return true;
  });

  const tbody = document.getElementById('rec-tbody');
  tbody.innerHTML = '';
  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="8" style="color:var(--text3)">No records match</td></tr>'; return;
  }

  filtered.forEach(rec => {
    const parts = rec.key.split('|');
    const type = parts[0], name = parts[1];
    const tr = document.createElement('tr');

    const ownBadge = {
      CfManaged: '<span class="badge badge-cf">CF</span>',
      DcManaged: '<span class="badge badge-dc">DC</span>',
      Conflict:  '<span class="badge badge-conflict">Conflict</span>'
    }[rec.ownership] || rec.ownership;

    const statusCell = rec.isOrphan
      ? `<span class="badge badge-orphan">Orphan ${rec.orphanCycleCount}/${rec.orphanDeleteAfter}</span>`
      : (rec.ownership === 'Conflict' ? '<span class="badge badge-conflict">Resolve!</span>' : '\u2014');

    const cfText = rec.cfContent != null
      ? (rec.cfPriority != null ? 'prio:' + rec.cfPriority + ' ' : '') + rec.cfContent : null;
    const dcText = rec.dcContent != null
      ? (rec.dcPriority != null ? 'prio:' + rec.dcPriority + ' ' : '') + rec.dcContent : null;

    const cfCell = cfText != null
      ? `<code class="rec-val" title="${esc(cfText)}">${esc(cfText)}</code>`
      : '<span style="color:var(--text3)">\u2014</span>';
    const dcCell = dcText != null
      ? `<code class="rec-val" title="${esc(dcText)}">${esc(dcText)}</code>`
      : '<span style="color:var(--text3)">\u2014</span>';

    const isCf = rec.ownership === 'CfManaged', isDc = rec.ownership === 'DcManaged';
    const toggles = `<div class="toggle-wrap">
      <button class="toggle-btn ${isCf ? 'active-cf' : ''}" onclick="setOwnership('${esc(rec.key)}','CfManaged')">CF</button>
      <button class="toggle-btn ${isDc ? 'active-dc' : ''}" onclick="setOwnership('${esc(rec.key)}','DcManaged')">DC</button>
    </div>`;

    const orphCycles = rec.isOrphan
      ? `<span style="color:var(--red)">${rec.orphanCycleCount}/${rec.orphanDeleteAfter}</span>`
      : '\u2014';

    tr.innerHTML = `
      <td><code style="font-size:.78rem;white-space:nowrap">${esc(name)}</code></td>
      <td style="color:var(--text2);white-space:nowrap">${esc(type)}</td>
      <td>${ownBadge}</td>
      <td>${statusCell}</td>
      <td class="td-cf">${cfCell}</td>
      <td class="td-dc">${dcCell}</td>
      <td style="text-align:center">${orphCycles}</td>
      <td>${toggles}</td>`;
    tbody.appendChild(tr);
  });
}

async function setOwnership(key, ownership) {
  await fetch('/api/records/ownership', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ key, ownership })
  });
  await loadRecords();
}

// Diff
async function loadDiff() {
  const loadEl = document.getElementById('diff-loading');
  const wrapEl = document.getElementById('diff-wrap');
  loadEl.textContent = 'Fetching live DNS data from CF and DC...';
  loadEl.style.display = '';
  wrapEl.style.display = 'none';
  const r = await fetch('/api/diff');
  if (!r.ok) { loadEl.textContent = 'Failed to load diff: ' + r.status; return; }
  diffData = await r.json();
  loadEl.style.display = 'none';
  wrapEl.style.display = '';
  renderDiff();
}

function renderDiff() {
  const search  = document.getElementById('diff-search').value.toLowerCase();
  const statusF = document.getElementById('diff-status').value;
  const filtered = diffData.filter(d => {
    if (search  && !d.key.toLowerCase().includes(search)) return false;
    if (statusF && d.status !== statusF) return false;
    return true;
  });
  const tbody = document.getElementById('diff-tbody');
  tbody.innerHTML = '';
  if (!filtered.length) { tbody.innerHTML = '<tr><td colspan="5" style="color:var(--text3)">No records match</td></tr>'; return; }
  filtered.forEach(d => {
    const [type, name] = d.key.split('|');
    const tr = document.createElement('tr');
    const stBadge = { match: '<span class="badge badge-match">Match</span>',
      mismatch: '<span class="badge badge-mismatch">Mismatch</span>',
      cf_only:  '<span class="badge badge-cf-only">CF only</span>',
      dc_only:  '<span class="badge badge-dc-only">DC only</span>' }[d.status] || d.status;
    const ownBadge = { CfManaged: '<span class="badge badge-cf">CF</span>',
      DcManaged: '<span class="badge badge-dc">DC</span>',
      Conflict:  '<span class="badge badge-conflict">Conflict</span>' }[d.ownership] || '';
    const cfCell = d.cf
      ? `<code style="font-size:.77rem">${esc(d.cf.content)}</code>${d.cf.priority != null ? ` <span style="color:var(--text3)">prio:${d.cf.priority}</span>` : ''} <span style="color:var(--text3)">ttl:${d.cf.ttl}</span>`
      : '<span class="td-miss">not present</span>';
    const dcCell = d.dc
      ? `<code style="font-size:.77rem">${esc(d.dc.content)}</code>${d.dc.priority != null ? ` <span style="color:var(--text3)">prio:${d.dc.priority}</span>` : ''} <span style="color:var(--text3)">ttl:${d.dc.ttl}</span>`
      : '<span class="td-miss">not present</span>';
    const rowBg = d.status === 'mismatch' ? 'style="background:#1a1508"' : '';
    tr.innerHTML = `<td ${rowBg}><code style="font-size:.78rem">[${esc(type)}] ${esc(name)}</code></td>
      <td>${stBadge}${d.isOrphan ? ' <span class="badge badge-orphan">orphan</span>' : ''}</td>
      <td>${ownBadge}</td>
      <td class="td-cf">${cfCell}</td>
      <td class="td-dc">${dcCell}</td>`;
    tbody.appendChild(tr);
  });
}

// Settings
async function loadConfig() {
  const cfg = await fetch('/api/config').then(r => r.json());
  document.getElementById('cfg-zoneId').value      = cfg.cloudflareZoneId || '';
  document.getElementById('cfg-dnsDomain').value   = cfg.dnsDomain || '';
  document.getElementById('cfg-dnsServer').value   = cfg.dnsServer || 'localhost';
  document.getElementById('cfg-syncInterval').value = cfg.syncIntervalMinutes || 5;
  document.getElementById('cfg-dashPort').value    = cfg.webDashboardPort || 8765;
  document.getElementById('cfg-bindAddr').value    = cfg.webDashboardBindAddress || '0.0.0.0';
  document.getElementById('cfg-orphanCycles').value = cfg.orphanDeleteAfterCycles || 3;
  document.getElementById('cfg-retention').value    = cfg.recordModesRetentionDays ?? 90;
  document.getElementById('cfg-adGroup').value     = cfg.allowedAdGroup || 'Domain Admins';
  document.getElementById('cfg-certThumb').value   = cfg.certificateThumbprint || '';
  document.getElementById('cfg-certCn').value      = cfg.certificateCn || '';
  document.getElementById('cfg-syncA').checked     = cfg.syncARecords ?? true;
  document.getElementById('cfg-syncCname').checked = cfg.syncCnameRecords ?? true;
  document.getElementById('cfg-syncMx').checked    = cfg.syncMxRecords ?? true;
  document.getElementById('cfg-syncTxt').checked   = cfg.syncTxtRecords ?? true;
  document.getElementById('cfg-syncSrv').checked   = cfg.syncSrvRecords ?? true;
  document.getElementById('cfg-skipProxied').checked = cfg.skipProxiedARecords ?? true;
  document.getElementById('cfg-skipSsl').checked   = cfg.skipSslValidationCnames ?? true;
  document.getElementById('cfg-dryRun').checked    = cfg.dryRunMode ?? true;
  document.getElementById('cfg-skippedRecords').value = (cfg.skippedRecords ?? []).join('\n');
}

async function restartService() {
  const btn = document.getElementById('restart-btn');
  const status = document.getElementById('restart-status');
  if (!confirm('Restart the CfDnsSync service?\n\nThe dashboard will be unavailable for a few seconds.')) return;
  btn.disabled = true;
  status.textContent = 'Restarting...';
  try {
    await fetch('/api/restart', { method: 'POST' });
    status.textContent = 'Restart requested. Reconnecting...';
    // Poll until the service comes back
    let attempts = 0;
    const poll = setInterval(async () => {
      attempts++;
      try {
        await fetch('/api/status');
        clearInterval(poll);
        btn.disabled = false;
        status.textContent = 'Service restarted successfully.';
        setTimeout(() => { status.textContent = ''; }, 4000);
      } catch {
        if (attempts > 30) {
          clearInterval(poll);
          btn.disabled = false;
          status.textContent = 'Restart may have failed — check Event Log.';
        }
      }
    }, 1000);
  } catch {
    btn.disabled = false;
    status.textContent = 'Error sending restart request.';
  }
}

async function saveConfig(e) {
  e.preventDefault();
  clearErrors();
  const cfg = {
    cloudflareZoneId: v('cfg-zoneId'), dnsDomain: v('cfg-dnsDomain'),
    dnsServer: v('cfg-dnsServer') || 'localhost',
    syncIntervalMinutes: +v('cfg-syncInterval') || 5,
    webDashboardPort: +v('cfg-dashPort') || 8765,
    webDashboardBindAddress: v('cfg-bindAddr') || '0.0.0.0',
    orphanDeleteAfterCycles:  +v('cfg-orphanCycles') || 3,
    recordModesRetentionDays: +v('cfg-retention') || 90,
    allowedAdGroup: v('cfg-adGroup') || 'Domain Admins',
    certificateThumbprint: v('cfg-certThumb'),
    certificateCn: v('cfg-certCn'),
    dryRunMode: document.getElementById('cfg-dryRun').checked,
    skippedRecords: document.getElementById('cfg-skippedRecords').value.split('\n').map(s => s.trim()).filter(s => s.length > 0),
    syncARecords: document.getElementById('cfg-syncA').checked,
    syncCnameRecords: document.getElementById('cfg-syncCname').checked,
    syncMxRecords: document.getElementById('cfg-syncMx').checked,
    syncTxtRecords: document.getElementById('cfg-syncTxt').checked,
    syncSrvRecords: document.getElementById('cfg-syncSrv').checked,
    skipProxiedARecords: document.getElementById('cfg-skipProxied').checked,
    skipSslValidationCnames: document.getElementById('cfg-skipSsl').checked,
    protectedRecords: ["_ldap._tcp","_kerberos._tcp","_kerberos._udp","_kpasswd._tcp","_kpasswd._udp","_gc._tcp","DomainDnsZones","ForestDnsZones","gc._msdcs"],
    logDirectory: "logs", maxLogAgeDays: 30, cnameAllowPatterns: []
  };
  let ok = true;
  if (!cfg.cloudflareZoneId) { setErr('zoneId','Required'); ok=false; }
  if (!cfg.dnsDomain)        { setErr('dnsDomain','Required'); ok=false; }
  if (cfg.syncIntervalMinutes < 1 || cfg.syncIntervalMinutes > 1440) { setErr('syncInterval','1-1440'); ok=false; }
  if (cfg.webDashboardPort < 1024 || cfg.webDashboardPort > 65535)  { setErr('dashPort','1024-65535'); ok=false; }
  if (cfg.orphanDeleteAfterCycles < 1) { setErr('orphanCycles','Min 1'); ok=false; }
  if (!ok) return;
  const res  = await fetch('/api/config', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(cfg)});
  const data = await res.json();
  const msg  = document.getElementById('cfg-save-msg');
  msg.className = data.ok ? 'save-msg ok' : 'save-msg err';
  msg.textContent = data.ok ? ('Saved. ' + (data.message || '')) : ('Error: ' + (data.error || ''));
  setTimeout(() => { msg.textContent = ''; }, 6000);
}

function v(id) { return document.getElementById(id)?.value?.trim() || ''; }
function setErr(id, msg) { const el = document.getElementById('err-' + id); if (el) el.textContent = msg; }
function clearErrors() { document.querySelectorAll('.field-err').forEach(e => e.textContent = ''); }
function esc(s) { if (!s) return ''; return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

async function refresh() { await Promise.all([loadStatus(), loadHistory()]); }
refresh();
setInterval(refresh, 10000);
</script>
</body>
</html>
""";

    // ── Response helpers ──────────────────────────────────────────────────────

    private static string Serialize(object obj) =>
        JsonSerializer.Serialize(obj, JsonOpts);

    private static async Task ServeJsonAsync(HttpListenerContext ctx, string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        ctx.Response.StatusCode = 200;
        ctx.Response.ContentType = "application/json; charset=utf-8";
        ctx.Response.ContentLength64 = bytes.Length;
        ctx.Response.Headers.Add("Cache-Control", "no-store");
        await ctx.Response.OutputStream.WriteAsync(bytes);
        ctx.Response.Close();
    }

    private static async Task ServeHtmlAsync(HttpListenerContext ctx, string html)
    {
        var bytes = Encoding.UTF8.GetBytes(html);
        ctx.Response.StatusCode = 200;
        ctx.Response.ContentType = "text/html; charset=utf-8";
        ctx.Response.ContentLength64 = bytes.Length;
        await ctx.Response.OutputStream.WriteAsync(bytes);
        ctx.Response.Close();
    }

    private static async Task ServeTextAsync(HttpListenerContext ctx, string text)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        ctx.Response.ContentType = "text/plain; charset=utf-8";
        ctx.Response.ContentLength64 = bytes.Length;
        await ctx.Response.OutputStream.WriteAsync(bytes);
        ctx.Response.Close();
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };

    private class OwnershipRequest { public string Key { get; set; } = ""; public string Ownership { get; set; } = ""; }
}
