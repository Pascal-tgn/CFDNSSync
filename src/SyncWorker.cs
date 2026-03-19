using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CfDnsSync;

public class SyncWorker : BackgroundService
{
    private readonly ILogger<SyncWorker> _logger;
    private readonly SyncEngine _engine;
    private readonly ConfigManager _config;
    private readonly CloudflareClient _cf;
    private readonly TokenStore _tokenStore;

    public SyncWorker(ILogger<SyncWorker> logger, SyncEngine engine, ConfigManager config,
        CloudflareClient cf, TokenStore tokenStore)
    {
        _logger = logger;
        _engine = engine;
        _config = config;
        _cf = cf;
        _tokenStore = tokenStore;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("CfDnsSync worker started. Sync interval: {Minutes} minutes",
            _config.Config.SyncIntervalMinutes);

        // Validate configuration before first sync
        if (string.IsNullOrWhiteSpace(_config.Config.CloudflareZoneId))
        {
            _logger.LogError("CloudflareZoneId is not configured. Run setup-config and restart the service.");
            return;
        }

        // Auto-import token from plaintext file if present
        // This allows first-run setup without needing to run setup-token interactively
        var tokenTxtPath = Path.Combine(AppContext.BaseDirectory, "token.txt");
        if (File.Exists(tokenTxtPath))
        {
            try
            {
                var plainToken = File.ReadAllText(tokenTxtPath).Trim();
                if (!string.IsNullOrEmpty(plainToken))
                {
                    // SaveToken first — only delete the file if encryption succeeded
                    _tokenStore.SaveToken(plainToken);
                    _logger.LogInformation("Token imported from token.txt and encrypted with DPAPI.");
                    File.Delete(tokenTxtPath);
                    _logger.LogInformation("token.txt deleted.");
                }
                else
                {
                    // File is empty — delete it (nothing useful inside)
                    File.Delete(tokenTxtPath);
                    _logger.LogWarning("token.txt was empty — deleted without importing.");
                }
            }
            catch (Exception ex)
            {
                // SaveToken or file read failed — do NOT delete token.txt so the user can retry
                _logger.LogWarning(ex,
                    "Failed to import token from token.txt: {Err}. " +
                    "token.txt has NOT been deleted — fix the issue and restart the service.", ex.Message);
            }
        }

        if (!_tokenStore.TokenExists())
        {
            _logger.LogError("Cloudflare API token not found. Run setup-token and restart the service.");
            return;
        }

        // Validate token against Cloudflare API
        var tokenValid = await _cf.ValidateTokenAsync(stoppingToken);
        if (!tokenValid)
        {
            _logger.LogError("Cloudflare API token validation failed. Check token permissions and run setup-token.");
            return;
        }

        _logger.LogInformation("Configuration validated successfully. Starting sync worker.");

        // Run immediately on startup, then on interval
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await _engine.RunSyncAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unhandled exception in sync cycle");
            }

            var delay = TimeSpan.FromMinutes(_config.Config.SyncIntervalMinutes);
            _logger.LogDebug("Next sync in {Minutes} minutes", _config.Config.SyncIntervalMinutes);

            try
            {
                await Task.Delay(delay, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        _logger.LogInformation("CfDnsSync worker stopped.");
    }
}
