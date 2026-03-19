using CfDnsSync;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Events;
using Serilog.Extensions.Logging;

// ── Serilog: file sink (all levels) + selective EventLog (Warning+) ───────────
var logDir = Path.Combine(AppContext.BaseDirectory, "logs");
Directory.CreateDirectory(logDir);

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Debug()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
    .MinimumLevel.Override("System", LogEventLevel.Warning)
    // Rolling file — all levels
    .WriteTo.File(
        path: Path.Combine(logDir, "cfds-.log"),
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 30,
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}")
    // Windows Event Log — Errors only (all sources) + SyncWorker warnings only.
    // Everything else goes to file only — too verbose for EventLog.
    .WriteTo.Logger(lc => lc
        .Filter.ByIncludingOnly(e =>
        {
            if (e.Level >= LogEventLevel.Error) return true;
            if (e.Level < LogEventLevel.Warning) return false;
            // Only SyncWorker warnings go to EventLog (token import, startup failures)
            if (!e.Properties.TryGetValue("SourceContext", out var src)) return false;
            return src.ToString().Contains("SyncWorker");
        })
        .WriteTo.EventLog(
            source: "CfDnsSync",
            logName: "Application",
            manageEventSource: false,
            outputTemplate: "[{Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}"))
    .CreateLogger();

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "CfDnsSync";
});

builder.Services.AddSingleton<ConfigManager>();
builder.Services.AddSingleton<TokenStore>();
builder.Services.AddSingleton<CloudflareClient>();
builder.Services.AddSingleton<DnsManager>();
builder.Services.AddSingleton<SyncStateStore>();
builder.Services.AddSingleton<RecordModeStore>();
builder.Services.AddSingleton<SyncEngine>();
builder.Services.AddHostedService<SyncWorker>();
builder.Services.AddHostedService<WebDashboard>();

// Use Serilog as the logging provider — replaces all default providers
// For HostApplicationBuilder (not IHostBuilder) we add Serilog via AddSerilog
builder.Logging.ClearProviders();
builder.Logging.AddSerilog(Log.Logger, dispose: true);

var host = builder.Build();

// Handle setup commands
if (args.Length > 0)
{
    switch (args[0].ToLower())
    {
        case "setup-token":
            var tokenStore = host.Services.GetRequiredService<TokenStore>();
            Console.Write("Enter Cloudflare API Token: ");
            var token = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(token))
            {
                Console.Error.WriteLine("Token cannot be empty.");
                return 1;
            }
            tokenStore.SaveToken(token);
            Console.WriteLine("Token saved and encrypted successfully.");
            return 0;

        case "setup-config":
            var cfg = host.Services.GetRequiredService<ConfigManager>();
            cfg.RunInteractiveSetup();
            return 0;

        case "sync-now":
            var engine = host.Services.GetRequiredService<SyncEngine>();
            await engine.RunSyncAsync(CancellationToken.None);
            Console.WriteLine("Manual sync completed.");
            return 0;
    }
}

host.Run();
Log.CloseAndFlush();
return 0;
