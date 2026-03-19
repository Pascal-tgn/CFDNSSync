using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace CfDnsSync;

public class CloudflareClient
{
    private readonly ILogger<CloudflareClient> _logger;
    private readonly ConfigManager _config;
    private readonly TokenStore _tokenStore;
    private readonly HttpClient _http;

    // SSL validation CNAME pattern: starts with _ followed by 32 hex chars
    private static readonly Regex SslValidationCnamePattern =
        new(@"^_[0-9a-f]{32}\.", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public CloudflareClient(ILogger<CloudflareClient> logger, ConfigManager config, TokenStore tokenStore)
    {
        _logger = logger;
        _config = config;
        _tokenStore = tokenStore;
        _http = new HttpClient
        {
            BaseAddress = new Uri("https://api.cloudflare.com/client/v4/"),
            Timeout = TimeSpan.FromSeconds(30)
        };
    }

    private void SetAuthHeader()
    {
        var token = _tokenStore.LoadToken();
        _http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);
    }

    /// <summary>
    /// Fetches all relevant DNS records from Cloudflare and applies filtering rules.
    /// Returns records that should exist on the local DC.
    /// </summary>
    public async Task<List<DnsRecord>> FetchFilteredRecordsAsync(CancellationToken ct)
    {
        SetAuthHeader();
        var cfg = _config.Config;
        var zoneId = cfg.CloudflareZoneId;

        if (string.IsNullOrEmpty(zoneId))
            throw new InvalidOperationException("CloudflareZoneId is not configured.");

        var allRecords = await FetchAllRecordsAsync(zoneId, ct);
        _logger.LogInformation("Fetched {Count} total records from Cloudflare", allRecords.Count);

        var filtered = new List<DnsRecord>();

        foreach (var rec in allRecords)
        {
            if (!ShouldInclude(rec, cfg))
            {
                _logger.LogDebug("Excluded: {Record}", rec);
                continue;
            }
            filtered.Add(rec);
        }

        _logger.LogInformation("After filtering: {Count} records to sync", filtered.Count);
        return filtered;
    }

    private bool ShouldInclude(DnsRecord rec, AppConfig cfg)
    {
        // Check protected record names
        var relName = rec.Name.ToLowerInvariant();
        foreach (var protected_ in cfg.ProtectedRecords)
        {
            if (relName.StartsWith(protected_.ToLowerInvariant()))
                return false;
        }

        // Check skipped records list
        if (cfg.SkippedRecords.Any(s =>
            string.Equals(s, relName, StringComparison.OrdinalIgnoreCase)))
            return false;

        switch (rec.Type)
        {
            case DnsRecordType.A:
                if (!cfg.SyncARecords) return false;
                // Skip proxied A records (Cloudflare Anycast IPs like 141.193.213.x, 3.230.61.x with proxy)
                if (cfg.SkipProxiedARecords && rec.CfProxied) return false;
                return true;

            case DnsRecordType.CNAME:
                if (!cfg.SyncCnameRecords) return false;
                // Skip SSL validation CNAMEs (_hex32chars.subdomain format)
                if (cfg.SkipSslValidationCnames && SslValidationCnamePattern.IsMatch(rec.Name))
                    return false;
                // If allow list is configured, only allow matching patterns
                if (cfg.CnameAllowPatterns.Count > 0)
                {
                    var nameL = rec.Name.ToLowerInvariant();
                    return cfg.CnameAllowPatterns.Any(p =>
                        nameL.Contains(p.ToLowerInvariant()));
                }
                return true;

            case DnsRecordType.MX:
                return cfg.SyncMxRecords;

            case DnsRecordType.TXT:
                return cfg.SyncTxtRecords;

            case DnsRecordType.SRV:
                return cfg.SyncSrvRecords;

            default:
                return false;
        }
    }

    private async Task<List<DnsRecord>> FetchAllRecordsAsync(string zoneId, CancellationToken ct)
    {
        var results = new List<DnsRecord>();
        int page = 1;
        const int perPage = 100;

        while (true)
        {
            var url = $"zones/{zoneId}/dns_records?per_page={perPage}&page={page}";

            // Retry up to 3 times with exponential backoff for transient errors
            HttpResponseMessage response = null!;
            for (int attempt = 1; attempt <= 3; attempt++)
            {
                try
                {
                    response = await _http.GetAsync(url, ct);
                    if (response.IsSuccessStatusCode) break;
                    if (attempt < 3)
                    {
                        _logger.LogWarning("CF API returned {Status} on attempt {A}/3, retrying...",
                            (int)response.StatusCode, attempt);
                        await Task.Delay(TimeSpan.FromSeconds(attempt * 2), ct);
                    }
                }
                catch (HttpRequestException ex) when (attempt < 3)
                {
                    _logger.LogWarning("CF API request failed on attempt {A}/3: {Err}", attempt, ex.Message);
                    await Task.Delay(TimeSpan.FromSeconds(attempt * 2), ct);
                }
            }
            response.EnsureSuccessStatusCode();

            var body = await response.Content.ReadAsStringAsync(ct);
            var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            if (!root.GetProperty("success").GetBoolean())
            {
                var errors = root.GetProperty("errors").ToString();
                throw new Exception($"Cloudflare API error: {errors}");
            }

            var records = root.GetProperty("result");
            foreach (var r in records.EnumerateArray())
            {
                var rec = ParseRecord(r);
                if (rec != null) results.Add(rec);
            }

            var resultInfo = root.GetProperty("result_info");
            var totalPages = resultInfo.GetProperty("total_pages").GetInt32();
            if (page >= totalPages) break;
            page++;
        }

        return results;
    }

    private DnsRecord? ParseRecord(JsonElement r)
    {
        var typeStr = r.GetProperty("type").GetString() ?? "";
        if (!Enum.TryParse<DnsRecordType>(typeStr, true, out var type))
            return null; // Unsupported type (NS, SOA, CAA, etc.) - skip

        var fullName = r.GetProperty("name").GetString() ?? "";
        var domain = _config.Config.DnsDomain;

        // Convert FQDN to relative name (strip domain suffix)
        var relName = fullName;
        if (relName.Equals(domain, StringComparison.OrdinalIgnoreCase))
            relName = "@";
        else if (relName.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))
            relName = relName[..^(domain.Length + 1)];

        var content = r.GetProperty("content").GetString() ?? "";
        var ttl = r.GetProperty("ttl").GetInt32();
        if (ttl == 1) ttl = 300; // CF "auto" TTL → use 300s on DC

        var proxied = false;
        if (r.TryGetProperty("proxied", out var proxiedEl))
            proxied = proxiedEl.GetBoolean();

        var rec = new DnsRecord
        {
            Name = relName,
            Type = type,
            Content = content.TrimEnd('.'), // remove trailing dot from FQDNs
            Ttl = Math.Max(ttl, 60),
            CfProxied = proxied,
            CloudflareId = r.GetProperty("id").GetString()
        };

        // MX priority
        if (type == DnsRecordType.MX && r.TryGetProperty("priority", out var prioEl))
            rec.Priority = prioEl.GetInt32();

        // SRV data
        if (type == DnsRecordType.SRV && r.TryGetProperty("data", out var dataEl))
        {
            if (dataEl.TryGetProperty("priority", out var sp)) rec.Priority = sp.GetInt32();
            if (dataEl.TryGetProperty("weight", out var sw)) rec.Weight = sw.GetInt32();
            if (dataEl.TryGetProperty("port", out var sport)) rec.Port = sport.GetInt32();
            if (dataEl.TryGetProperty("target", out var st))
                rec.Content = st.GetString()?.TrimEnd('.') ?? rec.Content;
        }

        return rec;
    }

    public async Task<bool> ValidateTokenAsync(CancellationToken ct)
    {
        try
        {
            SetAuthHeader();
            var response = await _http.GetAsync("user/tokens/verify", ct);
            if (!response.IsSuccessStatusCode) return false;
            var body = await response.Content.ReadAsStringAsync(ct);
            var doc = JsonDocument.Parse(body);
            return doc.RootElement.GetProperty("success").GetBoolean();
        }
        catch { return false; }
    }
}
