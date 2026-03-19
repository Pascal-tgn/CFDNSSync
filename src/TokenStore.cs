using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;

namespace CfDnsSync;

/// <summary>
/// Stores the Cloudflare API token encrypted with DPAPI (Windows Data Protection API).
/// Uses CurrentUser scope — only the Windows account that ran setup-token can decrypt it.
/// The service must run under the same account. Run setup-token as that account.
/// On DC with LocalSystem: run "setup-token" as the service account, not as admin.
/// </summary>
public class TokenStore
{
    private readonly ILogger<TokenStore> _logger;
    private readonly string _tokenFilePath;

    public TokenStore(ILogger<TokenStore> logger)
    {
        _logger = logger;
        var baseDir = AppContext.BaseDirectory;
        _tokenFilePath = Path.Combine(baseDir, "cf_token.dat");
    }

    /// <summary>
    /// Encrypts and saves the token to disk using DPAPI.
    /// Must be called from the same Windows account that will run the service.
    /// </summary>
    public void SaveToken(string token)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            throw new PlatformNotSupportedException("DPAPI token storage requires Windows.");

        var plainBytes = Encoding.UTF8.GetBytes(token);
        // CurrentUser scope: only the same Windows service account can decrypt.
        // IMPORTANT: setup-token must be run as the same account that runs the service.
        var encrypted = ProtectedData.Protect(plainBytes, null, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(_tokenFilePath, encrypted);
        _logger.LogInformation("Cloudflare API token saved (DPAPI encrypted) to {Path}", _tokenFilePath);
    }

    /// <summary>
    /// Loads and decrypts the Cloudflare API token from disk.
    /// </summary>
    public string LoadToken()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            throw new PlatformNotSupportedException("DPAPI token storage requires Windows.");

        if (!File.Exists(_tokenFilePath))
            throw new FileNotFoundException(
                $"Cloudflare token file not found at {_tokenFilePath}. " +
                "Run 'CfDnsSync.exe setup-token' to configure the API token.");

        var encrypted = File.ReadAllBytes(_tokenFilePath);
        var plainBytes = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser);
        return Encoding.UTF8.GetString(plainBytes);
    }

    public bool TokenExists() => File.Exists(_tokenFilePath);
}
