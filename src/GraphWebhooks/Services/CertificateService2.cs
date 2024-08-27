// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

using System.Security.Cryptography.X509Certificates;

namespace GraphWebhooks.Services;

public class CertificateService2
{
    private readonly IConfiguration _config;
    private readonly ILogger<CertificateService> _logger;

    private byte[]? _publicKeyBytes = null;
    private byte[]? _privateKeyBytes = null;

    public CertificateService2(IConfiguration configuration, ILogger<CertificateService> logger)
    {
        _config = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Gets the configured public key from the local certificate file.
    /// </summary>
    /// <returns>The public key.</returns>
    public async Task<X509Certificate2> GetEncryptionCertificate()
    {
        if (_publicKeyBytes == null)
        {
            await LoadCertificates();
        }

        return new X509Certificate2(_publicKeyBytes ??
            throw new Exception("Could not load encryption certificate"));
    }

    /// <summary>
    /// Gets the configured private key from the local certificate file.
    /// </summary>
    /// <returns>The private key.</returns>
    public async Task<X509Certificate2> GetDecryptionCertificate()
    {
        if (_privateKeyBytes == null)
        {
            await LoadCertificates();
        }

        return new X509Certificate2(_privateKeyBytes ??
            throw new Exception("Could not load decryption certificate"));
    }

    /// <summary>
    /// Loads the public and private keys from the local certificate files.
    /// </summary>
    private async Task LoadCertificates()
    {
        // Load configuration values
        var certificatePath = _config.GetValue<string>("Certificate:Path");
        var certificatePassword = _config.GetValue<string>("Certificate:Password");

        if (string.IsNullOrEmpty(certificatePath) || string.IsNullOrEmpty(certificatePassword))
        {
            throw new Exception("Certificate path or password not set in appsettings");
        }

        _logger.LogInformation("Loading certificate from local directory");

        // Load the certificate file from the local directory
        //var certificate = new X509Certificate2(certificatePath);
        var certificate = new X509Certificate2(certificatePath, certificatePassword);

        // Get public and private keys
        _publicKeyBytes = certificate.Export(X509ContentType.Cert); // Public key
        _privateKeyBytes = certificate.Export(X509ContentType.Pfx); // Private key

        await Task.CompletedTask; // Simulating async operation, replace if needed
    }
}
