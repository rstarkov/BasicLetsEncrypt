using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace BasicLetsEncrypt;

/// <summary>
///     Minimal ACME v2 (RFC 8555) client covering only what this program needs: a fresh ES256 account, a single-identifier
///     order validated via DNS-01, finalization and certificate download.</summary>
class AcmeClient
{
    public const string LetsEncryptV2 = "https://acme-v02.api.letsencrypt.org/directory";

    private readonly HttpClient _http = new();
    private readonly ECDsa _accountKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly string _directoryUrl;
    private Dictionary<string, string> _directory;
    private string _nonce;
    private string _kid;

    public AcmeClient(string directoryUrl)
    {
        _directoryUrl = directoryUrl;
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("BasicLetsEncrypt/1.0");
        _http.Timeout = TimeSpan.FromSeconds(30); // short enough to allow several attempts within the retry window
    }

    /// <summary>Creates a new account with the given contact email, agreeing to the terms of service.</summary>
    public async Task NewAccount(string email)
    {
        var response = await Post((await Directory())["newAccount"], new { termsOfServiceAgreed = true, contact = new[] { "mailto:" + email } }, useJwk: true);
        _kid = response.Headers.Location.ToString();
    }

    public async Task<AcmeOrder> NewOrder(string domain)
    {
        var response = await Post((await Directory())["newOrder"], new { identifiers = new[] { new { type = "dns", value = domain } } });
        return ParseOrder(response.Headers.Location.ToString(), await ReadJson(response));
    }

    public async Task<AcmeOrder> GetOrder(string orderUrl)
    {
        return ParseOrder(orderUrl, await ReadJson(await Post(orderUrl, null)));
    }

    /// <summary>Polls the order until its status is no longer <paramref name="status"/>. Throws if the order becomes invalid.</summary>
    public async Task<AcmeOrder> WaitWhileOrderIs(string orderUrl, string status)
    {
        for (int attempt = 0; ; attempt++)
        {
            var order = await GetOrder(orderUrl);
            if (order.Status == "invalid")
                throw new AcmeException($"Order {orderUrl} is invalid.{await DescribeChallengeErrors(order)}");
            if (order.Status != status)
                return order;
            if (attempt >= 60)
                throw new AcmeException($"Order {orderUrl} is still \"{status}\" after {attempt} attempts.");
            await Task.Delay(2000);
        }
    }

    /// <summary>Retrieves the challenge of the specified type ("dns-01" or "http-01") from an authorization.</summary>
    /// <summary>
    ///     Collects the error reported by the server for every failed challenge in the order's authorizations, as text to
    ///     append to an error message. Empty if there are none, or if they can't be retrieved.</summary>
    private async Task<string> DescribeChallengeErrors(AcmeOrder order)
    {
        var result = new StringBuilder();
        try
        {
            foreach (var authorizationUrl in order.Authorizations)
            {
                var json = await ReadJson(await Post(authorizationUrl, null));
                foreach (var challenge in json.GetProperty("challenges").EnumerateArray())
                    if (challenge.TryGetProperty("error", out var error))
                        result.Append($"{Environment.NewLine}{challenge.GetProperty("type").GetString()} challenge error: {error}");
            }
        }
        catch (Exception e) { result.Append($"{Environment.NewLine}(could not retrieve the challenge errors: {e.Message})"); }
        return result.ToString();
    }

    public async Task<AcmeChallenge> GetChallenge(string authorizationUrl, string type)
    {
        var json = await ReadJson(await Post(authorizationUrl, null));
        var challenge = json.GetProperty("challenges").EnumerateArray().FirstOrDefault(c => c.GetProperty("type").GetString() == type);
        if (challenge.ValueKind == JsonValueKind.Undefined)
            throw new AcmeException($"The server did not offer a {type} challenge for this authorization.");
        return new AcmeChallenge(challenge.GetProperty("url").GetString(), challenge.GetProperty("token").GetString());
    }

    /// <summary>Computes the key authorization for a challenge token: the content to serve for an HTTP-01 challenge.</summary>
    public string KeyAuthorization(string token)
    {
        return token + "." + Thumbprint();
    }

    /// <summary>Computes the value of the _acme-challenge TXT record for a DNS-01 challenge token.</summary>
    public string DnsTxt(string token)
    {
        return Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes(KeyAuthorization(token))));
    }

    /// <summary>Tells the server that the challenge is ready to be validated.</summary>
    public Task Validate(string challengeUrl)
    {
        return Post(challengeUrl, new { });
    }

    public Task Finalize(string finalizeUrl, byte[] csrDer)
    {
        return Post(finalizeUrl, new { csr = Base64Url(csrDer) });
    }

    /// <summary>Downloads the certificate chain. The first certificate is the end-entity certificate, followed by the issuers.</summary>
    public async Task<X509Certificate2Collection> DownloadCertificate(string certificateUrl)
    {
        var response = await Post(certificateUrl, null, accept: "application/pem-certificate-chain");
        var chain = new X509Certificate2Collection();
        chain.ImportFromPem(await response.Content.ReadAsStringAsync());
        return chain;
    }

    private async Task<Dictionary<string, string>> Directory()
    {
        if (_directory == null)
        {
            var response = await Send(() => Task.FromResult(new HttpRequestMessage(HttpMethod.Get, _directoryUrl)));
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            _directory = doc.RootElement.EnumerateObject().Where(p => p.Value.ValueKind == JsonValueKind.String).ToDictionary(p => p.Name, p => p.Value.GetString());
        }
        return _directory;
    }

    private async Task<string> TakeNonce()
    {
        if (_nonce == null)
            await Send(async () => new HttpRequestMessage(HttpMethod.Head, (await Directory())["newNonce"])); // Send stores the Replay-Nonce
        var nonce = _nonce;
        _nonce = null;
        return nonce;
    }

    /// <summary>
    ///     Sends a JWS-signed POST. A null <paramref name="payload"/> sends a POST-as-GET. The account key is identified by
    ///     the JWK when creating the account, and by the account URL (kid) afterwards.</summary>
    private Task<HttpResponseMessage> Post(string url, object payload, bool useJwk = false, string accept = "application/json")
    {
        return Send(async () =>
        {
            var header = new Dictionary<string, object> { ["alg"] = "ES256", ["nonce"] = await TakeNonce(), ["url"] = url };
            if (useJwk)
                header["jwk"] = Jwk();
            else
                header["kid"] = _kid;
            var protectedB64 = Base64Url(JsonSerializer.SerializeToUtf8Bytes(header));
            var payloadB64 = payload == null ? "" : Base64Url(JsonSerializer.SerializeToUtf8Bytes(payload));
            var signature = _accountKey.SignData(Encoding.ASCII.GetBytes(protectedB64 + "." + payloadB64), HashAlgorithmName.SHA256);
            var body = JsonSerializer.Serialize(new { @protected = protectedB64, payload = payloadB64, signature = Base64Url(signature) });

            var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = new StringContent(body) };
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/jose+json");
            request.Headers.Accept.ParseAdd(accept);
            return request;
        });
    }

    /// <summary>
    ///     Sends a request, retrying transient failures (connection errors, timeouts, HTTP 5xx) every 5 seconds for up to
    ///     120 seconds. A bad nonce is retried immediately. The request is rebuilt for every attempt so that it carries a
    ///     fresh nonce. Any other failure throws an <see cref="AcmeException"/> with the server's error.</summary>
    private async Task<HttpResponseMessage> Send(Func<Task<HttpRequestMessage>> makeRequest)
    {
        var deadline = DateTime.UtcNow.AddSeconds(120);
        var waited = false;
        while (true)
        {
            HttpRequestMessage request = null;
            string failure;
            try
            {
                request = await makeRequest();
                var response = await _http.SendAsync(request);
                if (response.Headers.TryGetValues("Replay-Nonce", out var nonces))
                    _nonce = nonces.First();
                if (response.IsSuccessStatusCode)
                    return response;
                var error = await response.Content.ReadAsStringAsync();
                if (error.Contains("urn:ietf:params:acme:error:badNonce") && DateTime.UtcNow < deadline)
                    continue;
                if ((int) response.StatusCode < 500)
                    throw new AcmeException($"ACME request to {request.RequestUri} failed with HTTP {(int) response.StatusCode}: {error}");
                failure = $"HTTP {(int) response.StatusCode}: {error}";
            }
            catch (Exception e) when (e is HttpRequestException || e is TaskCanceledException) // connection failure or timeout
            {
                failure = e.Message;
            }

            if (DateTime.UtcNow >= deadline)
                throw new AcmeException($"ACME request to {request?.RequestUri} kept failing for 120 seconds. Last failure: {failure}");
            if (!waited)
                Console.WriteLine($"ACME request to {request?.RequestUri} failed: {failure} Retrying every 5 seconds for up to 120 seconds...");
            waited = true;
            await Task.Delay(5000);
        }
    }

    private static async Task<JsonElement> ReadJson(HttpResponseMessage response)
    {
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return doc.RootElement.Clone();
    }

    private static AcmeOrder ParseOrder(string url, JsonElement json)
    {
        return new AcmeOrder(
            Url: url,
            Status: json.GetProperty("status").GetString(),
            Authorizations: json.GetProperty("authorizations").EnumerateArray().Select(a => a.GetString()).ToArray(),
            Finalize: json.GetProperty("finalize").GetString(),
            Certificate: json.TryGetProperty("certificate", out var cert) ? cert.GetString() : null);
    }

    /// <summary>Public account key as a JWK. Members are in lexicographic order, as required for the thumbprint (RFC 7638).</summary>
    private object Jwk()
    {
        var q = _accountKey.ExportParameters(false).Q;
        return new { crv = "P-256", kty = "EC", x = Base64Url(q.X), y = Base64Url(q.Y) };
    }

    private string Thumbprint()
    {
        return Base64Url(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(Jwk())));
    }

    private static string Base64Url(byte[] bytes)
    {
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}

record AcmeOrder(string Url, string Status, string[] Authorizations, string Finalize, string Certificate);

record AcmeChallenge(string Url, string Token);

class AcmeException : Exception
{
    public AcmeException(string message) : base(message) { }
}

class CsrInfo
{
    public string CountryName { get; set; }
    public string State { get; set; }
    public string Locality { get; set; }
    public string Organization { get; set; }
    public string OrganizationUnit { get; set; }
    public string CommonName { get; set; }
}

static class Pki
{
    /// <summary>Builds a DER-encoded PKCS#10 certificate signing request with the common name as the sole subject alternative name.</summary>
    public static byte[] CreateCsr(CsrInfo info, ECDsa key)
    {
        // The builder encodes attributes in reverse order of addition, so add them from most to least specific.
        var subject = new X500DistinguishedNameBuilder();
        subject.AddCommonName(info.CommonName);
        if (!string.IsNullOrEmpty(info.OrganizationUnit)) subject.AddOrganizationalUnitName(info.OrganizationUnit);
        if (!string.IsNullOrEmpty(info.Organization)) subject.AddOrganizationName(info.Organization);
        if (!string.IsNullOrEmpty(info.Locality)) subject.AddLocalityName(info.Locality);
        if (!string.IsNullOrEmpty(info.State)) subject.AddStateOrProvinceName(info.State);
        if (!string.IsNullOrEmpty(info.CountryName)) subject.AddCountryOrRegion(info.CountryName);

        var request = new CertificateRequest(subject.Build(), key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(info.CommonName);
        request.CertificateExtensions.Add(san.Build());
        return request.CreateSigningRequest();
    }

    /// <summary>Packages the certificate chain and private key into a password-protected PKCS#12 file.</summary>
    public static byte[] ToPfx(X509Certificate2Collection chain, ECDsa privateKey, string friendlyName, string password)
    {
        var leaf = chain[0].CopyWithPrivateKey(privateKey);
        if (OperatingSystem.IsWindows())
            leaf.FriendlyName = friendlyName;
        var pfx = new X509Certificate2Collection { leaf };
        pfx.AddRange(chain.Skip(1).ToArray());
        return pfx.Export(X509ContentType.Pkcs12, password);
    }
}
