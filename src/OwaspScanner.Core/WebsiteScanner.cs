using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace OwaspScanner.Core;

public sealed class WebsiteScanner
{
    public async Task<ScanResult> ScanAsync(ScanOptions options, CancellationToken cancellationToken = default)
    {
        var started = DateTimeOffset.UtcNow;
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = options.FollowRedirects,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };

        using var client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds)
        };

        client.DefaultRequestHeaders.UserAgent.Clear();
        client.DefaultRequestHeaders.UserAgent.Add(ProductInfoHeaderValue.Parse(options.UserAgent));

        using var response = await client.GetAsync(options.Target, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        var findings = Analyze(response, body, options.Target);

        var completed = DateTimeOffset.UtcNow;
        var headers = response.Headers
            .Concat(response.Content.Headers)
            .ToDictionary(h => h.Key, h => string.Join(";", h.Value), StringComparer.OrdinalIgnoreCase);

        return new ScanResult(
            options.Target,
            started,
            completed,
            (int)response.StatusCode,
            findings,
            headers,
            body.Length);
    }

    public static string ToJson(ScanResult result)
        => JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });

    private static List<RiskFinding> Analyze(HttpResponseMessage response, string body, Uri target)
    {
        var findings = new List<RiskFinding>();
        var headers = response.Headers.Concat(response.Content.Headers)
            .ToDictionary(h => h.Key, h => string.Join(";", h.Value), StringComparer.OrdinalIgnoreCase);

        if (!target.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new RiskFinding(
                "A02:2021",
                "TLS-001",
                "Target does not enforce HTTPS",
                RiskLevel.High,
                $"URL scheme is '{target.Scheme}'.",
                "Use HTTPS with strong TLS and redirect HTTP traffic to HTTPS."));
        }

        CheckMissingHeader(findings, headers, "Content-Security-Policy", "A05:2021", "HDR-001", RiskLevel.High);
        CheckMissingHeader(findings, headers, "X-Content-Type-Options", "A05:2021", "HDR-002", RiskLevel.Medium);
        CheckMissingHeader(findings, headers, "X-Frame-Options", "A01:2021", "HDR-003", RiskLevel.Medium);
        CheckMissingHeader(findings, headers, "Strict-Transport-Security", "A02:2021", "HDR-004", RiskLevel.Medium);

        var serverHeader = headers.TryGetValue("Server", out var server) ? server : string.Empty;
        if (!string.IsNullOrWhiteSpace(serverHeader))
        {
            findings.Add(new RiskFinding(
                "A05:2021",
                "CFG-001",
                "Server banner disclosed",
                RiskLevel.Low,
                $"Server header: {serverHeader}",
                "Remove or minimize server banner details to reduce fingerprinting."));
        }

        if (Regex.IsMatch(body, "(password|apikey|secret)\\s*[:=]\\s*[\"']?[a-zA-Z0-9_\\-]{8,}", RegexOptions.IgnoreCase))
        {
            findings.Add(new RiskFinding(
                "A09:2021",
                "LOG-001",
                "Potential sensitive data exposure in response body",
                RiskLevel.High,
                "Detected secret-like tokens in response body.",
                "Do not expose credentials or secrets in HTML/JS responses."));
        }

        if (Regex.IsMatch(body, "<input[^>]+type=[\"']password[\"'][^>]*>", RegexOptions.IgnoreCase) &&
            !Regex.IsMatch(body, "autocomplete=[\"']off[\"']", RegexOptions.IgnoreCase))
        {
            findings.Add(new RiskFinding(
                "A07:2021",
                "AUTH-001",
                "Password input allows browser autocomplete",
                RiskLevel.Low,
                "Password field found without autocomplete safeguards.",
                "Review autocomplete settings and MFA requirements for sensitive flows."));
        }

        if (Regex.IsMatch(body, "(select\\s+\\*\\s+from|union\\s+select|or\\s+1=1)", RegexOptions.IgnoreCase))
        {
            findings.Add(new RiskFinding(
                "A03:2021",
                "INJ-001",
                "Potential SQL-injection pattern reflected",
                RiskLevel.Critical,
                "SQL-like payload pattern appeared in response.",
                "Validate and sanitize input and use parameterized queries."));
        }

        if ((int)response.StatusCode >= (int)HttpStatusCode.InternalServerError)
        {
            findings.Add(new RiskFinding(
                "A04:2021",
                "DSN-001",
                "Server returned 5xx errors",
                RiskLevel.Medium,
                $"HTTP {(int)response.StatusCode}",
                "Harden exception handling and avoid leaking stack traces."));
        }

        return findings;
    }

    private static void CheckMissingHeader(
        List<RiskFinding> findings,
        IReadOnlyDictionary<string, string> headers,
        string headerName,
        string category,
        string ruleId,
        RiskLevel severity)
    {
        if (headers.ContainsKey(headerName))
        {
            return;
        }

        findings.Add(new RiskFinding(
            category,
            ruleId,
            $"Missing security header: {headerName}",
            severity,
            $"{headerName} header was not found.",
            $"Add the {headerName} header with secure values."));
    }
}
