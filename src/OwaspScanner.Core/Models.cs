namespace OwaspScanner.Core;

public enum RiskLevel
{
    Informational,
    Low,
    Medium,
    High,
    Critical
}

public sealed record RiskFinding(
    string Category,
    string RuleId,
    string Title,
    RiskLevel Severity,
    string Evidence,
    string Recommendation);

public sealed record ScanOptions(
    Uri Target,
    int TimeoutSeconds = 20,
    bool FollowRedirects = true,
    string UserAgent = "OwaspScanner/1.0");

public sealed record ScanResult(
    Uri Target,
    DateTimeOffset StartedAt,
    DateTimeOffset CompletedAt,
    int StatusCode,
    IReadOnlyList<RiskFinding> Findings,
    IReadOnlyDictionary<string, string> ResponseHeaders,
    long BodyLength)
{
    public TimeSpan Duration => CompletedAt - StartedAt;
}
