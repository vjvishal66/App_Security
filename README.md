# OWASP Top 10 Desktop Scanner (Windows)

A Windows WPF application for **quick website security posture checks** mapped to OWASP Top 10 categories (2025-ready baseline).

> ⚠️ This tool provides lightweight heuristic checks. It is **not** a full penetration testing suite and must be used only against targets you own or are authorized to test.

## Features

- Windows desktop UI (WPF, .NET 8).
- URL-based website scanning with configurable request behavior in code.
- Heuristic checks mapped to OWASP categories:
  - Broken Access Control
  - Cryptographic Failures
  - Injection
  - Insecure Design
  - Security Misconfiguration
  - Vulnerable and Outdated Components
  - Identification and Authentication Failures
  - Software and Data Integrity Failures
  - Security Logging and Monitoring Failures
  - SSRF
- Findings grid with severity, evidence, and remediation advice.
- JSON report export.

## Project Structure

- `src/OwaspScanner.Core` — scanning engine, models, OWASP mapping.
- `src/OwaspScanner.App` — WPF UI for running scans and exporting reports.
- `OwaspScanner.sln` — solution file.

## Prerequisites

- Windows 10/11
- .NET 8 SDK
- Visual Studio 2022 (recommended) with Desktop Development workload

## Build & Run

```bash
dotnet build OwaspScanner.sln
dotnet run --project src/OwaspScanner.App/OwaspScanner.App.csproj
```

## How It Works

1. The app performs an HTTP GET request to the target URL.
2. It evaluates response headers, status code, body content patterns, and transport scheme.
3. It creates findings with category, rule ID, severity, evidence, and recommendation.
4. Results can be exported to JSON for further triage.

## Example Enhancements

- Add authenticated scanning profiles.
- Add crawling and endpoint discovery.
- Integrate CVE and dependency intelligence feeds.
- Expand rule packs into plugin-based signatures.
- Add CI mode (headless CLI) for DevSecOps pipelines.

## Legal

Use responsibly. Unauthorized scanning may violate law and policy.
