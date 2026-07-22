// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Collections.ObjectModel;
using System.Text.RegularExpressions;

namespace LocalNetworkScanner.Core.Models;

/// <summary>
/// Contrato comum para avisos recuperáveis e erros fatais apresentados ao utilizador.
/// </summary>
public sealed partial class ScanDiagnostic
{
    private const int MaximumTextLength = 512;

    public ScanDiagnostic(
        string code,
        DiagnosticCategory category,
        DiagnosticSeverity severity,
        string message,
        string recommendedAction,
        string? target = null,
        IReadOnlyDictionary<string, string>? context = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        ArgumentException.ThrowIfNullOrWhiteSpace(message);
        ArgumentException.ThrowIfNullOrWhiteSpace(recommendedAction);

        string normalizedCode = code.Trim().ToUpperInvariant();
        if (!DiagnosticCodeRegex().IsMatch(normalizedCode))
            throw new ArgumentException("O código de diagnóstico não segue o formato LNS-CAT-NNN.", nameof(code));
        string expectedPrefix = category switch
        {
            DiagnosticCategory.User => "LNS-USR-",
            DiagnosticCategory.Network => "LNS-NET-",
            DiagnosticCategory.Device => "LNS-DEV-",
            DiagnosticCategory.Application => "LNS-APP-",
            _ => throw new ArgumentOutOfRangeException(nameof(category), category, "Categoria inválida.")
        };
        if (!normalizedCode.StartsWith(expectedPrefix, StringComparison.Ordinal))
            throw new ArgumentException("O prefixo do código não corresponde à categoria.", nameof(code));
        if (!Enum.IsDefined(severity))
            throw new ArgumentOutOfRangeException(nameof(severity), severity, "Severidade inválida.");

        Code = normalizedCode;
        Category = category;
        Severity = severity;
        Message = SanitizeText(message);
        RecommendedAction = SanitizeText(recommendedAction);
        Target = string.IsNullOrWhiteSpace(target) ? null : SanitizePotentialSecrets(target);
        Context = SanitizeContext(context);
    }

    public string Code { get; }

    public DiagnosticCategory Category { get; }

    public DiagnosticSeverity Severity { get; }

    public string Message { get; }

    public string RecommendedAction { get; }

    public string? Target { get; }

    public IReadOnlyDictionary<string, string> Context { get; }

    public bool IsFatal => Severity is DiagnosticSeverity.Error or DiagnosticSeverity.Critical;

    private static IReadOnlyDictionary<string, string> SanitizeContext(
        IReadOnlyDictionary<string, string>? context)
    {
        if (context is null || context.Count == 0)
            return ReadOnlyDictionary<string, string>.Empty;

        Dictionary<string, string> safe = new(StringComparer.OrdinalIgnoreCase);
        foreach ((string key, string value) in context)
        {
            if (string.IsNullOrWhiteSpace(key) || IsSensitiveKey(key))
                continue;

            safe[SanitizeText(key)] = SanitizePotentialSecrets(value ?? string.Empty);
        }

        return new ReadOnlyDictionary<string, string>(safe);
    }

    private static bool IsSensitiveKey(string key)
    {
        string normalized = new(key.Where(char.IsLetterOrDigit).ToArray());
        return normalized.Contains("password", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("secret", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("token", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("community", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("credential", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("authorization", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("apikey", StringComparison.OrdinalIgnoreCase);
    }

    private static string SanitizeText(string value)
    {
        string singleLine = new(value
            .Select(character => char.IsControl(character) ? ' ' : character)
            .ToArray());
        singleLine = singleLine.Trim();
        return singleLine.Length <= MaximumTextLength
            ? singleLine
            : singleLine[..MaximumTextLength];
    }

    private static string SanitizePotentialSecrets(string value)
    {
        string sanitized = SanitizeText(value);
        sanitized = UriUserInfoRegex().Replace(
            sanitized,
            match => $"{match.Groups["scheme"].Value}<redacted>:<redacted>@");
        return SensitiveAssignmentRegex().Replace(
            sanitized,
            match =>
                $"{match.Groups["prefix"].Value}{match.Groups["key"].Value}" +
                $"{match.Groups["separator"].Value}<redacted>");
    }

    [GeneratedRegex(@"^LNS-(?:USR|NET|DEV|APP)-\d{3}$", RegexOptions.CultureInvariant)]
    private static partial Regex DiagnosticCodeRegex();

    [GeneratedRegex(
        @"(?<scheme>\b[a-z][a-z0-9+.-]*://)[^/\s:@]+:[^@/\s]+@",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UriUserInfoRegex();

    [GeneratedRegex(
        """(?<prefix>^|[?&;\s])(?<key>-{0,2}(?:password|passwd|pwd|secret|token|community|credential|authorization|api[-_]?key))(?<separator>\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^&;]+)""",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SensitiveAssignmentRegex();
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
