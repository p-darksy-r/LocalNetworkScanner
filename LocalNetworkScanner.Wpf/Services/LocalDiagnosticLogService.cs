// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Wpf.Services;

/// <summary>
/// Regista apenas metadados técnicos de falhas fatais. Mensagens, argumentos e
/// identificadores de rede são deliberadamente excluídos para evitar que uma
/// community SNMP, IP, MAC ou hostname termine num relatório de suporte.
/// </summary>
public sealed class LocalDiagnosticLogService
{
    private const long MaximumLogBytes = 512 * 1024;
    private const int MaximumStackLength = 12_000;
    private static readonly Lock FileGate = new();
    private static readonly UTF8Encoding Utf8WithoutBom = new(false);

    private readonly string _directory;

    public LocalDiagnosticLogService(string? directory = null)
    {
        _directory = directory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LocalNetworkScanner",
            "logs");
    }

    public string LogPath => Path.Combine(_directory, "app.log");

    public void TryWriteUnhandled(
        DiagnosticLogSource source,
        Exception exception,
        ScanDiagnostic diagnostic,
        bool processTerminating)
    {
        ArgumentNullException.ThrowIfNull(exception);
        ArgumentNullException.ThrowIfNull(diagnostic);

        try
        {
            string entry = BuildEntry(source, exception, diagnostic, processTerminating);
            lock (FileGate)
            {
                Directory.CreateDirectory(_directory);
                RotateIfNeeded(Utf8WithoutBom.GetByteCount(entry));
                File.AppendAllText(LogPath, entry, Utf8WithoutBom);
            }
        }
        catch (Exception writeException) when (IsRecoverable(writeException))
        {
            // Uma falha no relatório nunca deve esconder ou substituir a falha original.
        }
    }

    private static string BuildEntry(
        DiagnosticLogSource source,
        Exception exception,
        ScanDiagnostic diagnostic,
        bool processTerminating)
    {
        Exception effective = Unwrap(exception);
        string stack = new StackTrace(effective, false).ToString();
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrWhiteSpace(userProfile))
        {
            stack = stack.Replace(
                userProfile,
                "%USERPROFILE%",
                StringComparison.OrdinalIgnoreCase);
        }

        stack = stack.Length <= MaximumStackLength
            ? stack
            : stack[..MaximumStackLength];

        StringBuilder builder = new();
        builder.AppendLine("--- Local Network Scanner unhandled diagnostic ---");
        builder.Append("TimestampUtc: ").AppendLine(DateTimeOffset.UtcNow.ToString("O"));
        builder.Append("Version: ").AppendLine(
            typeof(LocalDiagnosticLogService).Assembly.GetName().Version?.ToString(3) ?? "unknown");
        builder.Append("OS: ").AppendLine(RuntimeInformation.OSDescription);
        builder.Append("Architecture: ").AppendLine(RuntimeInformation.ProcessArchitecture.ToString());
        builder.Append("Source: ").AppendLine(source.ToString());
        builder.Append("ProcessTerminating: ").AppendLine(
            processTerminating ? "true" : "false");
        builder.Append("DiagnosticCode: ").AppendLine(diagnostic.Code);
        builder.Append("DiagnosticCategory: ").AppendLine(diagnostic.Category.ToString());
        builder.Append("DiagnosticSeverity: ").AppendLine(diagnostic.Severity.ToString());
        builder.Append("ExceptionType: ").AppendLine(effective.GetType().FullName ?? effective.GetType().Name);
        builder.Append("HResult: 0x").AppendLine(
            effective.HResult.ToString("X8", CultureInfo.InvariantCulture));
        builder.AppendLine("StackTrace:");
        builder.AppendLine(stack);
        return builder.ToString();
    }

    private void RotateIfNeeded(long additionalBytes)
    {
        FileInfo current = new(LogPath);
        if (!current.Exists || current.Length + additionalBytes <= MaximumLogBytes)
            return;

        string previous = Path.Combine(_directory, "app.previous.log");
        File.Move(LogPath, previous, overwrite: true);
    }

    private static Exception Unwrap(Exception exception)
    {
        Exception current = exception;
        while (current is AggregateException { InnerExceptions.Count: 1 } aggregate)
            current = aggregate.InnerExceptions[0];
        return current;
    }

    private static bool IsRecoverable(Exception exception) =>
        exception is not OutOfMemoryException and not StackOverflowException and not AccessViolationException;

}

public enum DiagnosticLogSource
{
    WpfDispatcher,
    AppDomain,
    TaskScheduler
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
