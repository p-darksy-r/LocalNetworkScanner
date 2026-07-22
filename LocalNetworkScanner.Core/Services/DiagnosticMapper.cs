// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.ComponentModel;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

/// <summary>Converte exceções conhecidas num diagnóstico seguro e apresentável.</summary>
public static class DiagnosticMapper
{
    public static ScanDiagnostic FromException(Exception exception, string? target = null)
    {
        ArgumentNullException.ThrowIfNull(exception);

        Exception effective = Unwrap(exception);
        if (effective is IHasScanDiagnostic diagnosticException)
            return diagnosticException.Diagnostic;

        return effective switch
        {
            TaskCanceledException => DiagnosticCatalog.NetworkOperationFailed(target),
            OperationCanceledException => DiagnosticCatalog.OperationCancelled(target),
            UnauthorizedAccessException => DiagnosticCatalog.AccessDenied(target),
            IOException or InvalidDataException => DiagnosticCatalog.FileOperationFailed(target),
            HttpRequestException or SocketException or NetworkInformationException or TimeoutException =>
                DiagnosticCatalog.NetworkOperationFailed(target),
            Win32Exception { NativeErrorCode: 5 } => DiagnosticCatalog.AccessDenied(target),
            Win32Exception win32Exception when IsNetworkError(win32Exception.NativeErrorCode) =>
                DiagnosticCatalog.NetworkOperationFailed(target),
            Win32Exception win32Exception =>
                DiagnosticCatalog.UnexpectedApplicationError(target, win32Exception.GetType().Name),
            _ => DiagnosticCatalog.UnexpectedApplicationError(target, effective.GetType().Name)
        };
    }

    private static bool IsNetworkError(int nativeErrorCode) => nativeErrorCode is
        53 or 64 or 67 or 121 or 1_231 or 1_232 or 1_236 or
        >= 10_050 and <= 10_065;

    private static Exception Unwrap(Exception exception)
    {
        Exception current = exception;
        while (current is AggregateException { InnerExceptions.Count: 1 } aggregate)
            current = aggregate.InnerExceptions[0];
        return current;
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
