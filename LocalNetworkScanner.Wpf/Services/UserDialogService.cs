// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Wpf.Services;

public sealed class UserDialogService
{
    public string? ChooseExportPath(string title, string defaultFileName, string filter)
    {
        SaveFileDialog dialog = new()
        {
            Title = title,
            FileName = defaultFileName,
            Filter = filter,
            AddExtension = true,
            OverwritePrompt = true,
            CheckPathExists = true
        };

        return dialog.ShowDialog(Application.Current.MainWindow) == true
            ? dialog.FileName
            : null;
    }

    public bool Confirm(string title, string message) =>
        MessageBox.Show(
            Application.Current.MainWindow,
            message,
            title,
            MessageBoxButton.YesNo,
            MessageBoxImage.Question,
            MessageBoxResult.No) == MessageBoxResult.Yes;

    public void ShowError(string title, string message) =>
        MessageBox.Show(
            Application.Current.MainWindow,
            message,
            title,
            MessageBoxButton.OK,
            MessageBoxImage.Error);

    public void ShowDiagnostic(string title, ScanDiagnostic diagnostic)
    {
        ArgumentNullException.ThrowIfNull(diagnostic);

        StringBuilder message = new();
        message.Append('[').Append(diagnostic.Code).Append("] ")
            .Append(GetCategoryLabel(diagnostic.Category)).Append(" · ")
            .AppendLine(GetSeverityLabel(diagnostic.Severity))
            .AppendLine()
            .AppendLine(diagnostic.Message)
            .AppendLine()
            .Append("O que fazer: ").Append(diagnostic.RecommendedAction);
        if (!string.IsNullOrWhiteSpace(diagnostic.Target))
            message.AppendLine().Append("Alvo: ").Append(diagnostic.Target);

        MessageBox.Show(
            Application.Current.MainWindow,
            message.ToString(),
            title,
            MessageBoxButton.OK,
            diagnostic.Severity is DiagnosticSeverity.Information
                ? MessageBoxImage.Information
                : diagnostic.Severity is DiagnosticSeverity.Warning
                    ? MessageBoxImage.Warning
                    : MessageBoxImage.Error);
    }

    public bool TryCopyText(string text)
    {
        try
        {
            Clipboard.SetText(text);
            return true;
        }
        catch (Exception exception) when (
            exception is COMException or ExternalException)
        {
            return false;
        }
    }

    private static string GetCategoryLabel(DiagnosticCategory category) => category switch
    {
        DiagnosticCategory.User => "Utilizador",
        DiagnosticCategory.Network => "Rede",
        DiagnosticCategory.Device => "Dispositivo/dados",
        DiagnosticCategory.Application => "Aplicação",
        _ => "Desconhecida"
    };

    private static string GetSeverityLabel(DiagnosticSeverity severity) => severity switch
    {
        DiagnosticSeverity.Information => "Informação",
        DiagnosticSeverity.Warning => "Aviso",
        DiagnosticSeverity.Error => "Erro",
        DiagnosticSeverity.Critical => "Erro crítico",
        _ => "Desconhecido"
    };
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
