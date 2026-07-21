using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Windows;

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
}
