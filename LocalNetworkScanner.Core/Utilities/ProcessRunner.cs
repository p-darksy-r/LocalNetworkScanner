// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Diagnostics;

namespace LocalNetworkScanner.Core.Utilities;

internal static class ProcessRunner
{
    public static async Task<string?> RunAsync(
        string fileName,
        IEnumerable<string> arguments,
        int timeoutMs,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);
        ArgumentNullException.ThrowIfNull(arguments);
        if (timeoutMs <= 0)
            throw new ArgumentOutOfRangeException(nameof(timeoutMs), "O timeout deve ser superior a zero.");

        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            ProcessStartInfo startInfo = new(fileName)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            foreach (string argument in arguments)
                startInfo.ArgumentList.Add(argument);

            using Process process = new() { StartInfo = startInfo };
            if (!process.Start())
                return null;

            using CancellationTokenSource timeout =
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(timeoutMs);

            // Os dois pipes têm de ser drenados em paralelo; caso contrário um processo
            // que escreva muito em stderr pode bloquear antes de terminar.
            Task<string> outputTask = process.StandardOutput.ReadToEndAsync(CancellationToken.None);
            Task<string> errorTask = process.StandardError.ReadToEndAsync(CancellationToken.None);

            try
            {
                await process.WaitForExitAsync(timeout.Token);
            }
            catch (OperationCanceledException)
            {
                TryKillProcessTree(process);
                await DrainAfterTerminationAsync(process, outputTask, errorTask);

                cancellationToken.ThrowIfCancellationRequested();
                return null;
            }

            await Task.WhenAll(outputTask, errorTask);
            string output = await outputTask;
            return process.ExitCode == 0 ? output : null;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }

    private static void TryKillProcessTree(Process process)
    {
        try
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
        }
        catch
        {
            try
            {
                if (!process.HasExited)
                    process.Kill();
            }
            catch
            {
                // O processo pode ter terminado entre a verificação e o Kill.
            }
        }
    }

    private static async Task DrainAfterTerminationAsync(
        Process process,
        Task<string> outputTask,
        Task<string> errorTask)
    {
        try
        {
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(2));
        }
        catch
        {
            // A limpeza é best-effort e não deve mascarar timeout/cancelamento.
        }

        try
        {
            await Task.WhenAll(outputTask, errorTask).WaitAsync(TimeSpan.FromSeconds(2));
        }
        catch
        {
            // Os streams serão fechados ao libertar o Process.
        }
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
