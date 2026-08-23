// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Buffers.Binary;
using System.ComponentModel;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Formats.Asn1;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using LocalNetworkScanner.Core.Models;
using LocalNetworkScanner.Core.Services;
using LocalNetworkScanner.Core.Utilities;
using LocalNetworkScanner.Wpf;
using LocalNetworkScanner.Wpf.Controls;
using LocalNetworkScanner.Wpf.Infrastructure;
using LocalNetworkScanner.Wpf.Services;
using LocalNetworkScanner.Wpf.ViewModels;

if (args.Contains("--render-doc-images", StringComparer.OrdinalIgnoreCase))
{
    string imageDirectory = Path.Combine(Environment.CurrentDirectory, "docs", "images");
    await RunOnSta(() => DocumentationScreenshotRenderer.Render(imageDirectory));
    Console.WriteLine($"Imagens da documentação atualizadas em: {imageDirectory}");
    return 0;
}

List<(string Name, Func<Task> Run)> tests =
[
    ("IPv4 round-trip", () => Sync(() =>
    {
        IPAddress address = IPAddress.Parse("192.168.42.17");
        Equal(address, IpAddressHelper.FromUInt32(IpAddressHelper.ToUInt32(address)));
    })),
    ("CIDR and subnet", () => Sync(() =>
    {
        (IPAddress address, int prefix) = IpAddressHelper.ParseCidr("192.168.42.123/24");
        Equal(IPAddress.Parse("192.168.42.123"), address);
        Equal(24, prefix);
        Equal(IPAddress.Parse("192.168.42.0"),
            IpAddressHelper.GetNetworkAddress(address, IpAddressHelper.PrefixToMask(prefix)));
    })),
    ("Usable range", () => Sync(() =>
    {
        IReadOnlyList<IPAddress> range = new IpRangeService().GenerateFromCidr("10.4.0.0/30");
        Equal(2, range.Count);
        Equal("10.4.0.1", range[0].ToString());
        Equal("10.4.0.2", range[1].ToString());
        Throws<ArgumentOutOfRangeException>(() =>
            new IpRangeService().GenerateFromCidr("10.4.0.0/30", maximumAddresses: 0));
    })),
    ("Public target rejected", () => Sync(() =>
    {
        Throws<InvalidOperationException>(() =>
            ScanRequestValidator.Validate([IPAddress.Parse("8.8.8.8")], ScanOptions.ForProfile(ScanProfile.Quick)));
    })),
    ("Port specification", () => Sync(() =>
    {
        Equal("22,80,81,82,443", string.Join(',', ServiceCatalog.ParsePortSpecification("443,80-82,22")));
        Throws<FormatException>(() => ServiceCatalog.ParsePortSpecification("0,70000"));
    })),
    ("Desktop Web actions accept only explicit HTTP or HTTPS addresses", () => Sync(() =>
    {
        DesktopActionService actions = new();
        Throws<ArgumentNullException>(() => actions.OpenUri(null!));
        Throws<InvalidOperationException>(() =>
            actions.OpenUri(new Uri("relative/path", UriKind.Relative)));
        Throws<InvalidOperationException>(() =>
            actions.OpenUri(new Uri("ftp://example.invalid/resource", UriKind.Absolute)));
    })),
    ("Scan workload classifies attempts and deduplicates ports", () => Sync(() =>
    {
        ScanWorkloadEstimate normal = ScanWorkloadEstimator.Estimate(
            4,
            new ScanOptions
            {
                DiscoveryPorts = [80, 80, 443],
                Ports = [22, 22, 80]
            });
        Equal(4, normal.AddressCount);
        Equal(2, normal.DiscoveryPortCount);
        Equal(2, normal.FullPortCount);
        Equal(8L, normal.MaximumDiscoveryTcpAttempts);
        Equal(8L, normal.MaximumFullTcpAttempts);
        Equal(8L, normal.MaximumServiceProbeAttempts);
        Equal(NetworkScannerService.MaximumUpnpEnrichmentAttempts,
            normal.MaximumUpnpDescriptionAttempts);
        Equal(56L, normal.MaximumBuiltInTcpAttempts);
        Equal(false, normal.HasAdditionalNmapTraffic);
        Equal(ScanWorkloadLevel.Normal, normal.Level);
        Equal(false, normal.RequiresExplicitConfirmation);

        ScanWorkloadEstimate high = ScanWorkloadEstimator.Estimate(
            1_000,
            new ScanOptions
            {
                EnableTcpDiscovery = false,
                EnableServiceProbes = false,
                Ports = Enumerable.Range(1, 1_000).ToArray()
            });
        Equal(0, high.DiscoveryPortCount);
        Equal(1_000_032L, high.MaximumBuiltInTcpAttempts);
        Equal(ScanWorkloadLevel.High, high.Level);
        Equal(true, high.RequiresExplicitConfirmation);

        ScanWorkloadEstimate extreme = ScanWorkloadEstimator.Estimate(
            1_000,
            new ScanOptions
            {
                EnableTcpDiscovery = false,
                EnableServiceProbes = false,
                Ports = Enumerable.Range(1, 10_000).ToArray()
            });
        Equal(10_000_032L, extreme.MaximumBuiltInTcpAttempts);
        Equal(ScanWorkloadLevel.Extreme, extreme.Level);

        ScanWorkloadEstimate extremeByPortCount = ScanWorkloadEstimator.Estimate(
            1,
            new ScanOptions
            {
                EnableTcpDiscovery = false,
                Ports = Enumerable.Range(1, 16_384).ToArray()
            });
        Equal(16_384, extremeByPortCount.FullPortCount);
        Equal(ScanWorkloadLevel.Extreme, extremeByPortCount.Level);

        ScanWorkloadEstimate icmpOnly = ScanWorkloadEstimator.Estimate(
            65_536,
            new ScanOptions
            {
                EnableIcmp = true,
                EnableTcpDiscovery = false,
                EnableMulticastDiscovery = false,
                EnableNmapDiscovery = true,
                DiscoveryPorts = [80, 443],
                Ports = []
            });
        Equal(0L, icmpOnly.MaximumBuiltInTcpAttempts);
        Equal(true, icmpOnly.HasAdditionalNmapTraffic);
        Equal(ScanWorkloadLevel.Normal, icmpOnly.Level);
        Equal(false, icmpOnly.RequiresExplicitConfirmation);

        ScanWorkloadEstimate upnpOnly = ScanWorkloadEstimator.Estimate(
            1,
            new ScanOptions
            {
                EnableTcpDiscovery = false,
                EnableServiceProbes = false,
                EnableMulticastDiscovery = true,
                EnableUpnpDescription = true,
                Ports = []
            });
        Equal(NetworkScannerService.MaximumUpnpEnrichmentAttempts,
            upnpOnly.MaximumUpnpDescriptionAttempts);
        Equal((long)NetworkScannerService.MaximumUpnpEnrichmentAttempts,
            upnpOnly.MaximumBuiltInTcpAttempts);

        Throws<ArgumentOutOfRangeException>(() =>
            ScanWorkloadEstimator.Estimate(-1, new ScanOptions()));
    })),
    ("ICMP source binding rejects invalid routes without fallback", async () =>
    {
        PingScannerService scanner = new();

        PingProbeResult incompatibleSource = await scanner.ProbeAsync(
            IPAddress.Loopback,
            timeoutMs: 50,
            IPAddress.IPv6Loopback,
            CancellationToken.None);
        Equal(false, incompatibleSource.Success);
        Equal<long?>(null, incompatibleSource.RoundtripTimeMs);
        Equal<int?>(null, incompatibleSource.ReplyTtl);

        if (OperatingSystem.IsWindows())
        {
            PingProbeResult loopback = await scanner.ProbeAsync(
                IPAddress.Loopback,
                timeoutMs: 1_000,
                IPAddress.Loopback,
                CancellationToken.None);
            Equal(loopback.Success, loopback.RoundtripTimeMs.HasValue);
            Equal(loopback.Success, loopback.ReplyTtl.HasValue);
        }

        await ThrowsAsync<ArgumentNullException>(() =>
            scanner.ProbeAsync(
                null!,
                timeoutMs: 50,
                IPAddress.Loopback,
                CancellationToken.None));
        await ThrowsAsync<ArgumentOutOfRangeException>(() =>
            scanner.ProbeAsync(
                IPAddress.Loopback,
                timeoutMs: 0,
                IPAddress.Loopback,
                CancellationToken.None));

        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();
        await ThrowsAsync<OperationCanceledException>(() =>
            scanner.ProbeAsync(
                IPAddress.Loopback,
                timeoutMs: 50,
                IPAddress.Loopback,
                cancellation.Token));

        MethodInfo? sourceBoundOverload = typeof(PingScannerService).GetMethod(
            nameof(PingScannerService.ProbeAsync),
            [
                typeof(IPAddress),
                typeof(int),
                typeof(IPAddress),
                typeof(CancellationToken)
            ]);
        NotNull(sourceBoundOverload);
        Equal("sourceAddress", sourceBoundOverload!.GetParameters()[2].Name);
    }),
    ("Diagnostic contract and sanitization", () => Sync(() =>
    {
        ScanDiagnostic diagnostic = new(
            "lns-dev-099",
            DiagnosticCategory.Device,
            DiagnosticSeverity.Warning,
            "MAC inválido\nrecebido",
            "Confirma a tabela ARP.",
            "192.168.1.20",
            new Dictionary<string, string>
            {
                ["mac"] = "00:11:22:33:44:55",
                ["community"] = "private-value",
                ["password"] = "private-value",
                ["token"] = "private-value"
            });

        Equal("LNS-DEV-099", diagnostic.Code);
        Equal("MAC inválido recebido", diagnostic.Message);
        Equal(1, diagnostic.Context.Count);
        Equal("00:11:22:33:44:55", diagnostic.Context["mac"]);
        True(!diagnostic.Context.ContainsKey("community"), "A community SNMP não pode aparecer no contexto.");
        Throws<ArgumentException>(() => _ = new ScanDiagnostic(
            "LNS-APP-099",
            DiagnosticCategory.User,
            DiagnosticSeverity.Error,
            "Inválido",
            "Corrigir"));

        ScanDiagnostic redacted = new(
            "LNS-APP-098",
            DiagnosticCategory.Application,
            DiagnosticSeverity.Error,
            "Falha segura.",
            "Corrigir.",
            "--token=example-secret",
            new Dictionary<string, string>
            {
                ["endpoint"] = "https://alice:password@example.invalid/path?api_key=secret-key",
                ["api_key"] = "also-secret"
            });
        Equal("--token=<redacted>", redacted.Target);
        Equal(
            "https://<redacted>:<redacted>@example.invalid/path?api_key=<redacted>",
            redacted.Context["endpoint"]);
        True(!redacted.Context.ContainsKey("api_key"), "Uma API key não pode aparecer no contexto.");
    })),
    ("Local diagnostic log excludes private network details", () => Sync(() =>
    {
        string directory = Path.Combine(
            Path.GetTempPath(),
            "LocalNetworkScanner.Tests",
            Guid.NewGuid().ToString("N"));
        const string exceptionMessage = "exception-message-secret-c57978";
        const string diagnosticMessage = "diagnostic-message-secret-40e219";
        const string target = "target-secret-cfa552";
        const string ipAddress = "198.51.100.243";
        const string macAddress = "02:AA:BB:CC:DD:91";
        const string community = "community-private-780b65";
        const string hostname = "edge-private-40f6.example.invalid";
        string networkEvidence = $"{ipAddress}|{macAddress}|{community}|{hostname}";

        try
        {
            ScanDiagnostic diagnostic = new(
                "LNS-APP-097",
                DiagnosticCategory.Application,
                DiagnosticSeverity.Critical,
                diagnosticMessage,
                "recommended-action-secret-bab87a",
                target,
                new Dictionary<string, string>
                {
                    ["networkEvidence"] = networkEvidence,
                    ["community"] = community
                });
            Equal(target, diagnostic.Target);
            Equal(networkEvidence, diagnostic.Context["networkEvidence"]);

            LocalDiagnosticLogService service = new(directory);
            Exception exception = CaptureException(exceptionMessage);
            service.TryWriteUnhandled(
                DiagnosticLogSource.WpfDispatcher,
                exception,
                diagnostic,
                processTerminating: true);
            service.TryWriteUnhandled(
                DiagnosticLogSource.TaskScheduler,
                exception,
                diagnostic,
                processTerminating: false);

            string log = File.ReadAllText(service.LogPath);
            string[] entries = log.Split(
                "--- Local Network Scanner unhandled diagnostic ---",
                StringSplitOptions.RemoveEmptyEntries);
            Equal(2, entries.Length);
            True(entries[0].Contains("Source: WpfDispatcher", StringComparison.Ordinal),
                "A primeira entrada deve identificar a origem WPF Dispatcher.");
            True(entries[0].Contains("ProcessTerminating: true", StringComparison.Ordinal),
                "A primeira entrada deve preservar o indicador de terminação.");
            True(entries[1].Contains("Source: TaskScheduler", StringComparison.Ordinal),
                "A segunda entrada deve identificar a origem TaskScheduler.");
            True(entries[1].Contains("ProcessTerminating: false", StringComparison.Ordinal),
                "A segunda entrada deve preservar o indicador não terminante.");

            foreach (string privateValue in new[]
                     {
                         exceptionMessage,
                         diagnosticMessage,
                         target,
                         networkEvidence,
                         ipAddress,
                         macAddress,
                         community,
                         hostname
                     })
            {
                True(!log.Contains(privateValue, StringComparison.Ordinal),
                    $"O log técnico não pode incluir o valor privado '{privateValue}'.");
            }
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    })),
    ("Local diagnostic log rotates within its bounded contract", () => Sync(() =>
    {
        string directory = Path.Combine(
            Path.GetTempPath(),
            "LocalNetworkScanner.Tests",
            Guid.NewGuid().ToString("N"));

        try
        {
            Directory.CreateDirectory(directory);
            LocalDiagnosticLogService service = new(directory);
            FieldInfo? maximumLogBytesField = typeof(LocalDiagnosticLogService).GetField(
                "MaximumLogBytes",
                BindingFlags.Static | BindingFlags.NonPublic);
            NotNull(maximumLogBytesField);
            long maximumLogBytes = (long)maximumLogBytesField!.GetRawConstantValue()!;
            byte[] existingLog = new byte[checked((int)maximumLogBytes - 1)];
            byte[] sentinel = Encoding.ASCII.GetBytes("existing-log-before-rotation");
            sentinel.CopyTo(existingLog, 0);
            File.WriteAllBytes(service.LogPath, existingLog);

            ScanDiagnostic diagnostic = new(
                "LNS-APP-096",
                DiagnosticCategory.Application,
                DiagnosticSeverity.Error,
                "Falha técnica controlada.",
                "Reinicia a aplicação.");
            service.TryWriteUnhandled(
                DiagnosticLogSource.AppDomain,
                CaptureException("rotation-trigger"),
                diagnostic,
                processTerminating: true);

            string previousPath = Path.Combine(directory, "app.previous.log");
            True(File.Exists(previousPath), "O log anterior deve existir depois da rotação.");
            Equal(maximumLogBytes - 1, new FileInfo(previousPath).Length);
            True(new FileInfo(service.LogPath).Length <= maximumLogBytes,
                "O log atual não pode ultrapassar o limite configurado.");
            True(new FileInfo(previousPath).Length <= maximumLogBytes,
                "O log anterior não pode ultrapassar o limite configurado.");
            Equal(2, Directory.GetFiles(directory, "app*.log").Length);

            byte[] previousPrefix = File.ReadAllBytes(previousPath)[..sentinel.Length];
            True(previousPrefix.AsSpan().SequenceEqual(sentinel),
                "A rotação deve mover o conteúdo anterior sem o substituir.");
            True(File.ReadAllText(service.LogPath).Contains("Source: AppDomain", StringComparison.Ordinal),
                "A nova entrada deve ser escrita no log atual depois da rotação.");
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    })),
    ("Fatal shutdown bypasses prompts and settings persistence", () => Sync(() =>
    {
        MethodInfo? prepareMethod = typeof(MainWindow).GetMethod(
            "PrepareForFatalShutdown",
            BindingFlags.Instance | BindingFlags.NonPublic);
        NotNull(prepareMethod);
        Equal(typeof(void), prepareMethod!.ReturnType);
        Equal(0, prepareMethod.GetParameters().Length);

        FieldInfo? fatalFlag = typeof(MainWindow).GetField(
            "_isFatalShutdown",
            BindingFlags.Instance | BindingFlags.NonPublic);
        NotNull(fatalFlag);
        Equal(typeof(bool), fatalFlag!.FieldType);

        string source = File.ReadAllText(FindRepositoryFile(
            "LocalNetworkScanner.Wpf",
            "MainWindow.xaml.cs"));
        string compact = string.Concat(source.Where(character => !char.IsWhiteSpace(character)));
        string viewModelSource = File.ReadAllText(FindRepositoryFile(
            "LocalNetworkScanner.Wpf",
            "ViewModels",
            "MainViewModel.cs"));
        string compactViewModel = string.Concat(
            viewModelSource.Where(character => !char.IsWhiteSpace(character)));
        int onClosing = compact.IndexOf("privatevoidOnClosing(", StringComparison.Ordinal);
        int savingGuard = compact.IndexOf(
            "if(!_isFatalShutdown&&ViewModel.IsSavingDeviceMetadata)",
            onClosing,
            StringComparison.Ordinal);
        int savingCancel = compact.IndexOf("e.Cancel=true;return;", savingGuard, StringComparison.Ordinal);
        int fatalGuard = compact.IndexOf(
            "if(!_isFatalShutdown&&(ViewModel.IsScanning||ViewModel.HasUnsavedDeviceMetadata))",
            onClosing,
            StringComparison.Ordinal);
        int closePrompt = compact.IndexOf("MessageBox.Show(", fatalGuard, StringComparison.Ordinal);
        int completeShutdown = compact.IndexOf(
            "CompleteShutdown(saveSettings:!_isFatalShutdown);",
            closePrompt,
            StringComparison.Ordinal);
        int prepare = compact.IndexOf("internalvoidPrepareForFatalShutdown()", StringComparison.Ordinal);
        int setFatalFlag = compact.IndexOf("_isFatalShutdown=true;", prepare, StringComparison.Ordinal);
        int requestCancellation = compact.IndexOf(
            "ViewModel.RequestCancellation();",
            setFatalFlag,
            StringComparison.Ordinal);
        int completeMethod = compact.IndexOf("privatevoidCompleteShutdown(boolsaveSettings)", StringComparison.Ordinal);
        int guardedSave = compact.IndexOf(
            "if(saveSettings)ViewModel.SaveSettings();",
            completeMethod,
            StringComparison.Ordinal);

        True(onClosing >= 0 && savingGuard > onClosing && savingCancel > savingGuard &&
             fatalGuard > savingCancel && closePrompt > fatalGuard,
            "OnClosing deve esperar pela gravação de metadados antes de avaliar o fecho normal.");
        True(fatalGuard > onClosing && closePrompt > fatalGuard,
            "OnClosing deve proteger scan e metadados por guardar com o estado de falha fatal.");
        True(completeShutdown > closePrompt && completeShutdown < prepare,
            "OnClosing deve desativar a persistência quando a terminação é fatal.");
        True(prepare >= 0 && setFatalFlag > prepare && requestCancellation > setFatalFlag &&
             requestCancellation < completeMethod,
            "PrepareForFatalShutdown deve marcar a terminação antes de cancelar o scan.");
        True(completeMethod >= 0 && guardedSave > completeMethod,
            "CompleteShutdown só deve persistir definições quando explicitamente autorizado.");
        True(compactViewModel.Contains(
                "privateboolCanStartScan()=>!IsScanning&&!IsSavingDeviceMetadata&&",
                StringComparison.Ordinal),
            "Um novo scan deve ficar bloqueado enquanto os metadados são gravados.");
        True(compactViewModel.Contains(
                "()=>!IsScanning&&!IsSavingDeviceMetadata&&Devices.Count>0",
                StringComparison.Ordinal),
            "Limpar resultados deve ficar bloqueado enquanto os metadados são gravados.");
    })),
    ("Installer downgrade guard follows custom local install directories", () => Sync(() =>
    {
        string source = File.ReadAllText(FindRepositoryFile(
            "installer",
            "LocalNetworkScanner.iss"));
        string compact = string.Concat(source.Where(character => !char.IsWhiteSpace(character)));

        int registryResolver = compact.IndexOf(
            "procedureConsiderRegisteredInstallLocation(",
            StringComparison.Ordinal);
        int installLocationRead = compact.IndexOf(
            "RegQueryStringValue(",
            registryResolver,
            StringComparison.Ordinal);
        int localPathValidation = compact.IndexOf(
            "TryNormalizeLocalInstallDirectory(RegisteredDirectory,LocalDirectory)",
            registryResolver,
            StringComparison.Ordinal);
        int registeredExecutableCheck = compact.IndexOf(
            "ConsiderInstalledExecutable(AddBackslash(LocalDirectory)+",
            localPathValidation,
            StringComparison.Ordinal);
        int initialize = compact.IndexOf(
            "functionInitializeSetup():Boolean;",
            StringComparison.Ordinal);
        int hkcu64 = compact.IndexOf(
            "ConsiderRegisteredInstallLocation(HKCU64,",
            initialize,
            StringComparison.Ordinal);
        int hkcu32 = compact.IndexOf(
            "ConsiderRegisteredInstallLocation(HKCU32,",
            hkcu64,
            StringComparison.Ordinal);
        int hkcu = compact.IndexOf(
            "ConsiderRegisteredInstallLocation(HKCU,",
            hkcu32,
            StringComparison.Ordinal);
        int defaultFallback = compact.IndexOf(
            "AddBackslash(ExpandConstant('{#AppInstallDirectory}'))+",
            hkcu,
            StringComparison.Ordinal);

        True(compact.Contains(
                "#defineAppUninstallRegistryKey\"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{4CA46B3E-3522-4E1B-99B7-CBE0A34B5981}_is1\"",
                StringComparison.Ordinal),
            "O guard deve usar o AppId estável para localizar o InstallLocation anterior.");
        True(registryResolver >= 0 && installLocationRead > registryResolver &&
             compact.IndexOf("'InstallLocation'", installLocationRead, StringComparison.Ordinal) > installLocationRead &&
             localPathValidation > installLocationRead && registeredExecutableCheck > localPathValidation,
            "O InstallLocation registado deve ser validado antes de consultar a versão do executável.");
        True(hkcu64 > initialize && hkcu32 > hkcu64 && hkcu > hkcu32 &&
             defaultFallback > hkcu,
            "O guard deve consultar as vistas HKCU 64/32 e manter o diretório predefinido como fallback.");
        True(compact.Contains("(Trimmed[2]<>':')", StringComparison.Ordinal) &&
             compact.Contains("(Trimmed[3]<>'\\')", StringComparison.Ordinal) &&
             compact.Contains("GetDriveTypeW(Copy(Trimmed,1,3))", StringComparison.Ordinal) &&
             compact.Contains("DriveType<>DriveFixed", StringComparison.Ordinal) &&
             compact.Contains("DriveType<>DriveRemovable", StringComparison.Ordinal),
            "O caminho registado deve ser absoluto e pertencer a uma unidade local aceite.");
        True(compact.Contains(
                "ifHasInstalledVersionand(ComparePackedVersion(InstalledVersion,{#AppVersionPacked})>0)then",
                StringComparison.Ordinal),
            "A versão mais recente encontrada deve bloquear apenas um setup mais antigo.");
    })),
    ("Diagnostic mapper preserves origin", () => Sync(() =>
    {
        ScanDiagnostic input = DiagnosticCatalog.InvalidCidr("192.168.1.999/24");
        Equal(input, DiagnosticMapper.FromException(new ScanFormatException(input)));
        Equal(DiagnosticCatalog.FileOperationFailedCode,
            DiagnosticMapper.FromException(new IOException("sensitive detail"), "report.json").Code);
        Equal(DiagnosticCatalog.AccessDeniedCode,
            DiagnosticMapper.FromException(new UnauthorizedAccessException(), "report.json").Code);
        Equal(DiagnosticCatalog.NetworkOperationFailedCode,
            DiagnosticMapper.FromException(new HttpRequestException(), "IEEE OUI").Code);
        Equal(DiagnosticCatalog.NetworkOperationFailedCode,
            DiagnosticMapper.FromException(new TaskCanceledException(), "IEEE OUI").Code);
        Equal(DiagnosticCatalog.NetworkOperationFailedCode,
            DiagnosticMapper.FromException(new TimeoutException(), "192.168.1.20").Code);
        Equal(DiagnosticCatalog.NetworkOperationFailedCode,
            DiagnosticMapper.FromException(new Win32Exception(53), "rede").Code);
        Equal(DiagnosticCatalog.ApplicationControlBlockedCode,
            DiagnosticMapper.FromException(new Win32Exception(4_551), "LocalNetworkScanner.exe").Code);
        Equal(DiagnosticCatalog.OperationCancelledCode,
            DiagnosticMapper.FromException(new OperationCanceledException(), "scan").Code);
        Equal(DiagnosticCatalog.UnexpectedApplicationErrorCode,
            DiagnosticMapper.FromException(new ArgumentException("internal bug"), "motor").Code);
        Equal(DiagnosticCatalog.UnexpectedApplicationErrorCode,
            DiagnosticMapper.FromException(new InvalidProgramException("sensitive detail"), "UI").Code);
    })),
    ("Optional diagnostics preserve scan results", () => Sync(() =>
    {
        NetworkScanResult original = CreateTopologyExportResult();
        ScanDiagnostic warning = DiagnosticCatalog.OptionalFileOperationFailed(
            "histórico local",
            "guardar snapshot");
        NetworkScanResult updated = original.WithAdditionalDiagnostic(warning);

        Equal(original.Devices, updated.Devices);
        Equal(original.Diagnostics.Count + 1, updated.Diagnostics.Count);
        Equal(DiagnosticSeverity.Warning, updated.Diagnostics[^1].Severity);
        Equal(false, updated.Diagnostics[^1].IsFatal);
    })),
    ("Diagnostic catalog has stable unique codes", () => Sync(() =>
    {
        string[] codes = typeof(DiagnosticCatalog)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(field => field.IsLiteral &&
                            field.FieldType == typeof(string) &&
                            field.Name.EndsWith("Code", StringComparison.Ordinal))
            .Select(field => (string)field.GetRawConstantValue()!)
            .ToArray();

        Equal(32, codes.Length);
        Equal(codes.Length, codes.Distinct(StringComparer.Ordinal).Count());
        True(codes.All(code => code.Length == 11 && code.StartsWith("LNS-", StringComparison.Ordinal)),
            "Todos os códigos públicos devem seguir o contrato LNS-CAT-NNN.");
    })),
    ("MAC identity validation", () => Sync(() =>
    {
        True(MacAddressService.TryNormalizeDeviceAddress("00-11-22-33-44-55", out string normalized),
            "Um MAC unicast válido deveria ser aceite.");
        Equal("00:11:22:33:44:55", normalized);
        True(MacAddressService.TryNormalizeDeviceAddress("0011.2233.4455", out normalized),
            "O formato Cisco deveria ser aceite.");
        Equal("00:11:22:33:44:55", normalized);
        True(!MacAddressService.TryNormalizeDeviceAddress("00:00:00:00:00:00", out _), "MAC zero deve ser rejeitado.");
        True(!MacAddressService.TryNormalizeDeviceAddress("FF:FF:FF:FF:FF:FF", out _), "Broadcast deve ser rejeitado.");
        True(!MacAddressService.TryNormalizeDeviceAddress("01:00:5E:00:00:01", out _), "Multicast deve ser rejeitado.");
        True(!MacAddressService.TryNormalizeDeviceAddress("00:11-22:33-44:55", out _), "Separadores mistos devem ser rejeitados.");
        True(!MacAddressService.TryNormalizeDeviceAddress("0:01122334455", out _), "Separadores mal posicionados devem ser rejeitados.");
        True(!MacAddressService.TryNormalizeDeviceAddress("not-a-mac", out _), "Texto arbitrário deve ser rejeitado.");
    })),
    ("UPnP description URLs remain bound to the discovered device", () => Sync(() =>
    {
        IPAddress expectedAddress = IPAddress.Parse("192.168.1.20");

        True(
            UpnpDescriptionService.TryCreateSafeDescriptionUri(
                " http://192.168.1.20:8080/device.xml?profile=1 ",
                expectedAddress,
                out Uri? safeUri),
            "Uma descrição HTTP no mesmo IP privado deveria ser aceite.");
        Equal("http://192.168.1.20:8080/device.xml?profile=1", safeUri!.AbsoluteUri);

        True(!UpnpDescriptionService.TryCreateSafeDescriptionUri(
                "http://192.168.1.21/device.xml",
                expectedAddress,
                out _),
            "A app não pode seguir a descrição para outro host.");
        True(!UpnpDescriptionService.TryCreateSafeDescriptionUri(
                "http://admin:secret@192.168.1.20/device.xml",
                expectedAddress,
                out _),
            "Credenciais incorporadas numa URL UPnP devem ser rejeitadas.");
        True(!UpnpDescriptionService.TryCreateSafeDescriptionUri(
                "http://192.168.1.21/device.xml?next=http://192.168.1.20/",
                expectedAddress,
                out _),
            "Uma URL com aspeto de redirecionamento continua presa ao host efetivo.");
        True(!UpnpDescriptionService.TryCreateSafeDescriptionUri(
                "http://192.168.1.20/device.xml#other-device",
                expectedAddress,
                out _),
            "Fragmentos não são necessários para obter a descrição e devem falhar fechados.");
        True(!UpnpDescriptionService.TryCreateSafeDescriptionUri(
                "file:///C:/device.xml",
                expectedAddress,
                out _),
            "A localização UPnP só pode usar HTTP ou HTTPS.");
        True(!UpnpDescriptionService.TryCreateSafeDescriptionUri(
                "http://device.local/device.xml",
                expectedAddress,
                out _),
            "Um hostname não deve permitir nova resolução DNS fora do IP observado.");
    })),
    ("UPnP XML identity parsing is bounded and entity-safe", () => Sync(() =>
    {
        const string xml = """
            <?xml version="1.0" encoding="utf-8"?>
            <root xmlns="urn:schemas-upnp-org:device-1-0">
              <device>
                <deviceType>urn:schemas-upnp-org:device:Printer:1</deviceType>
                <friendlyName>  Office&#xA; Printer  </friendlyName>
                <manufacturer>Hewlett-Packard</manufacturer>
                <modelName>LaserJet Pro</modelName>
                <modelNumber>M404dn</modelNumber>
                <serialNumber>SN-123</serialNumber>
                <UDN>uuid:printer-1</UDN>
                <presentationURL>/</presentationURL>
              </device>
            </root>
            """;

        UpnpDeviceDescription? description = UpnpDescriptionService.ParseDescription(
            Encoding.UTF8.GetBytes(xml));
        NotNull(description);
        Equal("Office Printer", description!.FriendlyName);
        Equal("Hewlett-Packard", description.Manufacturer);
        Equal("LaserJet Pro (M404dn)", description.Model);
        Equal("SN-123", description.SerialNumber);
        Equal("urn:schemas-upnp-org:device:Printer:1", description.DeviceType);
        Equal("uuid:printer-1", description.UniqueDeviceName);

        const string dtd = """
            <!DOCTYPE root [<!ENTITY external SYSTEM "file:///C:/Windows/win.ini">]>
            <root><device><friendlyName>&external;</friendlyName></device></root>
            """;
        Throws<System.Xml.XmlException>(() =>
            UpnpDescriptionService.ParseDescription(Encoding.UTF8.GetBytes(dtd)));
        Equal<UpnpDeviceDescription?>(null, UpnpDescriptionService.ParseDescription([]));
        Equal<UpnpDeviceDescription?>(
            null,
            UpnpDescriptionService.ParseDescription(new byte[(256 * 1024) + 1]));
        Equal<UpnpDeviceDescription?>(
            null,
            UpnpDescriptionService.ParseDescription(
                Encoding.UTF8.GetBytes("<root><device><UDN>uuid:only</UDN></device></root>")));
    })),
    ("Multicast promotion and UPnP enrichment are bounded", () => Sync(() =>
    {
        IPAddress address = IPAddress.Parse("192.168.1.20");
        DiscoveryObservation announcedMdns = new()
        {
            IpAddress = address,
            Method = DiscoveryMethod.Mdns,
            HasDirectAddressEvidence = false
        };
        DiscoveryObservation directMdns = new()
        {
            IpAddress = address,
            Method = DiscoveryMethod.Mdns,
            HasDirectAddressEvidence = true
        };
        DiscoveryObservation ssdp = new()
        {
            IpAddress = address,
            Method = DiscoveryMethod.Ssdp,
            Location = $"http://{address}/device.xml"
        };

        True(!NetworkScannerService.CanPromoteMulticastObservation(announcedMdns),
            "Um endereço apenas anunciado por mDNS não pode criar um dispositivo online.");
        True(NetworkScannerService.CanPromoteMulticastObservation(directMdns),
            "Um datagrama mDNS vindo do próprio endereço pode confirmar a observação.");
        True(NetworkScannerService.CanPromoteMulticastObservation(ssdp),
            "Uma resposta SSDP é associada ao endereço UDP que respondeu.");

        DiscoveryObservation[] flood = Enumerable.Range(0, 40)
            .Select(index => new DiscoveryObservation
            {
                IpAddress = address,
                Method = DiscoveryMethod.Ssdp,
                Location = $"http://{address}/device-{index}.xml"
            })
            .ToArray();
        Equal(
            NetworkScannerService.MaximumUpnpEnrichmentAttempts,
            NetworkScannerService.SelectUpnpEnrichmentCandidates(flood).Count);

        DiscoveryObservation enriched = UpnpDescriptionService.CreateEnrichedObservation(
            ssdp,
            new UpnpDeviceDescription
            {
                Manufacturer = "Contoso",
                Model = "Self-reported"
            });
        Equal(ConfidenceLevel.Medium, enriched.Confidence);

        MulticastReceiveBudget budget = new(2, 10, 3);
        True(budget.TryConsumeDatagram(6), "O primeiro datagrama cabe no orçamento.");
        True(!budget.TryConsumeDatagram(5), "O orçamento total de bytes deve ser aplicado.");
        True(budget.TryConsumeDatagram(4), "O segundo datagrama completa o orçamento.");
        True(!budget.TryConsumeDatagram(0), "O limite total de datagramas deve ser aplicado.");
        True(budget.TryConsumeItems(3), "Os itens dentro do limite devem ser aceites.");
        True(!budget.TryConsumeItems(1), "O limite total de itens deve ser aplicado.");
    })),
    ("Multicast retransmissions obey budget and cancellation", async () =>
    {
        using UdpClient receiver = new(
            new IPEndPoint(IPAddress.Loopback, 0));
        using UdpClient sender = new(AddressFamily.InterNetwork);
        IPEndPoint destination = (IPEndPoint)receiver.Client.LocalEndPoint!;
        byte[] payload = [0x4C, 0x4E, 0x53];
        MulticastSendBudget budget = new(
            MulticastProbeTransmitter.DefaultMaximumTransmissions);

        True(
            await MulticastProbeTransmitter.SendAsync(
                sender,
                payload,
                destination,
                budget,
                CancellationToken.None),
            "A sonda inicial deveria consumir o primeiro envio.");
        await MulticastProbeTransmitter.RetransmitAsync(
            sender,
            payload,
            destination,
            timeoutMs: 1,
            budget,
            CancellationToken.None);

        Equal(3, budget.DatagramsConsumed);
        True(
            !await MulticastProbeTransmitter.SendAsync(
                sender,
                payload,
                destination,
                budget,
                CancellationToken.None),
            "O quarto envio deve ser recusado pelo orçamento.");
        Equal(3, budget.DatagramsConsumed);

        using CancellationTokenSource receiveTimeout = new(TimeSpan.FromSeconds(1));
        for (int index = 0; index < 3; index++)
        {
            UdpReceiveResult datagram = await receiver.ReceiveAsync(receiveTimeout.Token);
            Equal("LNS", Encoding.ASCII.GetString(datagram.Buffer));
        }

        MulticastSendBudget cancelledBudget = new(
            MulticastProbeTransmitter.DefaultMaximumTransmissions);
        True(
            await MulticastProbeTransmitter.SendAsync(
                sender,
                payload,
                destination,
                cancelledBudget,
                CancellationToken.None),
            "A sonda anterior ao cancelamento deveria ser enviada.");
        using CancellationTokenSource cancelled = new();
        cancelled.Cancel();
        await MulticastProbeTransmitter.RetransmitAsync(
            sender,
            payload,
            destination,
            timeoutMs: 1,
            cancelledBudget,
            cancelled.Token);
        Equal(1, cancelledBudget.DatagramsConsumed);
    }),
    ("Device identity evidence merges by confidence without duplicates", () => Sync(() =>
    {
        NetworkDevice device = new() { IpAddress = IPAddress.Parse("192.168.1.20") };
        DeviceIdentityService identity = new();

        identity.AddMacVendor(device, new MacVendorMatch(
            "Acme Networks",
            "MA-L",
            "001122",
            24,
            "incorporada",
            IsPrivate: false));
        Equal("Acme Networks", device.Manufacturer);
        Equal("Acme Networks", device.MacAssignee);
        Equal("MA-L", device.MacRegistry);
        Equal("001122/24", device.MacAssignmentPrefix);
        Equal(ConfidenceLevel.Medium, device.IdentityConfidence);

        identity.AddObservation(device, new DiscoveryObservation
        {
            IpAddress = device.IpAddress,
            Method = DiscoveryMethod.Ssdp,
            Manufacturer = "Untrusted announcement",
            Model = "Basic model",
            FriendlyName = "  Office\n Device  ",
            EvidenceSource = "SSDP",
            Confidence = ConfidenceLevel.Low
        });
        Equal("Acme Networks", device.Manufacturer);
        Equal("Basic model", device.Model);
        Equal("Office Device", device.FriendlyName);
        Equal(ConfidenceLevel.Low, device.IdentityConfidence);

        DiscoveryObservation highConfidence = new()
        {
            IpAddress = device.IpAddress,
            Method = DiscoveryMethod.Snmp,
            Manufacturer = "  Acme Enterprise  ",
            Model = "CoreSwitch 48",
            FriendlyName = "core-switch",
            SerialNumber = "SN-42",
            Description = "Managed\r\nnetwork switch",
            DeviceType = "Switch gerível",
            OperatingSystem = "AcmeOS",
            EvidenceSource = "ENTITY-MIB",
            Confidence = ConfidenceLevel.High
        };
        identity.AddObservation(device, highConfidence);
        identity.AddObservation(device, highConfidence);

        Equal("Acme Enterprise", device.Manufacturer);
        Equal("CoreSwitch 48", device.Model);
        Equal("core-switch", device.FriendlyName);
        Equal("SN-42", device.SerialNumber);
        Equal("Managed network switch", device.IdentityDescription);
        Equal("Switch gerível", device.DeviceType);
        Equal("AcmeOS", device.OsGuess);
        Equal(ConfidenceLevel.High, device.IdentityConfidence);
        Equal(3, device.IdentityEvidence.Count);

        identity.AddEvidence(device, new DeviceIdentityEvidence
        {
            Method = DiscoveryMethod.Nmap,
            Source = "Nmap",
            Confidence = ConfidenceLevel.High,
            Manufacturer = "Equal confidence cannot replace",
            Model = "Equal confidence cannot replace"
        });
        Equal("Acme Enterprise", device.Manufacturer);
        Equal("CoreSwitch 48", device.Model);

        int evidenceCount = device.IdentityEvidence.Count;
        identity.AddEvidence(device, new DeviceIdentityEvidence
        {
            Method = DiscoveryMethod.Mdns,
            Source = "empty",
            Confidence = ConfidenceLevel.High
        });
        Equal(evidenceCount, device.IdentityEvidence.Count);
    })),
    ("Device identity resolution is field-specific and order-independent", () => Sync(() =>
    {
        DeviceIdentityEvidence[] evidence =
        [
            new DeviceIdentityEvidence
            {
                Method = DiscoveryMethod.Snmp,
                Source = "SNMP ENTITY-MIB",
                Confidence = ConfidenceLevel.High,
                Manufacturer = "Contoso Networks",
                OperatingSystem = "ContosoOS"
            },
            new DeviceIdentityEvidence
            {
                Method = DiscoveryMethod.Mdns,
                Source = "mDNS TXT",
                Confidence = ConfidenceLevel.Low,
                Model = "Outdated model"
            },
            new DeviceIdentityEvidence
            {
                Method = DiscoveryMethod.Nmap,
                Source = "Nmap version probe",
                Confidence = ConfidenceLevel.Medium,
                Model = "Preferred model"
            },
            new DeviceIdentityEvidence
            {
                Method = DiscoveryMethod.Ssdp,
                Source = "UPnP description",
                Confidence = ConfidenceLevel.Medium,
                Model = "Other model"
            },
            new DeviceIdentityEvidence
            {
                Method = DiscoveryMethod.Ssdp,
                Source = "UPnP description",
                Confidence = ConfidenceLevel.Medium,
                FriendlyName = "Zulu endpoint"
            },
            new DeviceIdentityEvidence
            {
                Method = DiscoveryMethod.Ssdp,
                Source = "UPnP description",
                Confidence = ConfidenceLevel.Medium,
                FriendlyName = "Alpha endpoint"
            },
            new DeviceIdentityEvidence
            {
                Method = DiscoveryMethod.Mdns,
                Source = "mDNS service type",
                Confidence = ConfidenceLevel.Low,
                Description = "Identidade parcial anunciada"
            }
        ];

        DeviceIdentityService service = new();
        NetworkDevice forward = new() { IpAddress = IPAddress.Parse("192.168.1.30") };
        NetworkDevice reverse = new() { IpAddress = IPAddress.Parse("192.168.1.30") };
        foreach (DeviceIdentityEvidence item in evidence)
            service.AddEvidence(forward, item);
        foreach (DeviceIdentityEvidence item in evidence.Reverse())
            service.AddEvidence(reverse, item);

        Equal("Contoso Networks", forward.Manufacturer);
        Equal("Preferred model", forward.Model);
        Equal("Alpha endpoint", forward.FriendlyName);
        Equal("ContosoOS", forward.OsGuess);
        Equal("Identidade parcial anunciada", forward.IdentityDescription);
        Equal(ConfidenceLevel.Low, forward.IdentityConfidence);
        True(
            forward.IdentityConfidence == ConfidenceLevel.Low,
            "A confiança consolidada deve ser o mínimo conservador dos campos escolhidos.");

        Equal(forward.Manufacturer, reverse.Manufacturer);
        Equal(forward.Model, reverse.Model);
        Equal(forward.FriendlyName, reverse.FriendlyName);
        Equal(forward.OsGuess, reverse.OsGuess);
        Equal(forward.IdentityDescription, reverse.IdentityDescription);
        Equal(forward.IdentityConfidence, reverse.IdentityConfidence);
        Equal(
            string.Join('|', forward.IdentityEvidence.Select(item =>
                $"{item.Method}:{item.Source}:{item.Manufacturer}:{item.Model}:{item.FriendlyName}")),
            string.Join('|', reverse.IdentityEvidence.Select(item =>
                $"{item.Method}:{item.Source}:{item.Manufacturer}:{item.Model}:{item.FriendlyName}")));
    })),
    ("SSDP headers are case-insensitive and malformed lines are ignored", () => Sync(() =>
    {
        Dictionary<string, string> headers = SsdpDiscoveryService.ParseHeaders(
            "HTTP/1.1 200 OK\r\n" +
            "SERVER: Windows/10 UPnP/1.0\r\n" +
            "Location: http://192.168.1.20/device.xml\r\n" +
            "ST: upnp:rootdevice\r\n" +
            "st: urn:schemas-upnp-org:device:Printer:1\r\n" +
            "USN: uuid:printer::upnp:rootdevice\r\n" +
            "Malformed\r\n\r\n");

        Equal(4, headers.Count);
        Equal("Windows/10 UPnP/1.0", headers["server"]);
        Equal("http://192.168.1.20/device.xml", headers["LOCATION"]);
        Equal("urn:schemas-upnp-org:device:Printer:1", headers["st"]);
        Equal("uuid:printer::upnp:rootdevice", headers["usn"]);
        True(!headers.ContainsKey("Malformed"), "Uma linha sem separador não é um cabeçalho SSDP.");
    })),
    ("SSDP preserves distinct descriptions with a per-device limit", () => Sync(() =>
    {
        IPAddress address = IPAddress.Parse("192.168.1.20");
        List<DiscoveryObservation> announcements = Enumerable.Range(0, 10)
            .Select(index => new DiscoveryObservation
            {
                IpAddress = address,
                Method = DiscoveryMethod.Ssdp,
                Location = $"http://{address}/description-{index}.xml",
                ServiceType = $"urn:example:service:{index}",
                UniqueServiceName = $"uuid:device-{index}"
            })
            .ToList();
        announcements.Insert(1, new DiscoveryObservation
        {
            IpAddress = address,
            Method = DiscoveryMethod.Ssdp,
            Location = $"http://{address}/description-0.xml",
            ServiceType = "urn:example:service:additional",
            UniqueServiceName = "uuid:device-0::additional"
        });

        IReadOnlyList<DiscoveryObservation> consolidated =
            SsdpDiscoveryService.ConsolidateAnnouncements(announcements);
        Equal(8, consolidated.Count);
        DiscoveryObservation merged = consolidated.Single(item =>
            item.Location?.EndsWith("description-0.xml", StringComparison.Ordinal) == true);
        True(merged.ServiceType?.Contains("additional", StringComparison.Ordinal) == true,
            "Serviços do mesmo documento UPnP devem ser preservados.");
        True(merged.UniqueServiceName?.Contains("::additional", StringComparison.Ordinal) == true,
            "USNs distintos do mesmo documento UPnP devem ser preservados.");
    })),
    ("SNMP ENTITY-MIB parsing selects coherent chassis identity", () => Sync(() =>
    {
        string root = SnmpDeviceDiscoveryService.EntityClassRoot;
        Dictionary<int, SnmpEntityIdentityRow> parsed =
            SnmpDeviceDiscoveryService.ParseEntityRows(
            [
                new SnmpVariable(root + ".7", 3, null),
                new SnmpVariable(root + ".8", 10, null),
                new SnmpVariable(root + ".7.1", 3, null),
                new SnmpVariable(root + "x.9", 3, null),
                new SnmpVariable(root + ".8", 3, null)
            ],
            root);
        Equal(2, parsed.Count);
        Equal(3, parsed[7].EntityClass);
        Equal(10, parsed[8].EntityClass);

        parsed[7].Description = "Core chassis";
        parsed[8].Manufacturer = "Detailed vendor";
        parsed[8].Model = "Detailed model";
        parsed[8].SerialNumber = "SN-8";
        SnmpEntityIdentityRow? selected = SnmpDeviceDiscoveryService.SelectEntity(parsed.Values);
        NotNull(selected);
        Equal(7, selected!.Index);

        Equal(
            "Cisco IOS XE switch",
            SnmpDeviceDiscoveryService.SanitizeValue(" \tCisco\r\nIOS XE switch\0 "));
        Equal("Cisco IOS XE", SnmpDeviceDiscoveryService.InferOperatingSystem("Cisco IOS XE 17.9"));
        Equal("MikroTik RouterOS", SnmpDeviceDiscoveryService.InferOperatingSystem("RouterOS 7.15"));
        Equal<string?>(null, SnmpDeviceDiscoveryService.InferOperatingSystem("unknown appliance"));
    })),
    ("Nmap input validation and port compression fail closed", () => Sync(() =>
    {
        True(
            NmapDiscoveryService.TryValidateTargets(
                [
                    IPAddress.Parse("192.168.1.20"),
                    IPAddress.Parse("192.168.1.20"),
                    IPAddress.Parse("10.0.0.5")
                ],
                out IReadOnlyList<IPAddress> targets),
            "Alvos privados explícitos deveriam ser aceites.");
        Equal("192.168.1.20,10.0.0.5", string.Join(',', targets));
        True(!NmapDiscoveryService.TryValidateTargets([IPAddress.Parse("8.8.8.8")], out _),
            "O wrapper Nmap não pode aceitar alvos públicos.");
        True(!NmapDiscoveryService.TryValidateTargets([IPAddress.IPv6Loopback], out _),
            "O wrapper Nmap suporta apenas IPv4 privado.");
        True(!NmapDiscoveryService.TryValidateTargets(
                Enumerable.Repeat(IPAddress.Parse("192.168.1.20"), 257),
                out _),
            "Até duplicados de entrada contam para o limite antiabuso.");

        True(NmapDiscoveryService.TryValidatePorts(
                [443, 80, 82, 81, 80, 22],
                out IReadOnlyList<int> ports),
            "Portas TCP válidas deveriam ser normalizadas.");
        Equal("22,80,81,82,443", string.Join(',', ports));
        Equal("22,80-82,443-444", NmapDiscoveryService.BuildPortSpecification(
            [22, 80, 81, 82, 443, 444]));
        True(!NmapDiscoveryService.TryValidatePorts([0, 80], out _),
            "A porta zero deve ser rejeitada.");
        True(!NmapDiscoveryService.TryValidatePorts(
                Enumerable.Repeat(80, 65_536),
                out _),
            "A entrada Nmap tem um limite mesmo quando repete a mesma porta.");
        Throws<ArgumentException>(() => NmapDiscoveryService.BuildPortSpecification([]));
    })),
    ("Nmap executable resolution rejects remote and ambient PATH binaries", () => Sync(() =>
    {
        string temporaryDirectory = Path.Combine(
            Path.GetTempPath(),
            $"lns-nmap-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temporaryDirectory);
        string localExecutable = Path.Combine(temporaryDirectory, "nmap.exe");
        File.WriteAllBytes(localExecutable, [0x4D, 0x5A]);
        string? previousPath = Environment.GetEnvironmentVariable("PATH");

        try
        {
            Equal(Path.GetFullPath(localExecutable),
                NmapDiscoveryService.TryNormalizeExecutablePath(localExecutable));
            Equal<string?>(null,
                NmapDiscoveryService.TryNormalizeExecutablePath(@"\\server\share\nmap.exe"));
            Equal<string?>(null,
                NmapDiscoveryService.TryNormalizeExecutablePath(@"\\?\C:\tools\nmap.exe"));
            Equal<string?>(null,
                NmapDiscoveryService.TryNormalizeExecutablePath(@"\\.\C:\tools\nmap.exe"));

            Environment.SetEnvironmentVariable("PATH", temporaryDirectory);
            True(!NmapDiscoveryService.ResolveCandidatePaths(null).Contains(
                    Path.GetFullPath(localExecutable),
                    StringComparer.OrdinalIgnoreCase),
                "A autodeteção não deve executar um nmap.exe encontrado apenas no PATH.");
        }
        finally
        {
            Environment.SetEnvironmentVariable("PATH", previousPath);
            Directory.Delete(temporaryDirectory, recursive: true);
        }
    })),
    ("Nmap service products are not promoted to physical model or IEEE assignee", () => Sync(() =>
    {
        IPAddress address = IPAddress.Parse("192.168.1.20");
        NetworkDevice device = new()
        {
            IpAddress = address,
            IsOnline = true
        };
        Dictionary<IPAddress, NetworkDevice> devices = new()
        {
            [address] = device
        };

        new NetworkScannerService().ApplyNmapObservations(
        [
            new NmapHostObservation
            {
                IpAddress = address,
                State = "up",
                MacVendor = "Unverified banner vendor",
                Ports =
                [
                    new NmapPortObservation
                    {
                        Port = 22,
                        State = "open",
                        ServiceName = "ssh",
                        Product = "OpenSSH",
                        Version = "9.9"
                    }
                ]
            }
        ], devices);

        Equal<string?>(null, device.Model);
        Equal<string?>(null, device.MacAssignee);
        True(device.NmapSummary?.Contains("OpenSSH 9.9", StringComparison.Ordinal) == true,
            "O produto do serviço deve permanecer no resumo/banner Nmap.");
    })),
    ("Nmap XML parser preserves scoped identity evidence", () => Sync(() =>
    {
        const string xml = """
            <?xml version="1.0"?>
            <nmaprun>
              <host>
                <status state="up" />
                <address addr="192.168.1.20" addrtype="ipv4" />
                <address addr="00-11-22-33-44-55" addrtype="mac" vendor="Acme Devices" />
                <hostnames><hostname name="printer.local" /></hostnames>
                <ports>
                  <port protocol="tcp" portid="9100">
                    <state state="open" />
                    <service name="jetdirect" product="Acme Laser" version="2.0"
                             extrainfo="embedded server" devicetype="printer" ostype="embedded" />
                  </port>
                  <port protocol="udp" portid="161"><state state="open" /></port>
                </ports>
                <os>
                  <osmatch name="Linux 5.x" accuracy="92" />
                  <osmatch name="Embedded Printer OS" accuracy="98" />
                </os>
              </host>
              <host>
                <status state="up" />
                <address addr="192.168.1.21" addrtype="ipv4" />
              </host>
            </nmaprun>
            """;

        HashSet<IPAddress> scope = [IPAddress.Parse("192.168.1.20")];
        IReadOnlyList<NmapHostObservation> hosts = NmapDiscoveryService.ParseXml(xml, scope);
        Equal(1, hosts.Count);
        NmapHostObservation host = hosts[0];
        Equal(IPAddress.Parse("192.168.1.20"), host.IpAddress);
        Equal("up", host.State);
        Equal("printer.local", host.Hostname);
        Equal("00:11:22:33:44:55", host.MacAddress);
        Equal("Acme Devices", host.MacVendor);
        Equal("Embedded Printer OS", host.OperatingSystem);
        Equal<int?>(98, host.OperatingSystemAccuracy);
        Equal(1, host.Ports.Count);
        Equal(9100, host.Ports[0].Port);
        Equal("Acme Laser", host.Ports[0].Product);
        Equal("printer", host.Ports[0].DeviceType);
    })),
    ("Nmap XML parser rejects DTD depth and host-limit abuse", () => Sync(() =>
    {
        const string dtd = """
            <!DOCTYPE nmaprun [<!ENTITY local SYSTEM "file:///C:/Windows/win.ini">]>
            <nmaprun><host><address addr="192.168.1.20" addrtype="ipv4" />&local;</host></nmaprun>
            """;
        Throws<System.Xml.XmlException>(() => NmapDiscoveryService.ParseXml(dtd));

        string tooDeep = "<nmaprun>" +
                         string.Concat(Enumerable.Repeat("<node>", 66)) +
                         string.Concat(Enumerable.Repeat("</node>", 66)) +
                         "</nmaprun>";
        Throws<InvalidDataException>(() => NmapDiscoveryService.ParseXml(tooDeep));

        string tooManyHosts = "<nmaprun>" + string.Concat(
            Enumerable.Range(0, 257).Select(index =>
                $"<host><address addr=\"10.0.{index / 254}.{(index % 254) + 1}\" addrtype=\"ipv4\" /></host>")) +
            "</nmaprun>";
        Throws<InvalidDataException>(() => NmapDiscoveryService.ParseXml(tooManyHosts));
    })),
    ("Advanced discovery options require explicit safe configuration", () => Sync(() =>
    {
        IPAddress[] addresses = [IPAddress.Parse("192.168.1.20")];

        Throws<ScanInputException>(() => ScanRequestValidator.Validate(
            addresses,
            new ScanOptions
            {
                Profile = ScanProfile.Standard,
                EnableNmapDiscovery = true
            }));
        ScanRequestValidator.Validate(
            addresses,
            new ScanOptions
            {
                Profile = ScanProfile.Deep,
                EnableNmapDiscovery = true,
                NmapTimeoutMs = 120_000
            });
        Throws<ScanInputException>(() => ScanRequestValidator.Validate(
            addresses,
            new ScanOptions
            {
                Profile = ScanProfile.Deep,
                EnableNmapDiscovery = true,
                NmapExecutablePath = @"\\server\share\nmap.exe",
                NmapTimeoutMs = 120_000
            }));

        Throws<ScanInputException>(() => ScanRequestValidator.Validate(
            addresses,
            new ScanOptions
            {
                EnableSnmpDeviceDiscovery = true,
                SnmpCommunity = "  "
            }));
        ScanRequestValidator.Validate(
            addresses,
            new ScanOptions
            {
                EnableSnmpDeviceDiscovery = true,
                SnmpCommunity = "private-read-only",
                SnmpTimeoutMs = 900
            });
        Throws<ScanInputException>(() => ScanRequestValidator.Validate(
            addresses,
            new ScanOptions
            {
                EnableSnmpTopology = true,
                SnmpCommunity = "private-read-only"
            }));

        ScanOptions quick = ScanOptions.ForProfile(ScanProfile.Quick);
        Equal(false, quick.EnableUpnpDescription);
        Equal(false, quick.EnableNetBiosDiscovery);
        Equal(false, quick.EnableNmapDiscovery);
    })),
    ("WPF advanced integer validation", () => Sync(() =>
    {
        IntegerRangeValidationRule rule = new()
        {
            FieldName = "Timeout",
            Minimum = 50,
            Maximum = 30_000
        };
        CultureInfo culture = CultureInfo.GetCultureInfo("pt-PT");
        Equal(false, rule.Validate(string.Empty, culture).IsValid);
        Equal(false, rule.Validate("abc", culture).IsValid);
        Equal(false, rule.Validate("49", culture).IsValid);
        Equal(true, rule.Validate("50", culture).IsValid);
        Equal(true, rule.Validate("30000", culture).IsValid);
        Equal(false, rule.Validate("30001", culture).IsValid);
    })),
    ("Custom scan settings are explicit and migrate legacy preferences", () => RunOnSta(() =>
    {
        string directory = Path.Combine(
            Path.GetTempPath(),
            "LocalNetworkScanner.Tests",
            Guid.NewGuid().ToString("N"));
        string settingsPath = Path.Combine(directory, "settings.json");
        Directory.CreateDirectory(directory);
        try
        {
            File.WriteAllText(
                settingsPath,
                """
                {
                  "Profile": 2,
                  "IsAdvancedMode": true,
                  "MaximumHosts": 2048,
                  "MaximumHostConcurrency": 7
                }
                """);

            UiSettingsService settingsService = new(settingsPath);
            using MainViewModel viewModel = new(
                new UserDialogService(),
                new DesktopActionService(),
                settingsService);

            Equal(true, viewModel.UseCustomScanSettings);
            Equal(true, viewModel.IsCustomScanSettingsExpanded);
            True(
                viewModel.CustomOverrideCount >= 2,
                "As preferências técnicas legadas devem continuar identificadas como substituições.");

            viewModel.IsCustomScanSettingsExpanded = false;
            viewModel.IsCustomScanSettingsExpanded = true;
            Equal(true, viewModel.UseCustomScanSettings);

            MethodInfo buildScanOptions = typeof(MainViewModel)
                .GetMethod("BuildScanOptions", BindingFlags.Instance | BindingFlags.NonPublic)!;
            viewModel.UseCustomScanSettings = false;
            ScanOptions profileOptions = (ScanOptions)buildScanOptions.Invoke(viewModel, null)!;
            Equal(64, profileOptions.MaximumHostConcurrency);
            Equal(0, viewModel.ActiveCustomOverrideCount);

            viewModel.UseCustomScanSettings = true;
            ScanOptions customOptions = (ScanOptions)buildScanOptions.Invoke(viewModel, null)!;
            Equal(7, customOptions.MaximumHostConcurrency);
            True(
                viewModel.ActiveCustomOverrideCount >= 2,
                "As substituições devem ficar ativas apenas depois de o utilizador as ativar explicitamente.");

            viewModel.EnableHistory = false;
            viewModel.ResetProfileOverridesCommand.Execute(null);
            Equal(0, viewModel.CustomOverrideCount);
            Equal(64, viewModel.MaximumHostConcurrency);
            Equal(false, viewModel.EnableHistory);

            viewModel.SaveSettings();
            UiSettings migrated = settingsService.Load();
            Equal<bool?>(true, migrated.UseCustomScanSettings);
            Equal<bool?>(true, migrated.IsCustomScanSettingsExpanded);
            Equal(true, migrated.IsAdvancedMode);
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    })),
    ("Device rows expose typed sort keys", () => Sync(() =>
    {
        DeviceRowViewModel lowerIp = new(new NetworkDevice
        {
            IpAddress = IPAddress.Parse("192.168.1.2"),
            ResponseTimeMs = 9,
            RiskScore = 20,
            Ports = [new PortScanResult { Port = 80, Protocol = "TCP" }]
        });
        DeviceRowViewModel higherIp = new(new NetworkDevice
        {
            IpAddress = IPAddress.Parse("192.168.1.10"),
            ResponseTimeMs = 100,
            RiskScore = 80,
            Ports =
            [
                new PortScanResult { Port = 22, Protocol = "TCP" },
                new PortScanResult { Port = 443, Protocol = "TCP" }
            ]
        });
        DeviceRowViewModel noPing = new(new NetworkDevice
        {
            IpAddress = IPAddress.Parse("192.168.1.20")
        });

        True(lowerIp.IpSortKey < higherIp.IpSortKey, "A ordenação de IP deve ser numérica.");
        True(lowerIp.ResponseTimeSortKey < higherIp.ResponseTimeSortKey,
            "A ordenação de ping deve usar milissegundos.");
        Equal(long.MaxValue, noPing.ResponseTimeSortKey);
        True(lowerIp.RiskScore < higherIp.RiskScore, "O risco deve ser ordenado pela pontuação.");
        True(lowerIp.OpenPortCount < higherIp.OpenPortCount,
            "As portas devem ser ordenadas pela contagem.");
    })),
    ("TLS state is evidence-based and JSON-stable", () => Sync(() =>
    {
        PortScanResult conventionalTlsPort = new()
        {
            Port = 443,
            ServiceName = ServiceCatalog.GetServiceName(443)
        };
        Equal(TlsProbeStatus.NotProbed, conventionalTlsPort.TlsStatus);
        Equal<bool?>(null, conventionalTlsPort.IsEncrypted);
        Equal("\u004E\u00E3o verificado", conventionalTlsPort.TlsStatusDisplay);

        using (JsonDocument document = JsonDocument.Parse(
                   JsonSerializer.Serialize(conventionalTlsPort)))
        {
            JsonElement root = document.RootElement;
            Equal("NotProbed", root.GetProperty("TlsStatus").GetString());
            Equal(JsonValueKind.Null, root.GetProperty("IsEncrypted").ValueKind);
        }

        PortScanResult confirmed = new()
        {
            Port = 8443,
            TlsStatus = TlsProbeStatus.HandshakeSucceeded,
            TlsProtocol = "TLS 1.3"
        };
        Equal<bool?>(true, confirmed.IsEncrypted);
        Equal("TLS 1.3 confirmado", confirmed.TlsStatusDisplay);

        PortScanResult failed = new()
        {
            Port = 443,
            TlsStatus = TlsProbeStatus.HandshakeFailed,
            TlsFailureReason = "handshake rejeitado"
        };
        Equal<bool?>(null, failed.IsEncrypted);
        Equal("Indeterminado (handshake rejeitado)", failed.TlsStatusDisplay);

        PortScanResult failedWithoutReason = new()
        {
            Port = 443,
            TlsStatus = TlsProbeStatus.HandshakeFailed
        };
        Equal<bool?>(null, failedWithoutReason.IsEncrypted);
        Equal("Indeterminado (falha)", failedWithoutReason.TlsStatusDisplay);
    })),
    ("Topology filters distinguish infrastructure clients and alerts", () => Sync(() =>
    {
        NetworkMapNode gateway = new()
        {
            Id = "gateway",
            Kind = NetworkMapNodeKind.Gateway,
            Label = "Gateway",
            RiskLevel = "Baixo",
            IsOnline = true
        };
        NetworkMapNode client = new()
        {
            Id = "client",
            Kind = NetworkMapNodeKind.Device,
            Label = "Portátil",
            DeviceType = "Computador Windows",
            RiskLevel = "Baixo",
            IsOnline = true
        };
        NetworkMapNode alert = new()
        {
            Id = "alert",
            Kind = NetworkMapNodeKind.Device,
            Label = "Câmara",
            DeviceType = "Câmara / vídeo IP",
            RiskLevel = "Alto",
            IsOnline = true
        };

        Equal(true, NetworkTopologyControl.IsNodeVisible(gateway, TopologyFilterMode.Infrastructure));
        Equal(false, NetworkTopologyControl.IsNodeVisible(gateway, TopologyFilterMode.Clients));
        Equal(true, NetworkTopologyControl.IsNodeVisible(client, TopologyFilterMode.Clients));
        Equal(false, NetworkTopologyControl.IsNodeVisible(client, TopologyFilterMode.Alerts));
        Equal(true, NetworkTopologyControl.IsNodeVisible(alert, TopologyFilterMode.Alerts));
    })),
    ("Topology filters preserve matching nodes and ancestor context", () => Sync(() =>
    {
        NetworkMapNode unrelated = new()
        {
            Id = "unrelated",
            Kind = NetworkMapNodeKind.Gateway,
            Label = "Gateway sem liga\u00E7\u00E3o"
        };
        NetworkMapNode client = new()
        {
            Id = "client",
            Kind = NetworkMapNodeKind.Device,
            Label = "Port\u00E1til",
            DeviceType = "Computador Windows"
        };
        NetworkMapNode network = new()
        {
            Id = "network",
            Kind = NetworkMapNodeKind.NetworkSegment,
            Label = "192.168.1.0/24"
        };
        NetworkMapNode managedSwitch = new()
        {
            Id = "switch",
            Kind = NetworkMapNodeKind.ManagedSwitch,
            Label = "Switch principal"
        };
        NetworkMapNode gateway = new()
        {
            Id = "gateway",
            Kind = NetworkMapNodeKind.Gateway,
            Label = "Gateway"
        };
        NetworkMap map = new()
        {
            NetworkCidr = "192.168.1.0/24",
            GeneratedAt = DateTimeOffset.UnixEpoch,
            Nodes = [unrelated, client, network, managedSwitch, gateway],
            Edges =
            [
                new NetworkMapEdge
                {
                    SourceId = "network",
                    TargetId = "gateway",
                    Kind = NetworkMapEdgeKind.Contains,
                    Label = "cont\u00E9m",
                    Evidence = "teste"
                },
                new NetworkMapEdge
                {
                    SourceId = "gateway",
                    TargetId = "switch",
                    Kind = NetworkMapEdgeKind.Layer2Observed,
                    Label = "liga",
                    Evidence = "teste"
                },
                new NetworkMapEdge
                {
                    SourceId = "switch",
                    TargetId = "client",
                    Kind = NetworkMapEdgeKind.Layer2Observed,
                    Label = "liga",
                    Evidence = "teste"
                },
                new NetworkMapEdge
                {
                    SourceId = "client",
                    TargetId = "gateway",
                    Kind = NetworkMapEdgeKind.IpReachability,
                    Label = "ciclo",
                    Evidence = "teste"
                },
                new NetworkMapEdge
                {
                    SourceId = "ghost",
                    TargetId = "client",
                    Kind = NetworkMapEdgeKind.Layer2Observed,
                    Label = "origem desconhecida",
                    Evidence = "teste"
                },
                new NetworkMapEdge
                {
                    SourceId = "client",
                    TargetId = "missing",
                    Kind = NetworkMapEdgeKind.Layer2Observed,
                    Label = "destino desconhecido",
                    Evidence = "teste"
                }
            ]
        };

        IReadOnlyList<NetworkMapNode> visible = NetworkTopologyControl.GetVisibleNodes(
            map,
            TopologyFilterMode.Clients,
            out int matchingCount);

        Equal(1, matchingCount);
        Equal("client,network,switch,gateway", string.Join(',', visible.Select(node => node.Id)));
        Equal(true, NetworkTopologyControl.IsNodeVisible(client, TopologyFilterMode.Clients));
        Equal(false, NetworkTopologyControl.IsNodeVisible(network, TopologyFilterMode.Clients));
        Equal(false, NetworkTopologyControl.IsNodeVisible(managedSwitch, TopologyFilterMode.Clients));
        Equal(false, NetworkTopologyControl.IsNodeVisible(gateway, TopologyFilterMode.Clients));

        IReadOnlyList<NetworkMapNode> all = NetworkTopologyControl.GetVisibleNodes(
            map,
            TopologyFilterMode.All,
            out int allMatchingCount);
        Equal(map.Nodes.Count, allMatchingCount);
        Equal(
            string.Join(',', map.Nodes.Select(node => node.Id)),
            string.Join(',', all.Select(node => node.Id)));
    })),
    ("ARP neighbor table parsing", () => Sync(() =>
    {
        const string output =
            "Interface: 192.168.1.10 --- 0x5\n" +
            "  Internet Address      Physical Address      Type\n" +
            "  192.168.1.1           00-11-22-33-44-55     dynamic\n" +
            "  192.168.1.250         01-00-5e-00-00-01     static\n" +
            "192.168.1.20 dev eth0 lladdr 00:AA:BB:CC:DD:EE REACHABLE\n" +
            "999.168.1.30 dev eth0 lladdr 00:10:20:30:40:50 STALE\n";

        IReadOnlyDictionary<IPAddress, string> neighbors =
            MacAddressService.ParseNeighborTable(output);
        Equal(2, neighbors.Count);
        Equal("00:11:22:33:44:55", neighbors[IPAddress.Parse("192.168.1.1")]);
        Equal("00:AA:BB:CC:DD:EE", neighbors[IPAddress.Parse("192.168.1.20")]);
        True(!neighbors.ContainsKey(IPAddress.Parse("192.168.1.250")),
            "Uma entrada multicast não pode ser aceite como identidade ARP.");
    })),
    ("IP Helper neighbor interop layout", () => Sync(() =>
    {
        Type? socketAddressType = typeof(MacAddressService).GetNestedType(
            "SockaddrInet",
            BindingFlags.NonPublic);
        Type? neighborRowType = typeof(MacAddressService).GetNestedType(
            "MibIpNetRow2",
            BindingFlags.NonPublic);
        NotNull(socketAddressType);
        NotNull(neighborRowType);

        Equal(28, Marshal.SizeOf(socketAddressType!));
        Equal(88, Marshal.SizeOf(neighborRowType!));
        Equal(new IntPtr(28), Marshal.OffsetOf(neighborRowType!, "InterfaceIndex"));
        Equal(new IntPtr(32), Marshal.OffsetOf(neighborRowType!, "InterfaceLuid"));
        Equal(new IntPtr(72), Marshal.OffsetOf(neighborRowType!, "PhysicalAddressLength"));
    })),
    ("Fresh neighbor accepts a valid post-baseline entry without mutation", () => Sync(() =>
    {
        int sendArpCalls = 0;
        string? resolved = MacAddressService.ResolveWithFreshNeighbor(
            IPAddress.Parse("192.168.1.20"),
            IPAddress.Parse("192.168.1.10"),
            37,
            (ref MacAddressService.MibIpNetRow2 row) =>
            {
                Equal<uint>(37, row.InterfaceIndex);
                SetNeighborRow(
                    ref row,
                    [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
                    physicalAddressLength: 6,
                    state: 5);
                return 0;
            },
            (uint _, uint _, byte[] _, ref int _) =>
            {
                Interlocked.Increment(ref sendArpCalls);
                return 0;
            });

        Equal("00:11:22:33:44:55", resolved);
        Equal(0, Volatile.Read(ref sendArpCalls));
    })),
    ("Stale neighbor requires ARP revalidation and a matching reachable post-read", () => Sync(() =>
    {
        int neighborReads = 0;
        int sendArpCalls = 0;
        string? resolved = MacAddressService.ResolveWithFreshNeighbor(
            IPAddress.Parse("192.168.1.21"),
            IPAddress.Parse("192.168.1.10"),
            38,
            (ref MacAddressService.MibIpNetRow2 row) =>
            {
                int read = Interlocked.Increment(ref neighborReads);
                SetNeighborRow(
                    ref row,
                    [0x00, 0x11, 0x22, 0x33, 0x44, 0x66],
                    physicalAddressLength: 6,
                    state: read == 1 ? 4 : 5);
                return 0;
            },
            (uint _, uint _, byte[] buffer, ref int physicalAddressLength) =>
            {
                Interlocked.Increment(ref sendArpCalls);
                byte[] response = [0x00, 0x11, 0x22, 0x33, 0x44, 0x66];
                response.CopyTo(buffer, 0);
                physicalAddressLength = response.Length;
                return 0;
            });

        Equal("00:11:22:33:44:66", resolved);
        Equal(2, Volatile.Read(ref neighborReads));
        Equal(1, Volatile.Read(ref sendArpCalls));
    })),
    ("Stale neighbor is rejected when ARP cannot prove the same current MAC", () => Sync(() =>
    {
        foreach ((int arpResult, uint refreshedLength, int refreshedState, byte refreshedFlags, byte refreshedLastByte) in new[]
        {
            (67, 6U, 5, (byte)0x00, (byte)0x66),
            (0, 6U, 4, (byte)0x00, (byte)0x66),
            (0, 6U, 5, (byte)0x00, (byte)0x77),
            (0, 6U, 5, (byte)0x02, (byte)0x66),
            (0, 5U, 5, (byte)0x00, (byte)0x66)
        })
        {
            int neighborReads = 0;
            string? resolved = MacAddressService.ResolveWithFreshNeighbor(
                IPAddress.Parse("192.168.1.21"),
                IPAddress.Parse("192.168.1.10"),
                38,
                (ref MacAddressService.MibIpNetRow2 row) =>
                {
                    int read = Interlocked.Increment(ref neighborReads);
                    SetNeighborRow(
                        ref row,
                        [0x00, 0x11, 0x22, 0x33, 0x44, read == 1 ? (byte)0x66 : refreshedLastByte],
                        physicalAddressLength: read == 1 ? 6 : refreshedLength,
                        state: read == 1 ? 4 : refreshedState,
                        flags: read == 1 ? (byte)0x00 : refreshedFlags);
                    return 0;
                },
                (uint _, uint _, byte[] buffer, ref int physicalAddressLength) =>
                {
                    byte[] response = [0x00, 0x11, 0x22, 0x33, 0x44, 0x66];
                    response.CopyTo(buffer, 0);
                    physicalAddressLength = response.Length;
                    return arpResult;
                });

            Equal<string?>(null, resolved);
        }
    })),
    ("Permanent ARP neighbor stays passive and is not revalidated", () => Sync(() =>
    {
        int sendArpCalls = 0;
        string? resolved = MacAddressService.ResolveWithFreshNeighbor(
            IPAddress.Parse("192.168.1.24"),
            IPAddress.Parse("192.168.1.10"),
            41,
            (ref MacAddressService.MibIpNetRow2 row) =>
            {
                SetNeighborRow(
                    ref row,
                    [0x00, 0x11, 0x22, 0x33, 0x44, 0x88],
                    physicalAddressLength: 6,
                    state: 6);
                return 0;
            },
            (uint _, uint _, byte[] _, ref int _) =>
            {
                Interlocked.Increment(ref sendArpCalls);
                return 0;
            });

        Equal<string?>(null, resolved);
        Equal(0, Volatile.Read(ref sendArpCalls));
    })),
    ("SendARP result and returned length are validated strictly", () => Sync(() =>
    {
        IPAddress destinationAddress = IPAddress.Parse("192.168.1.22");
        IPAddress sourceAddress = IPAddress.Parse("192.168.1.10");
        int successfulCalls = 0;
        string? successfulResolution = MacAddressService.ResolveWithFreshNeighbor(
            destinationAddress,
            sourceAddress,
            39,
            (ref MacAddressService.MibIpNetRow2 _) => 1_168,
            (uint destination, uint source, byte[] buffer, ref int physicalAddressLength) =>
            {
                Interlocked.Increment(ref successfulCalls);
                Equal(BitConverter.ToUInt32(destinationAddress.GetAddressBytes(), 0), destination);
                Equal(BitConverter.ToUInt32(sourceAddress.GetAddressBytes(), 0), source);
                Equal(8, buffer.Length);
                Equal(8, physicalAddressLength);
                byte[] response = [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x22];
                response.CopyTo(buffer, 0);
                buffer[6] = 0xFE;
                buffer[7] = 0xFF;
                physicalAddressLength = 6;
                return 0;
            });
        Equal("00:AA:BB:CC:DD:22", successfulResolution);
        Equal(1, Volatile.Read(ref successfulCalls));

        foreach ((int nativeResult, int returnedLength) in new[] { (1, 6), (0, 8) })
        {
            string? resolved = MacAddressService.ResolveWithFreshNeighbor(
                destinationAddress,
                sourceAddress,
                39,
                (ref MacAddressService.MibIpNetRow2 _) => 1_168,
                (uint _, uint _, byte[] buffer, ref int physicalAddressLength) =>
                {
                    Equal(8, buffer.Length);
                    Equal(8, physicalAddressLength);
                    byte[] response = [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x22];
                    response.CopyTo(buffer, 0);
                    physicalAddressLength = returnedLength;
                    return nativeResult;
                });

            Equal<string?>(null, resolved);
        }
    })),
    ("Unexpected neighbor API errors fail closed", () => Sync(() =>
    {
        int sendArpCalls = 0;
        string? resolved = MacAddressService.ResolveWithFreshNeighbor(
            IPAddress.Parse("192.168.1.23"),
            IPAddress.Parse("192.168.1.10"),
            40,
            (ref MacAddressService.MibIpNetRow2 _) => 5,
            (uint _, uint _, byte[] _, ref int _) =>
            {
                Interlocked.Increment(ref sendArpCalls);
                return 0;
            });

        Equal<string?>(null, resolved);
        Equal(0, Volatile.Read(ref sendArpCalls));
    })),
    ("ARP scan session resolves and forwards the interface index once", async () =>
    {
        int interfaceIndexResolutions = 0;
        int activeResolutions = 0;
        MacAddressService service = new(
            (_, _) => Task.FromResult<string?>(string.Empty),
            (_, _, interfaceIndex, _) =>
            {
                Interlocked.Increment(ref activeResolutions);
                Equal<uint?>(41, interfaceIndex);
                return Task.FromResult<string?>("00-AA-BB-CC-DD-41");
            },
            networkInterface =>
            {
                Equal("test-interface", networkInterface.Id);
                Interlocked.Increment(ref interfaceIndexResolutions);
                return 41;
            });
        await using MacAddressService.ScanSession session =
            service.CreateScanSession(CreateInterface());

        Equal(1, Volatile.Read(ref interfaceIndexResolutions));
        Equal(false, session.IsNeighborBaselineAvailable);
        await session.InitializeAsync(CancellationToken.None);
        Equal(true, session.IsNeighborBaselineAvailable);

        Equal("00:AA:BB:CC:DD:41", await session.ResolveAsync(
            IPAddress.Parse("192.168.1.41"),
            CancellationToken.None));
        Equal("00:AA:BB:CC:DD:41", await session.ResolveAsync(
            IPAddress.Parse("192.168.1.42"),
            CancellationToken.None));
        Equal(1, Volatile.Read(ref interfaceIndexResolutions));
        Equal(2, Volatile.Read(ref activeResolutions));
    }),
    ("ARP scan session caches table and addresses", async () =>
    {
        int tableReads = 0;
        int activeResolutions = 0;
        MacAddressService service = new(
            (_, _) =>
            {
                Interlocked.Increment(ref tableReads);
                return Task.FromResult<string?>(
                    "192.168.1.20  00-11-22-33-44-55  dynamic");
            },
            (address, _, _) =>
            {
                Interlocked.Increment(ref activeResolutions);
                return Task.FromResult<string?>(address.Equals(IPAddress.Parse("192.168.1.30"))
                    ? "00-AA-BB-CC-DD-01"
                    : "01:00:5E:00:00:01");
            },
            maximumActiveConcurrency: 2);
        await using MacAddressService.ScanSession session =
            service.CreateScanSession(CreateInterface());

        IPAddress tableAddress = IPAddress.Parse("192.168.1.20");
        string?[] tableResults = await Task.WhenAll(
            session.ResolveAsync(tableAddress, CancellationToken.None),
            session.ResolveAsync(tableAddress, CancellationToken.None));
        True(tableResults.All(value => value == "00:11:22:33:44:55"),
            "A tabela de vizinhos deveria resolver o endereço sem resolução ativa.");
        MacAddressResolution? cachedEvidence = await session.ResolveWithEvidenceAsync(
            tableAddress,
            CancellationToken.None);
        Equal(MacAddressResolutionSource.NeighborCache, cachedEvidence!.Source);
        Equal(false, cachedEvidence.ConfirmsReachability);

        IPAddress activeAddress = IPAddress.Parse("192.168.1.30");
        string?[] activeResults = await Task.WhenAll(
            session.ResolveAsync(activeAddress, CancellationToken.None),
            session.ResolveAsync(activeAddress, CancellationToken.None));
        True(activeResults.All(value => value == "00:AA:BB:CC:DD:01"),
            "A resolução ativa deveria ser normalizada e reutilizada.");
        MacAddressResolution? activeEvidence = await session.ResolveWithEvidenceAsync(
            activeAddress,
            CancellationToken.None);
        Equal(MacAddressResolutionSource.ActiveArp, activeEvidence!.Source);
        Equal(true, activeEvidence.ConfirmsReachability);

        IPAddress invalidAddress = IPAddress.Parse("192.168.1.40");
        Equal<string?>(null, await session.ResolveAsync(invalidAddress, CancellationToken.None));
        Equal<string?>(null, await session.ResolveAsync(invalidAddress, CancellationToken.None));
        Equal("00:AA:BB:CC:DD:EE",
            await session.ResolveAsync(CreateInterface().IpAddress, CancellationToken.None));
        Equal<string?>(null,
            await session.ResolveAsync(IPAddress.Parse("10.0.0.20"), CancellationToken.None));

        Equal(1, Volatile.Read(ref tableReads));
        Equal(2, Volatile.Read(ref activeResolutions));
    }),
    ("ARP baseline is captured before reachability probes", async () =>
    {
        TaskCompletionSource tableRequested = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource releaseTable = new(TaskCreationOptions.RunContinuationsAsynchronously);
        int pingProbes = 0;
        int tcpProbes = 0;
        IPAddress target = IPAddress.Parse("192.168.1.59");
        MacAddressService macService = new(
            async (_, cancellationToken) =>
            {
                tableRequested.TrySetResult();
                await releaseTable.Task.WaitAsync(cancellationToken);
                return string.Empty;
            },
            (_, _, _) => Task.FromResult<string?>(null));
        NetworkScannerService scanner = new(
            macService,
            (_, _, _, _) =>
            {
                Interlocked.Increment(ref pingProbes);
                return Task.FromResult(new PingProbeResult(false, null, null));
            },
            (_, _, _, _, _) =>
            {
                Interlocked.Increment(ref tcpProbes);
                return Task.FromResult<int?>(null);
            });

        Task<NetworkScanResult> scanTask = scanner.ScanAsync(
            [target],
            CreateInterface(),
            new ScanOptions
            {
                EnableIcmp = true,
                EnableTcpDiscovery = true,
                EnableArp = true,
                EnableMulticastDiscovery = false,
                EnableUpnpDescription = false,
                EnableNetBiosDiscovery = false,
                EnableServiceProbes = false,
                Ports = [65_535],
                DiscoveryPorts = [65_535]
            });

        try
        {
            await tableRequested.Task.WaitAsync(TimeSpan.FromSeconds(2));
            Equal(0, Volatile.Read(ref pingProbes));
            Equal(0, Volatile.Read(ref tcpProbes));
        }
        finally
        {
            releaseTable.TrySetResult();
        }

        await scanTask;
        Equal(1, Volatile.Read(ref pingProbes));
        Equal(1, Volatile.Read(ref tcpProbes));
    }),
    ("Cached ARP revalidation starts without waiting for a slow TCP probe", async () =>
    {
        TaskCompletionSource arpStarted =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource releaseTcp =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        IPAddress target = IPAddress.Parse("127.0.0.2");
        LocalNetworkInterface loopbackInterface = new()
        {
            Id = "test-loopback-parallel-arp",
            Name = "Loopback",
            Description = "Interface loopback de teste ARP paralelo",
            IpAddress = IPAddress.Loopback,
            SubnetMask = IPAddress.Parse("255.0.0.0"),
            GatewayAddress = IPAddress.Loopback,
            MacAddress = "00:AA:BB:CC:DD:EE",
            InterfaceType = NetworkInterfaceType.Ethernet,
            SpeedBitsPerSecond = 1_000_000_000
        };
        MacAddressService macService = new(
            (_, _) => Task.FromResult<string?>(
                $"{target}  00-AA-BB-CC-DD-72  dynamic"),
            (_, _, _) =>
            {
                arpStarted.TrySetResult();
                return Task.FromResult<string?>("00-AA-BB-CC-DD-72");
            });
        NetworkScannerService scanner = new(
            macService,
            (_, _, _, _) => Task.FromResult(new PingProbeResult(false, null, null)),
            async (_, _, _, _, token) =>
            {
                await releaseTcp.Task.WaitAsync(token);
                return null;
            });

        Task<NetworkScanResult> scanTask = scanner.ScanAsync(
            [target],
            loopbackInterface,
            new ScanOptions
            {
                EnableIcmp = true,
                EnableTcpDiscovery = true,
                EnableArp = true,
                EnableMulticastDiscovery = false,
                EnableUpnpDescription = false,
                EnableNetBiosDiscovery = false,
                EnableServiceProbes = false,
                Ports = [65_535],
                DiscoveryPorts = [65_535]
            });

        try
        {
            await arpStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
            Equal(false, scanTask.IsCompleted);
        }
        finally
        {
            releaseTcp.TrySetResult();
        }

        NetworkScanResult result = await scanTask;
        Equal(1, result.Devices.Count);
        Equal(true, result.Devices[0].DiscoveryMethods.HasFlag(DiscoveryMethod.Arp));
    }),
    ("Cached ARP stays passive until explicitly revalidated", async () =>
    {
        int activeResolutions = 0;
        IPAddress target = IPAddress.Parse("192.168.1.60");
        MacAddressService service = new(
            (_, _) => Task.FromResult<string?>(
                $"{target}  00-11-22-33-44-55  dynamic"),
            (_, _, _) =>
            {
                Interlocked.Increment(ref activeResolutions);
                return Task.FromResult<string?>("00-AA-BB-CC-DD-66");
            });
        await using MacAddressService.ScanSession session =
            service.CreateScanSession(CreateInterface());

        MacAddressResolution? cached = await session.ResolveWithEvidenceAsync(
            target,
            CancellationToken.None);
        Equal("00:11:22:33:44:55", cached!.MacAddress);
        Equal(MacAddressResolutionSource.NeighborCache, cached.Source);
        Equal(false, cached.ConfirmsReachability);

        MacAddressResolution? repeated = await session.ResolveWithEvidenceAsync(
            target,
            CancellationToken.None);
        Equal("00:11:22:33:44:55", repeated!.MacAddress);
        Equal(MacAddressResolutionSource.NeighborCache, repeated.Source);
        Equal(false, repeated.ConfirmsReachability);
        Equal(0, Volatile.Read(ref activeResolutions));

        MacAddressResolution? revalidated = await session.ConfirmReachabilityAsync(
            target,
            CancellationToken.None);
        Equal("00:AA:BB:CC:DD:66", revalidated!.MacAddress);
        Equal(MacAddressResolutionSource.CurrentReachableNeighbor, revalidated.Source);
        Equal(true, revalidated.ConfirmsReachability);
        Equal(1, Volatile.Read(ref activeResolutions));

        MacAddressResolution? repeatedRevalidation = await session.ConfirmReachabilityAsync(
            target,
            CancellationToken.None);
        Equal(revalidated, repeatedRevalidation);
        Equal(1, Volatile.Read(ref activeResolutions));
    }),
    ("Active ARP fails closed when the neighbor table is unavailable", async () =>
    {
        int activeResolutions = 0;
        MacAddressService service = new(
            (_, _) => Task.FromResult<string?>(null),
            (_, _, _) =>
            {
                Interlocked.Increment(ref activeResolutions);
                return Task.FromResult<string?>("00-AA-BB-CC-DD-61");
            });

        await using MacAddressService.ScanSession session =
            service.CreateScanSession(CreateInterface());
        await session.InitializeAsync(CancellationToken.None);
        Equal(false, session.IsNeighborBaselineAvailable);

        MacAddressResolution? resolution = await session.ResolveWithEvidenceAsync(
            IPAddress.Parse("192.168.1.61"),
            CancellationToken.None);

        Equal<MacAddressResolution?>(null, resolution);
        Equal(0, Volatile.Read(ref activeResolutions));
    }),
    ("Unavailable ARP baseline is reported without invalidating other protocols", async () =>
    {
        int activeResolutions = 0;
        IPAddress target = IPAddress.Parse("127.0.0.2");
        LocalNetworkInterface loopbackInterface = new()
        {
            Id = "test-loopback-baseline-unavailable",
            Name = "Loopback",
            Description = "Interface loopback sem baseline ARP",
            IpAddress = IPAddress.Loopback,
            SubnetMask = IPAddress.Parse("255.0.0.0"),
            GatewayAddress = IPAddress.Loopback,
            MacAddress = "00:AA:BB:CC:DD:EE",
            InterfaceType = NetworkInterfaceType.Ethernet,
            SpeedBitsPerSecond = 1_000_000_000
        };
        MacAddressService macService = new(
            (_, _) => Task.FromResult<string?>(null),
            (_, _, _) =>
            {
                Interlocked.Increment(ref activeResolutions);
                return Task.FromResult<string?>("00-AA-BB-CC-DD-62");
            });
        NetworkScannerService scanner = new(
            macService,
            (_, _, _, _) => Task.FromResult(new PingProbeResult(true, 1, 128)),
            (_, _, _, _, _) => Task.FromResult<int?>(null));

        NetworkScanResult result = await scanner.ScanAsync(
            [target],
            loopbackInterface,
            new ScanOptions
            {
                EnableIcmp = true,
                EnableTcpDiscovery = false,
                EnableArp = true,
                EnableMulticastDiscovery = false,
                EnableUpnpDescription = false,
                EnableNetBiosDiscovery = false,
                EnableServiceProbes = false,
                Ports = [65_535],
                DiscoveryPorts = [65_535]
            });

        Equal(1, result.Devices.Count);
        Equal(true, result.Devices[0].DiscoveryMethods.HasFlag(DiscoveryMethod.Icmp));
        Equal(false, result.Devices[0].DiscoveryMethods.HasFlag(DiscoveryMethod.Arp));
        Equal(0, Volatile.Read(ref activeResolutions));
        True(result.Diagnostics.Any(item =>
                item.Code.Equals(DiagnosticCatalog.ArpBaselineUnavailableCode, StringComparison.Ordinal)),
            "A degradação ARP deveria ficar visível sem invalidar o dispositivo ICMP.");
    }),
    ("Cached ARP is actively revalidated before promoting a silent host", async () =>
    {
        int tableReads = 0;
        int activeResolutions = 0;
        int pingProbes = 0;
        int tcpProbes = 0;
        IPAddress target = IPAddress.Parse("192.168.1.70");
        MacAddressService macService = new(
            (_, _) =>
            {
                Interlocked.Increment(ref tableReads);
                return Task.FromResult<string?>(
                    $"{target}  00-11-22-33-44-77  dynamic");
            },
            (_, _, _) =>
            {
                Interlocked.Increment(ref activeResolutions);
                return Task.FromResult<string?>(null);
            });
        NetworkScannerService scanner = new(
            macService,
            (_, _, _, _) =>
            {
                Interlocked.Increment(ref pingProbes);
                return Task.FromResult(new PingProbeResult(false, null, null));
            },
            (_, _, _, _, _) =>
            {
                Interlocked.Increment(ref tcpProbes);
                return Task.FromResult<int?>(null);
            });

        NetworkScanResult result = await scanner.ScanAsync(
            [target],
            CreateInterface(),
            new ScanOptions
            {
                EnableIcmp = true,
                EnableTcpDiscovery = true,
                EnableArp = true,
                EnableMulticastDiscovery = false,
                EnableUpnpDescription = false,
                EnableNetBiosDiscovery = false,
                EnableServiceProbes = false,
                Ports = [65_535],
                DiscoveryPorts = [65_535]
            });

        Equal(0, result.Devices.Count);
        Equal(1, Volatile.Read(ref pingProbes));
        Equal(1, Volatile.Read(ref tcpProbes));
        Equal(1, Volatile.Read(ref activeResolutions));
        Equal(1, Volatile.Read(ref tableReads));
    }),
    ("Revalidated cached ARP keeps consecutive scan inventories consistent", async () =>
    {
        int tableReads = 0;
        int activeResolutions = 0;
        IPAddress target = IPAddress.Parse("127.0.0.2");
        LocalNetworkInterface loopbackInterface = new()
        {
            Id = "test-loopback-revalidated",
            Name = "Loopback",
            Description = "Interface loopback de teste ARP reconfirmado",
            IpAddress = IPAddress.Loopback,
            SubnetMask = IPAddress.Parse("255.0.0.0"),
            GatewayAddress = IPAddress.Loopback,
            MacAddress = "00:AA:BB:CC:DD:EE",
            InterfaceType = NetworkInterfaceType.Ethernet,
            SpeedBitsPerSecond = 1_000_000_000
        };
        MacAddressService macService = new(
            (_, _) => Task.FromResult<string?>(
                Interlocked.Increment(ref tableReads) == 1
                    ? string.Empty
                    : $"{target}  00-11-22-33-44-99  dynamic"),
            (_, _, _) =>
            {
                Interlocked.Increment(ref activeResolutions);
                return Task.FromResult<string?>("00-11-22-33-44-99");
            });
        NetworkScannerService scanner = new(
            macService,
            (_, _, _, _) => Task.FromResult(new PingProbeResult(false, null, null)),
            (_, _, _, _, _) => Task.FromResult<int?>(null));

        ScanOptions options = new()
        {
            EnableIcmp = true,
            EnableTcpDiscovery = true,
            EnableArp = true,
            EnableMulticastDiscovery = false,
            EnableUpnpDescription = false,
            EnableNetBiosDiscovery = false,
            EnableServiceProbes = false,
            Ports = [65_535],
            DiscoveryPorts = [65_535]
        };

        NetworkScanResult first = await scanner.ScanAsync(
            [target],
            loopbackInterface,
            options);
        NetworkScanResult second = await scanner.ScanAsync(
            [target],
            loopbackInterface,
            options);

        Equal(1, first.Devices.Count);
        Equal(1, second.Devices.Count);
        Equal(MacAddressResolutionSource.ActiveArp, first.Devices[0].MacAddressSource);
        Equal(
            MacAddressResolutionSource.CurrentReachableNeighbor,
            second.Devices[0].MacAddressSource);
        foreach (NetworkDevice device in first.Devices.Concat(second.Devices))
        {
            Equal("00:11:22:33:44:99", device.MacAddress);
            Equal(true, device.DiscoveryMethods.HasFlag(DiscoveryMethod.Arp));
            Equal(true, device.Topology.SameLayer2Segment);
            Equal(true, device.ObservedProtocols.Contains("ARP"));
        }

        Equal(2, Volatile.Read(ref activeResolutions));
        Equal(2, Volatile.Read(ref tableReads));
    }),
    ("Fresh ARP promotes an otherwise silent local host", async () =>
    {
        int tableReads = 0;
        int activeResolutions = 0;
        IPAddress target = IPAddress.Parse("127.0.0.2");
        LocalNetworkInterface loopbackInterface = new()
        {
            Id = "test-loopback-active",
            Name = "Loopback",
            Description = "Interface loopback de teste ARP",
            IpAddress = IPAddress.Loopback,
            SubnetMask = IPAddress.Parse("255.0.0.0"),
            GatewayAddress = IPAddress.Loopback,
            MacAddress = "00:AA:BB:CC:DD:EE",
            InterfaceType = NetworkInterfaceType.Ethernet,
            SpeedBitsPerSecond = 1_000_000_000
        };
        MacAddressService macService = new(
            (_, _) =>
            {
                Interlocked.Increment(ref tableReads);
                return Task.FromResult<string?>(string.Empty);
            },
            (_, _, _) =>
            {
                Interlocked.Increment(ref activeResolutions);
                return Task.FromResult<string?>("00-AA-BB-CC-DD-71");
            });
        NetworkScannerService scanner = new(
            macService,
            (_, _, _, _) => Task.FromResult(new PingProbeResult(false, null, null)),
            (_, _, _, _, _) => Task.FromResult<int?>(null));

        NetworkScanResult result = await scanner.ScanAsync(
            [target],
            loopbackInterface,
            new ScanOptions
            {
                EnableIcmp = true,
                EnableTcpDiscovery = true,
                EnableArp = true,
                EnableMulticastDiscovery = false,
                EnableUpnpDescription = false,
                EnableNetBiosDiscovery = false,
                EnableServiceProbes = false,
                Ports = [65_535],
                DiscoveryPorts = [65_535]
            });

        Equal(1, result.Devices.Count);
        NetworkDevice device = result.Devices[0];
        Equal("00:AA:BB:CC:DD:71", device.MacAddress);
        Equal(true, device.DiscoveryMethods.HasFlag(DiscoveryMethod.Arp));
        Equal(true, device.Topology.SameLayer2Segment);
        Equal(true, device.ObservedProtocols.Contains("ARP"));
        Equal(1, Volatile.Read(ref activeResolutions));
        Equal(1, Volatile.Read(ref tableReads));
    }),
    ("Cached ARP enriches a confirmed host without fresh ARP evidence", async () =>
    {
        int activeResolutions = 0;
        IPAddress target = IPAddress.Parse("127.0.0.2");
        LocalNetworkInterface loopbackInterface = new()
        {
            Id = "test-loopback",
            Name = "Loopback",
            Description = "Interface loopback de teste",
            IpAddress = IPAddress.Loopback,
            SubnetMask = IPAddress.Parse("255.0.0.0"),
            GatewayAddress = IPAddress.Loopback,
            MacAddress = "00:AA:BB:CC:DD:EE",
            InterfaceType = NetworkInterfaceType.Ethernet,
            SpeedBitsPerSecond = 1_000_000_000
        };
        MacAddressService macService = new(
            (_, _) => Task.FromResult<string?>(
                $"{target}  00-11-22-33-44-88  dynamic"),
            (_, _, _) =>
            {
                Interlocked.Increment(ref activeResolutions);
                return Task.FromResult<string?>(null);
            });
        NetworkScannerService scanner = new(
            macService,
            (_, _, _, _) => Task.FromResult(new PingProbeResult(true, 1, 128)),
            (_, _, _, _, _) => Task.FromResult<int?>(null));

        NetworkScanResult result = await scanner.ScanAsync(
            [target],
            loopbackInterface,
            new ScanOptions
            {
                EnableIcmp = true,
                EnableTcpDiscovery = true,
                EnableArp = true,
                EnableMulticastDiscovery = false,
                EnableUpnpDescription = false,
                EnableNetBiosDiscovery = false,
                EnableServiceProbes = false,
                ConnectTimeoutMs = 50,
                Ports = [65_535],
                DiscoveryPorts = [65_535]
            });

        Equal(1, result.Devices.Count);
        NetworkDevice device = result.Devices[0];
        Equal("00:11:22:33:44:88", device.MacAddress);
        Equal(true, device.DiscoveryMethods.HasFlag(DiscoveryMethod.Icmp));
        Equal(false, device.DiscoveryMethods.HasFlag(DiscoveryMethod.Arp));
        Equal(MacAddressResolutionSource.NeighborCache, device.MacAddressSource);
        Equal<bool?>(null, device.Topology.SameLayer2Segment);
        Equal(false, device.ObservedProtocols.Contains("ARP"));
        Equal(1, Volatile.Read(ref activeResolutions));
    }),
    ("ARP scan session propagates cancellation", async () =>
    {
        int activeResolutions = 0;
        TaskCompletionSource tableStarted =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        using CancellationTokenSource cancellation = new();
        MacAddressService service = new(
            async (_, token) =>
            {
                tableStarted.TrySetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
                return null;
            },
            (_, _, _) =>
            {
                Interlocked.Increment(ref activeResolutions);
                return Task.FromResult<string?>(null);
            });
        await using MacAddressService.ScanSession session =
            service.CreateScanSession(CreateInterface(), cancellation.Token);

        Task<string?> resolution = session.ResolveAsync(
            IPAddress.Parse("192.168.1.50"),
            CancellationToken.None);
        await tableStarted.Task;
        cancellation.Cancel();
        await ThrowsAsync<OperationCanceledException>(async () => _ = await resolution);
        Equal(0, Volatile.Read(ref activeResolutions));
    }),
    ("ARP revalidation returns promptly when its scan is cancelled", async () =>
    {
        IPAddress target = IPAddress.Parse("192.168.1.51");
        TaskCompletionSource activeStarted =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        using CancellationTokenSource cancellation = new();
        MacAddressService service = new(
            (_, _) => Task.FromResult<string?>(
                $"{target}  00-11-22-33-44-51  dynamic"),
            async (_, _, token) =>
            {
                activeStarted.TrySetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
                return null;
            });
        await using MacAddressService.ScanSession session =
            service.CreateScanSession(CreateInterface(), cancellation.Token);

        Task<MacAddressResolution?> resolution = session.ResolveForDiscoveryAsync(
            target,
            CancellationToken.None);
        await activeStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        cancellation.Cancel();
        await ThrowsAsync<OperationCanceledException>(async () => _ = await resolution);
    }),
    ("Invalid MAC is quarantined end-to-end", async () =>
    {
        NetworkDevice device = new()
        {
            IpAddress = IPAddress.Parse("192.168.1.70"),
            IsOnline = true,
            MacAddress = "0:01122334455",
            Manufacturer = "Untrusted",
            IsRandomizedMac = true,
            MacAddressSource = MacAddressResolutionSource.ActiveArp,
            DiscoveryMethods = DiscoveryMethod.Arp
        };

        string? observed = NetworkScannerService.NormalizeDeviceMacIdentity(device);
        Equal("0:01122334455", observed);
        Equal<string?>(null, device.MacAddress);
        Equal<MacAddressResolutionSource?>(null, device.MacAddressSource);
        Equal<string?>(null, device.Manufacturer);
        Equal(false, device.IsRandomizedMac);
        True(!device.DiscoveryMethods.HasFlag(DiscoveryMethod.Arp),
            "Um MAC inválido não pode preservar evidência ARP.");

        device.Topology = new TopologyInferenceService().Assess(device, CreateInterface());
        Equal<bool?>(null, device.Topology.SameLayer2Segment);
        Equal(false, new DeviceRowViewModel(device).HasMacAddress);

        NetworkScanResult result = new()
        {
            NetworkInterface = CreateInterface(),
            StartedAt = DateTimeOffset.UtcNow.AddSeconds(-1),
            CompletedAt = DateTimeOffset.UtcNow,
            AddressesScanned = 1,
            Devices = [device]
        };
        NetworkMap map = new NetworkTopologyMapService().Build(result);
        Equal(0, map.Edges.Count(edge => edge.Kind == NetworkMapEdgeKind.Layer2Observed));

        NetworkDevice missing = new()
        {
            IpAddress = IPAddress.Parse("192.168.1.71"),
            DiscoveryMethods = DiscoveryMethod.Tcp
        };
        Equal<string?>(null, NetworkScannerService.NormalizeDeviceMacIdentity(missing));
        Equal(DiscoveryMethod.Tcp, missing.DiscoveryMethods);

        ScanFormatException exception = await ThrowsAsync<ScanFormatException>(() =>
            new WakeOnLanService().SendAsync("0:01122334455", IPAddress.Broadcast));
        Equal(DiagnosticCatalog.InvalidMacAddressCode, exception.Diagnostic.Code);
    }),
    ("Product identity follows assembly version", () => Sync(() =>
    {
        string expectedVersion = typeof(NetworkDevice).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
        Equal(expectedVersion, ProductIdentity.Version);
        Equal($"LocalNetworkScanner/{expectedVersion}", ProductIdentity.UserAgent);
    })),
    ("IEEE OUI CSV", () => Sync(() =>
    {
        string path = Path.Combine(Path.GetTempPath(), $"local-network-scanner-oui-{Guid.NewGuid():N}.csv");
        try
        {
            File.WriteAllText(
                path,
                "Registry,Assignment,Organization Name,Organization Address\n" +
                "MA-L,001122,\"Example Networks, Inc.\",\"Lisboa, Portugal\"\n",
                new UTF8Encoding(false));

            MacVendorService service = new(path);
            Equal("Example Networks, Inc.", service.Lookup("00:11:22:33:44:55"));
        }
        finally
        {
            File.Delete(path);
        }
    })),
    ("Bundled IEEE vendor database integrity", () => Sync(() =>
    {
        const string resourceName = "LocalNetworkScanner.Core.Data.ieee-mac-vendors.tsv.gz";
        using Stream? resource = typeof(MacVendorService).Assembly.GetManifestResourceStream(resourceName);
        NotNull(resource);

        using MemoryStream compressed = new();
        resource!.CopyTo(compressed);
        string resourceHash = Convert.ToHexString(
            SHA256.HashData(compressed.ToArray())).ToLowerInvariant();
        Equal(
            "5149df53f544226cf917275233734aa8ad9ae362a9cf1ec1aa3e9753a518927f",
            resourceHash);

        compressed.Position = 0;
        using GZipStream gzip = new(compressed, CompressionMode.Decompress);
        using StreamReader reader = new(gzip, new UTF8Encoding(false));
        Dictionary<string, string> metadata = new(StringComparer.Ordinal);
        Dictionary<string, int> registryCounts = new(StringComparer.Ordinal)
        {
            ["MA-L"] = 0,
            ["MA-M"] = 0,
            ["MA-S"] = 0,
            ["IAB"] = 0
        };
        Dictionary<string, int> prefixOccurrences = new(StringComparer.Ordinal);
        int entries = 0;
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (line.StartsWith('#'))
            {
                int separator = line.IndexOf('=');
                if (separator > 2)
                    metadata[line[2..separator]] = line[(separator + 1)..];
                continue;
            }

            string[] columns = line.Split('\t', 3);
            Equal(3, columns.Length);
            True(registryCounts.ContainsKey(columns[0]), $"Registo IEEE inesperado: {columns[0]}.");
            int expectedPrefixLength = columns[0] switch
            {
                "MA-L" => 6,
                "MA-M" => 7,
                _ => 9
            };
            Equal(expectedPrefixLength, columns[1].Length);
            True(
                columns[1].All(character =>
                    character is >= '0' and <= '9' or >= 'A' and <= 'F'),
                $"Prefixo IEEE inválido: {columns[1]}.");
            True(!string.IsNullOrWhiteSpace(columns[2]), "A organização IEEE não pode estar vazia.");

            entries++;
            registryCounts[columns[0]]++;
            prefixOccurrences[columns[1]] =
                prefixOccurrences.GetValueOrDefault(columns[1]) + 1;
        }

        Equal(58_166, entries);
        Equal(58_163, prefixOccurrences.Count);
        Equal(39_923, registryCounts["MA-L"]);
        Equal(6_540, registryCounts["MA-M"]);
        Equal(7_128, registryCounts["MA-S"]);
        Equal(4_575, registryCounts["IAB"]);
        Equal("LocalNetworkScanner.IEEE-MAC-Vendors/v1", metadata["format"]);
        Equal("2026-08-12", metadata["snapshotDate"]);
        Equal("58166", metadata["entries"]);
        Equal("58163", metadata["uniquePrefixes"]);
        Equal("IEEE. All rights reserved.", metadata["sourceCopyright"]);
        Equal(
            "Bundled for offline lookup; no IEEE endorsement implied.",
            metadata["notice"]);
        Equal("39923", metadata["count.MA-L"]);
        Equal("6540", metadata["count.MA-M"]);
        Equal("7128", metadata["count.MA-S"]);
        Equal("4575", metadata["count.IAB"]);
        Equal(
            "https://standards-oui.ieee.org/oui/oui.csv",
            metadata["source.MA-L"]);
        Equal(
            "https://standards-oui.ieee.org/oui28/mam.csv",
            metadata["source.MA-M"]);
        Equal(
            "https://standards-oui.ieee.org/oui36/oui36.csv",
            metadata["source.MA-S"]);
        Equal(
            "https://standards-oui.ieee.org/iab/iab.csv",
            metadata["source.IAB"]);
        Equal(
            "f4c224a540adc45c0c48233335c6241a420f1b85f3754bc379022c343c3d3e9d",
            metadata["sha256.MA-L"]);
        Equal(
            "29ec2874d7664610e3622aa157e6b81da53ed6e54912dd6de5e51c70b6b5a32c",
            metadata["sha256.MA-M"]);
        Equal(
            "7b2927f8857c62cf0638a0e4501076c4ad56df4c29b7ad1092d7dfa6ed7940b5",
            metadata["sha256.MA-S"]);
        Equal(
            "6e71aa3d47f00f19d09cb3b31ce1038de1834703420f0ce4ce111da586f1a533",
            metadata["sha256.IAB"]);
        Equal(2, prefixOccurrences["0001C8"]);
        Equal(3, prefixOccurrences["080030"]);
        Equal(
            2,
            prefixOccurrences.Count(item => item.Value > 1));
    })),
    ("Bundled IEEE vendor lookup coverage", () => Sync(() =>
    {
        string missingOverride = Path.Combine(
            Path.GetTempPath(),
            "LocalNetworkScanner.Tests",
            Guid.NewGuid().ToString("N"),
            "missing-vendors.tsv.gz");
        MacVendorService service = new(missingOverride);

        Equal(false, service.HasExternalDatabase);
        Equal(false, service.DatabaseInfo.IsDegraded);
        Equal("Incorporada", service.DatabaseInfo.Source);
        Equal(new DateOnly(2026, 8, 12), service.DatabaseInfo.SnapshotDate);
        Equal(58_166, service.DatabaseInfo.EntryCount);
        Equal(58_163, service.DatabaseInfo.UniquePrefixCount);
        Equal(39_923, service.DatabaseInfo.RegistryCounts["MA-L"]);
        Equal(6_540, service.DatabaseInfo.RegistryCounts["MA-M"]);
        Equal(7_128, service.DatabaseInfo.RegistryCounts["MA-S"]);
        Equal(4_575, service.DatabaseInfo.RegistryCounts["IAB"]);

        MacVendorMatch? large = service.LookupDetailed("00:0C:29:12:34:56");
        NotNull(large);
        Equal("VMware, Inc.", large!.Organization);
        Equal("MA-L", large.Registry);
        Equal(24, large.PrefixLength);

        MacVendorMatch? medium = service.LookupDetailed("C8:5C:E2:7A:BC:DE");
        NotNull(medium);
        Equal("SYNERGY SYSTEMS AND SOLUTIONS", medium!.Organization);
        Equal("MA-M", medium.Registry);
        Equal(28, medium.PrefixLength);

        MacVendorMatch? small = service.LookupDetailed("8C:1F:64:AF:A1:23");
        NotNull(small);
        Equal("DATA ELECTRONIC DEVICES, INC", small!.Organization);
        Equal("MA-S", small.Registry);
        Equal(36, small.PrefixLength);

        MacVendorMatch? legacy = service.LookupDetailed("00:50:C2:00:31:23");
        NotNull(legacy);
        Equal("Microsoft", legacy!.Organization);
        Equal("IAB", legacy.Registry);
        Equal(36, legacy.PrefixLength);
    })),
    ("Vendor lookup uses the longest prefix and parses quoted Unicode CSV", () => Sync(() =>
    {
        string directory = Path.Combine(
            Path.GetTempPath(),
            "LocalNetworkScanner.Tests",
            Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "vendors.csv");
        try
        {
            Directory.CreateDirectory(directory);
            File.WriteAllText(
                path,
                "Registry,Assignment,Organization Name,Organization Address\n" +
                "MA-L,00FFEE,\"Parent, S.A. – Lisboa\",Portugal\n" +
                "MA-M,00FFEEA,\"Médio & Filhos\",Portugal\n" +
                "MA-S,00FFEEABC,\"Específico, Lda.\",Portugal\n" +
                "IAB,00FFEEABD,\"Legado, Lda.\",Portugal\n",
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));

            MacVendorService service = new(path);
            Equal(true, service.HasExternalDatabase);
            Equal(4, service.DatabaseInfo.EntryCount);
            Equal(4, service.DatabaseInfo.UniquePrefixCount);

            MacVendorMatch? small = service.LookupDetailed("00:FF:EE:AB:C0:01");
            NotNull(small);
            Equal("Específico, Lda.", small!.Organization);
            Equal("MA-S", small.Registry);
            Equal("00FFEEABC", small.Prefix);
            Equal(36, small.PrefixLength);

            MacVendorMatch? legacy = service.LookupDetailed("00:FF:EE:AB:D0:01");
            NotNull(legacy);
            Equal("Legado, Lda.", legacy!.Organization);
            Equal("IAB", legacy.Registry);

            MacVendorMatch? medium = service.LookupDetailed("00:FF:EE:AF:00:01");
            NotNull(medium);
            Equal("Médio & Filhos", medium!.Organization);
            Equal("MA-M", medium.Registry);
            Equal(28, medium.PrefixLength);

            MacVendorMatch? large = service.LookupDetailed("00:FF:EE:BF:00:01");
            NotNull(large);
            Equal("Parent, S.A. – Lisboa", large!.Organization);
            Equal("MA-L", large.Registry);
            Equal(24, large.PrefixLength);
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    })),
    ("Historical vendor duplicates aggregate deterministically", () => Sync(() =>
    {
        string directory = Path.Combine(
            Path.GetTempPath(),
            "LocalNetworkScanner.Tests",
            Guid.NewGuid().ToString("N"));
        string firstPath = Path.Combine(directory, "duplicates-a.tsv");
        string secondPath = Path.Combine(directory, "duplicates-b.tsv");
        try
        {
            Directory.CreateDirectory(directory);
            string header = "Registry\tAssignment\tOrganization Name\n";
            File.WriteAllText(
                firstPath,
                header +
                "MA-L\t00FFEE\tÁrvore Networks\n" +
                "MA-L\t00FFEE\tZeta, S.A.\n" +
                "MA-L\t00FFEE\tÁrvore Networks\n",
                new UTF8Encoding(false));
            File.WriteAllText(
                secondPath,
                header +
                "MA-L\t00FFEE\tZeta, S.A.\n" +
                "MA-L\t00FFEE\tÁrvore Networks\n" +
                "MA-L\t00FFEE\tÁrvore Networks\n",
                new UTF8Encoding(false));

            MacVendorService first = new(firstPath);
            MacVendorService second = new(secondPath);
            const string macAddress = "00:FF:EE:12:34:56";
            string? firstOrganization = first.Lookup(macAddress);
            string? secondOrganization = second.Lookup(macAddress);

            Equal("Zeta, S.A. / Árvore Networks", firstOrganization);
            Equal(firstOrganization, secondOrganization);
            Equal(3, first.DatabaseInfo.EntryCount);
            Equal(1, first.DatabaseInfo.UniquePrefixCount);
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    })),
    ("Vendor lookup rejects non-global MAC identities", () => Sync(() =>
    {
        string missingOverride = Path.Combine(
            Path.GetTempPath(),
            "LocalNetworkScanner.Tests",
            Guid.NewGuid().ToString("N"),
            "missing-vendors.tsv.gz");
        MacVendorService service = new(missingOverride);

        Equal("MAC privado/aleatório", service.Lookup("02:00:00:00:00:01"));
        Equal<string?>(null, service.LookupDetailed("02:00:00:00:00:01")?.Organization);
        Equal<string?>(null, service.Lookup("01:00:5E:00:00:01"));
        Equal<string?>(null, service.Lookup("not-a-mac"));
        Equal<string?>(null, service.Lookup("00:00:00:00:00:00"));
        Equal<string?>(null, service.Lookup("FF:FF:FF:FF:FF:FF"));
    })),
    ("Corrupt external vendor database falls back to bundled snapshot", () => Sync(() =>
    {
        string directory = Path.Combine(
            Path.GetTempPath(),
            "LocalNetworkScanner.Tests",
            Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "vendors.tsv");
        try
        {
            Directory.CreateDirectory(directory);
            File.WriteAllText(
                path,
                "Registry\tAssignment\tOrganization Name\n" +
                "MA-L\tINVALID\tCorrupt entry\n",
                new UTF8Encoding(false));

            MacVendorService service = new(path);
            Equal(false, service.HasExternalDatabase);
            Equal("Incorporada", service.DatabaseInfo.Source);
            Equal(false, service.DatabaseInfo.IsDegraded);
            True(
                !string.IsNullOrWhiteSpace(service.ExternalDatabaseError),
                "A rejeição da base externa deveria ficar disponível para diagnóstico.");
            Equal("VMware, Inc.", service.Lookup("00:0C:29:12:34:56"));
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    })),
    ("Vendor lookups are safe under concurrency", async () =>
    {
        string missingOverride = Path.Combine(
            Path.GetTempPath(),
            "LocalNetworkScanner.Tests",
            Guid.NewGuid().ToString("N"),
            "missing-vendors.tsv.gz");
        MacVendorService service = new(missingOverride);
        string?[] results = await Task.WhenAll(
            Enumerable.Range(0, 512).Select(index => Task.Run(() =>
                (index % 4) switch
                {
                    0 => service.Lookup("00:0C:29:12:34:56"),
                    1 => service.Lookup("C8:5C:E2:7A:BC:DE"),
                    2 => service.Lookup("8C:1F:64:AF:A1:23"),
                    _ => service.Lookup("00:50:C2:00:31:23")
                })));

        Equal(128, results.Count(value => value == "VMware, Inc."));
        Equal(128, results.Count(value => value == "SYNERGY SYSTEMS AND SOLUTIONS"));
        Equal(128, results.Count(value => value == "DATA ELECTRONIC DEVICES, INC"));
        Equal(128, results.Count(value => value == "Microsoft"));
    }),
    ("Optional IEEE update is complete and atomic", async () =>
    {
        string directory = Path.Combine(
            Path.GetTempPath(),
            "LocalNetworkScanner.Tests",
            Guid.NewGuid().ToString("N"));
        string databasePath = Path.Combine(directory, "vendor-database.tsv.gz");
        IReadOnlyList<OuiDatabaseSource> sources =
        [
            new(
                "MA-L",
                "mal.csv",
                "https://fixtures.invalid/mal.csv",
                6,
                1,
                10,
                4_096),
            new(
                "MA-M",
                "mam.csv",
                "https://fixtures.invalid/mam.csv",
                7,
                1,
                10,
                4_096),
            new(
                "MA-S",
                "mas.csv",
                "https://fixtures.invalid/mas.csv",
                9,
                1,
                10,
                4_096),
            new(
                "IAB",
                "iab.csv",
                "https://fixtures.invalid/iab.csv",
                9,
                1,
                10,
                4_096)
        ];
        Dictionary<string, string> initialBodies = new(StringComparer.Ordinal)
        {
            ["/mal.csv"] = VendorCsv("MA-L", "00FFEE", "Inicial MA-L"),
            ["/mam.csv"] = VendorCsv("MA-M", "00FFEEA", "Inicial MA-M"),
            ["/mas.csv"] = VendorCsv("MA-S", "00FFEEABC", "Inicial,\nMA-S"),
            ["/iab.csv"] = VendorCsv("IAB", "00FFEEABD", "Inicial IAB")
        };

        try
        {
            Directory.CreateDirectory(directory);
            List<string> requests = [];
            using HttpClient initialClient = new(new StubHttpMessageHandler(
                (request, _) =>
                {
                    string path = request.RequestUri!.AbsolutePath;
                    requests.Add(path);
                    return Task.FromResult(CsvResponse(initialBodies[path]));
                }));
            OuiDatabaseService initialUpdater = new(
                initialClient,
                databasePath,
                sources);
            string updatedPath = await initialUpdater.UpdateAsync();

            Equal(Path.GetFullPath(databasePath), updatedPath);
            Equal(true, File.Exists(databasePath));
            Equal(4, requests.Count);
            Equal(4, requests.Distinct(StringComparer.Ordinal).Count());
            True(
                initialClient.DefaultRequestHeaders.UserAgent.Any(item =>
                    item.Product?.Name == ProductIdentity.Name),
                "O updater deveria identificar o produto no User-Agent.");
            Equal(0, Directory.GetDirectories(directory, ".vendor-update-*").Length);

            MacVendorService updated = new(databasePath);
            Equal(true, updated.HasExternalDatabase);
            Equal(4, updated.DatabaseInfo.EntryCount);
            Equal(4, updated.DatabaseInfo.UniquePrefixCount);
            Equal("Inicial, MA-S", updated.Lookup("00:FF:EE:AB:C0:01"));
            Equal("Inicial MA-M", updated.Lookup("00:FF:EE:AF:00:01"));
            Equal("Inicial MA-L", updated.Lookup("00:FF:EE:BF:00:01"));
            Equal("Inicial IAB", updated.Lookup("00:FF:EE:AB:D0:01"));
            Throws<InvalidDataException>(() =>
                MacVendorService.ValidateCompleteDatabaseFile(databasePath, "Teste parcial"));

            byte[] originalDatabase = await File.ReadAllBytesAsync(databasePath);
            Dictionary<string, string> replacementBodies = new(StringComparer.Ordinal)
            {
                ["/mal.csv"] = VendorCsv("MA-L", "00FFEE", "Substituição MA-L"),
                ["/mam.csv"] = VendorCsv("MA-M", "00FFEEA", "Substituição MA-M"),
                ["/mas.csv"] = VendorCsv("MA-S", "00FFEEABC", "Substituição MA-S"),
                ["/iab.csv"] = VendorCsv("IAB", "00FFEEABD", "Substituição IAB")
            };
            using HttpClient failingClient = new(new StubHttpMessageHandler(
                (request, _) =>
                {
                    string path = request.RequestUri!.AbsolutePath;
                    if (path == "/mas.csv")
                    {
                        return Task.FromResult(
                            new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
                    }

                    return Task.FromResult(CsvResponse(replacementBodies[path]));
                }));
            OuiDatabaseService failingUpdater = new(
                failingClient,
                databasePath,
                sources,
                Path.Combine(directory, "legacy-oui.csv"));

            await ThrowsAsync<HttpRequestException>(() => failingUpdater.UpdateAsync());
            Equal(
                Convert.ToHexString(SHA256.HashData(originalDatabase)),
                Convert.ToHexString(SHA256.HashData(
                    await File.ReadAllBytesAsync(databasePath))));
            Equal(0, Directory.GetDirectories(directory, ".vendor-update-*").Length);
            Equal(
                "Inicial, MA-S",
                new MacVendorService(databasePath).Lookup("00:FF:EE:AB:C0:01"));

            string legacyPath = Path.Combine(directory, "legacy-oui.csv");
            await File.WriteAllTextAsync(
                legacyPath,
                VendorCsv("MA-L", "001122", "Legado"));
            Equal(true, failingUpdater.ResetLocalDatabase());
            Equal(false, File.Exists(databasePath));
            Equal(false, File.Exists(legacyPath));
            Equal(false, failingUpdater.ResetLocalDatabase());
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }),
    ("NetBIOS request", () => Sync(() =>
    {
        byte[] request = NetBiosDiscoveryService.BuildNodeStatusRequest();
        Equal(50, request.Length);
        Equal((ushort)1, BinaryPrimitives.ReadUInt16BigEndian(request.AsSpan(4, 2)));
        Equal((ushort)0x21, BinaryPrimitives.ReadUInt16BigEndian(request.AsSpan(46, 2)));
    })),
    ("NetBIOS response", () => Sync(() =>
    {
        NetBiosInfo? info = NetBiosDiscoveryService.ParseNodeStatusResponse(BuildNetBiosResponse(), 7);
        NotNull(info);
        Equal("MY-PC", info!.ComputerName);
        Equal("WORKGROUP", info.Workgroup);
        Equal("00:11:22:33:44:55", info.MacAddress);
        Equal(null, NetBiosDiscoveryService.ParseNodeStatusResponse(BuildNetBiosResponse(), 8));
    })),
    ("WS-Discovery response", () => Sync(() =>
    {
        const string messageId = "urn:uuid:11111111-2222-3333-4444-555555555555";
        byte[] xml = Encoding.UTF8.GetBytes(
            $"<e:Envelope xmlns:e='urn:e' xmlns:d='urn:d' xmlns:a='urn:a'><e:Header><a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</a:Action><a:RelatesTo>{messageId}</a:RelatesTo></e:Header><e:Body><d:ProbeMatches><d:ProbeMatch><d:Types>dn:NetworkVideoTransmitter</d:Types><d:XAddrs>http://192.168.1.9/onvif/device_service</d:XAddrs></d:ProbeMatch></d:ProbeMatches></e:Body></e:Envelope>");
        IReadOnlyList<WsDiscoveryMatch> matches = WsDiscoveryService.ParseResponse(
            xml,
            messageId,
            IPAddress.Parse("192.168.1.200"));
        Equal(1, matches.Count);
        Equal(IPAddress.Parse("192.168.1.200"), matches[0].Address);
        Equal("dn:NetworkVideoTransmitter", matches[0].Types);
        Equal("http://192.168.1.9/onvif/device_service", matches[0].XAddresses);
        True(!matches[0].Address.Equals(IPAddress.Parse("192.168.1.9")),
            "Um XAddr anunciado não pode fazer outro IP parecer online.");
        Equal(0, WsDiscoveryService.ParseResponse(
            xml,
            "urn:uuid:wrong",
            IPAddress.Parse("192.168.1.200")).Count);

        byte[] spoofedPublicTarget = Encoding.UTF8.GetBytes(
            $"<e:Envelope xmlns:e='urn:e' xmlns:d='urn:d' xmlns:a='urn:a'>" +
            $"<e:Header><a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</a:Action>" +
            $"<a:RelatesTo>{messageId}</a:RelatesTo></e:Header>" +
            "<e:Body><d:ProbeMatches><d:ProbeMatch>" +
            "<d:Types>dn:NetworkVideoTransmitter</d:Types>" +
            "<d:XAddrs>http://8.8.8.8/onvif/device_service</d:XAddrs>" +
            "</d:ProbeMatch></d:ProbeMatches></e:Body></e:Envelope>");
        IReadOnlyList<WsDiscoveryMatch> spoofedMatches = WsDiscoveryService.ParseResponse(
            spoofedPublicTarget,
            messageId,
            IPAddress.Parse("192.168.1.201"));
        Equal(1, spoofedMatches.Count);
        Equal(IPAddress.Parse("192.168.1.201"), spoofedMatches[0].Address);
        Equal("http://8.8.8.8/onvif/device_service", spoofedMatches[0].XAddresses);
    })),
    ("SNMP request and response", () => Sync(() =>
    {
        byte[] request = SnmpClientService.BuildRequest(42, "public", "1.3.6.1.2.1.1.5.0", useGetNext: false);
        True(request.Length > 20, "O pedido SNMP deveria conter um PDU completo.");
        SnmpResponse response = SnmpClientService.ParseResponse(BuildSnmpResponse());
        Equal(42, response.RequestId);
        Equal(1, response.Version);
        Equal("public", response.Community);
        Equal(0, response.ErrorStatus);
        NotNull(response.Variable);
        Equal("1.3.6.1.2.1.1.5.0", response.Variable!.Oid);
        Equal("switch-core", response.Variable.TextValue);
    })),
    ("LLDP remote index and binary identifiers", () => Sync(() =>
    {
        const string firstIndex = ".100.7.1";
        const string secondIndex = ".100.7.2";
        IReadOnlyList<LldpNeighborObservation> neighbors = SnmpTopologyService.ParseLldpNeighbors(
            [
                new SnmpVariable(SnmpTopologyService.LldpLocalPortSubtypeRoot + ".7", 5, null)
            ],
            [
                new SnmpVariable(
                    SnmpTopologyService.LldpLocalPortIdRoot + ".7",
                    null,
                    "Gi1/0/7",
                    Encoding.ASCII.GetBytes("Gi1/0/7"))
            ],
            [
                new SnmpVariable(
                    SnmpTopologyService.LldpLocalPortDescriptionRoot + ".7",
                    null,
                    "Uplink de distribuição")
            ],
            [
                new SnmpVariable(SnmpTopologyService.LldpRemoteChassisSubtypeRoot + firstIndex, 4, null),
                new SnmpVariable(SnmpTopologyService.LldpRemoteChassisSubtypeRoot + secondIndex, 4, null),
                new SnmpVariable(SnmpTopologyService.LldpRemoteChassisSubtypeRoot + ".100.7", 4, null),
                new SnmpVariable(SnmpTopologyService.LldpRemoteChassisSubtypeRoot + ".100.5000.3", 4, null)
            ],
            [
                new SnmpVariable(
                    SnmpTopologyService.LldpRemoteChassisIdRoot + firstIndex,
                    null,
                    null,
                    [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                new SnmpVariable(
                    SnmpTopologyService.LldpRemoteChassisIdRoot + secondIndex,
                    null,
                    null,
                    [0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
            ],
            [
                new SnmpVariable(SnmpTopologyService.LldpRemotePortSubtypeRoot + firstIndex, 5, null),
                new SnmpVariable(SnmpTopologyService.LldpRemotePortSubtypeRoot + secondIndex, 5, null)
            ],
            [
                new SnmpVariable(
                    SnmpTopologyService.LldpRemotePortIdRoot + firstIndex,
                    null,
                    "Ethernet1/1",
                    Encoding.ASCII.GetBytes("Ethernet1/1")),
                new SnmpVariable(
                    SnmpTopologyService.LldpRemotePortIdRoot + secondIndex,
                    null,
                    "Ethernet1/2",
                    Encoding.ASCII.GetBytes("Ethernet1/2"))
            ],
            [],
            [
                new SnmpVariable(SnmpTopologyService.LldpRemoteSystemNameRoot + firstIndex, null, "dist-a"),
                new SnmpVariable(SnmpTopologyService.LldpRemoteSystemNameRoot + secondIndex, null, "dist-a"),
                new SnmpVariable(SnmpTopologyService.LldpRemoteSystemNameRoot + ".4000000000.8.1", null, "edge-z")
            ],
            []);

        Equal(3, neighbors.Count);
        Equal(100u, neighbors[0].TimeMark);
        Equal(7, neighbors[0].LocalPortNumber);
        Equal(1, neighbors[0].RemoteIndex);
        Equal(2, neighbors[1].RemoteIndex);
        Equal("00:11:22:33:44:55", neighbors[0].ChassisId);
        Equal("Gi1/0/7", neighbors[0].LocalPortId);
        Equal(5, neighbors[0].LocalPortIdSubtype);
        Equal(4_000_000_000u, neighbors[2].TimeMark);
    })),
    ("mDNS A record", () => Sync(() =>
    {
        IReadOnlyList<(IPAddress Address, string? Hostname)> records =
            MdnsDiscoveryService.ParseAddressRecords(BuildMdnsResponse());
        Equal(1, records.Count);
        Equal("printer.local", records[0].Hostname);
        Equal(IPAddress.Parse("192.168.1.50"), records[0].Address);
    })),
    ("mDNS compressed DNS-SD records preserve typed evidence", () => Sync(() =>
    {
        byte[] packet = BuildCompressedDnsSdResponse();
        True(
            MdnsDiscoveryService.IsValidResponse(packet, sourcePort: 5353),
            "Uma resposta mDNS autoritativa com ID zero e origem 5353 deveria ser aceite.");

        byte[] queryPacket = (byte[])packet.Clone();
        BinaryPrimitives.WriteUInt16BigEndian(queryPacket.AsSpan(2, 2), 0);
        True(!MdnsDiscoveryService.IsValidResponse(queryPacket, sourcePort: 5353),
            "Uma query UDP não pode ser acumulada como resposta mDNS.");

        byte[] foreignTransaction = (byte[])packet.Clone();
        BinaryPrimitives.WriteUInt16BigEndian(foreignTransaction.AsSpan(0, 2), 7);
        True(!MdnsDiscoveryService.IsValidResponse(foreignTransaction, sourcePort: 5353),
            "Uma transação alheia não pode ser acumulada.");

        byte[] unsupportedOpcode = (byte[])packet.Clone();
        BinaryPrimitives.WriteUInt16BigEndian(unsupportedOpcode.AsSpan(2, 2), 0x8800);
        True(!MdnsDiscoveryService.IsValidResponse(unsupportedOpcode, sourcePort: 5353),
            "Um opcode DNS não suportado deve ser rejeitado.");
        True(!MdnsDiscoveryService.IsValidResponse(packet, sourcePort: 9999),
            "A resposta deve ter origem na porta mDNS.");

        MdnsDiscoveryService.MdnsMessage message = MdnsDiscoveryService.ParseMessage(packet);

        Equal(5, message.Records.Count);

        MdnsDiscoveryService.MdnsResourceRecord pointer =
            message.Records.Single(record => record.Type == 12);
        Equal("_ipp._tcp.local", pointer.Owner);
        Equal("Office Printer._ipp._tcp.local", pointer.DomainName);
        Equal((ushort)1, pointer.RecordClass);
        Equal(120u, pointer.TimeToLive);

        MdnsDiscoveryService.MdnsResourceRecord service =
            message.Records.Single(record => record.Type == 33);
        Equal("Office Printer._ipp._tcp.local", service.Owner);
        Equal("printer.local", service.DomainName);
        Equal((ushort?)631, service.Port);
        Equal((ushort?)0, service.Priority);
        Equal((ushort?)5, service.Weight);

        MdnsDiscoveryService.MdnsResourceRecord text =
            message.Records.Single(record => record.Type == 16);
        NotNull(text.Text);
        Equal("ty=Laser,note=Lab", string.Join(',', text.Text!));

        MdnsDiscoveryService.MdnsResourceRecord ipv4 =
            message.Records.Single(record => record.Type == 1);
        Equal((ushort)1, ipv4.RecordClass);
        Equal(0u, ipv4.TimeToLive);
        Equal(IPAddress.Parse("192.168.1.50"), ipv4.Address);

        MdnsDiscoveryService.MdnsResourceRecord ipv6 =
            message.Records.Single(record => record.Type == 28);
        Equal(IPAddress.Parse("fd00::50"), ipv6.Address);
        Equal(60u, ipv6.TimeToLive);

        IReadOnlyList<(IPAddress Address, string? Hostname)> addresses =
            MdnsDiscoveryService.ParseAddressRecords(packet);
        Equal(2, addresses.Count);
        True(
            addresses.Any(record =>
                record.Address.Equals(IPAddress.Parse("192.168.1.50")) &&
                record.Hostname == "printer.local"),
            "O registo A comprimido deveria manter o hostname.");
        True(
            addresses.Any(record =>
                record.Address.Equals(IPAddress.Parse("fd00::50")) &&
                record.Hostname == "printer.local"),
            "O registo AAAA comprimido deveria manter o hostname.");

        IReadOnlyList<DiscoveryObservation> observations =
            MdnsDiscoveryService.CorrelateRecords(message.Records);
        Equal(2, observations.Count);
        Equal(IPAddress.Parse("fd00::50"), observations[0].IpAddress);
        Equal("printer.local", observations[0].Hostname);
        Equal("Office Printer._ipp._tcp.local", observations[1].Hostname);
        Equal("Laser", observations[1].Model);
        Equal("Office Printer", observations[1].FriendlyName);
        Equal("Impressora", observations[1].DeviceType);
        Equal(631, observations[1].ServicePort);
        Equal("TCP", observations[1].ServiceTransport);
        Equal("printer.local:631/tcp", observations[1].Location);
        True(
            observations[1].EvidenceSource.Contains("TCP/631", StringComparison.Ordinal),
            "A evidência DNS-SD deve manter transporte e porta SRV.");
        Equal<string?>(null, observations[1].Manufacturer);
        string typedValues = string.Join('|',
            typeof(DiscoveryObservation).GetProperties()
                .Where(property => property.PropertyType == typeof(string))
                .Select(property => property.GetValue(observations[1]) as string)
                .Where(value => value is not null));
        True(!typedValues.Contains("note=Lab", StringComparison.Ordinal),
            "Campos TXT fora da allowlist não podem contaminar a identidade tipada.");
        True(
            observations.All(observation =>
                !observation.IpAddress.Equals(IPAddress.Parse("192.168.1.50"))),
            "Um registo com TTL zero não pode criar uma observação final.");

        const string identityInstance = "Lab Printer._ipp._tcp.local";
        IReadOnlyList<DiscoveryObservation> typedIdentity =
            MdnsDiscoveryService.CorrelateRecords(
            [
                new MdnsDiscoveryService.MdnsResourceRecord(
                    "lab-printer.local",
                    1,
                    1,
                    120,
                    Address: IPAddress.Parse("192.168.1.90")),
                new MdnsDiscoveryService.MdnsResourceRecord(
                    "_ipp._tcp.local",
                    12,
                    1,
                    120,
                    DomainName: identityInstance),
                new MdnsDiscoveryService.MdnsResourceRecord(
                    identityInstance,
                    33,
                    1,
                    120,
                    DomainName: "lab-printer.local",
                    Port: 631),
                new MdnsDiscoveryService.MdnsResourceRecord(
                    identityInstance,
                    16,
                    1,
                    120,
                    Text:
                    [
                        "manufacturer=Acme Printing",
                        "model=Laser 9000",
                        "note=private lab",
                        "password=private-value",
                        "serial=SN-private"
                    ])
            ]);
        DiscoveryObservation identityObservation = typedIdentity.Single(observation =>
            observation.UniqueServiceName == identityInstance);
        Equal("Acme Printing", identityObservation.Manufacturer);
        Equal("Laser 9000", identityObservation.Model);
        Equal(631, identityObservation.ServicePort);
        Equal("TCP", identityObservation.ServiceTransport);
        Equal("lab-printer.local:631/tcp", identityObservation.Location);
        string identityValues = string.Join('|',
            typeof(DiscoveryObservation).GetProperties()
                .Where(property => property.PropertyType == typeof(string))
                .Select(property => property.GetValue(identityObservation) as string)
                .Where(value => value is not null));
        True(!identityValues.Contains("private lab", StringComparison.Ordinal) &&
             !identityValues.Contains("private-value", StringComparison.Ordinal) &&
             !identityValues.Contains("SN-private", StringComparison.Ordinal),
            "TXT não aprovado não deve ser exposto como identidade do dispositivo.");

        MdnsDiscoveryService.MdnsResourceRecord addressEvidence = new(
            "camera.local",
            1,
            1,
            120,
            Address: IPAddress.Parse("192.168.1.80"));
        DiscoveryObservation isolatedAnnouncement = MdnsDiscoveryService.CorrelateRecords(
            [addressEvidence],
            IPAddress.Parse("192.168.1.81")).Single();
        Equal(false, isolatedAnnouncement.HasDirectAddressEvidence);
        True(
            !NetworkScannerService.CanPromoteMulticastObservation(isolatedAnnouncement),
            "Um A/AAAA anunciado por outro remetente não pode promover um host.");

        DiscoveryObservation directAnnouncement = MdnsDiscoveryService.CorrelateRecords(
            [addressEvidence],
            addressEvidence.Address).Single();
        Equal(true, directAnnouncement.HasDirectAddressEvidence);
        True(
            NetworkScannerService.CanPromoteMulticastObservation(directAnnouncement),
            "O remetente que confirma o próprio A/AAAA pode promover o host.");

        MdnsDiscoveryService.MdnsResourceRecord serviceEvidence = new(
            "Front Door._rtsp._tcp.local",
            33,
            1,
            120,
            DomainName: "camera.local",
            Port: 554);
        MdnsDiscoveryService.MdnsResourceRecord serviceGoodbye =
            serviceEvidence with { TimeToLive = 0 };
        IReadOnlyList<DiscoveryObservation> hostOnly =
            MdnsDiscoveryService.CorrelateRecords(
                [addressEvidence, serviceEvidence, serviceGoodbye]);
        Equal(1, hostOnly.Count);
        Equal("camera.local", hostOnly[0].Hostname);

        MdnsDiscoveryService.MdnsResourceRecord addressGoodbye =
            addressEvidence with { TimeToLive = 0 };
        Equal(
            0,
            MdnsDiscoveryService.CorrelateRecords(
                [addressEvidence, serviceEvidence, addressGoodbye]).Count);
    })),
    ("mDNS parser and query limits fail closed", () => Sync(() =>
    {
        byte[] excessiveQuestions = new byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(excessiveQuestions.AsSpan(4, 2), 65);
        Equal(0, MdnsDiscoveryService.ParseMessage(excessiveQuestions).Records.Count);

        byte[] excessiveRecords = new byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(excessiveRecords.AsSpan(6, 2), 257);
        Equal(0, MdnsDiscoveryService.ParseMessage(excessiveRecords).Records.Count);

        byte[] oversizedPacket = new byte[(16 * 1024) + 1];
        Equal(0, MdnsDiscoveryService.ParseMessage(oversizedPacket).Records.Count);

        byte[] cyclicPointer = new byte[18];
        BinaryPrimitives.WriteUInt16BigEndian(cyclicPointer.AsSpan(4, 2), 1);
        cyclicPointer[12] = 0xC0;
        cyclicPointer[13] = 0x0C;
        Equal(0, MdnsDiscoveryService.ParseMessage(cyclicPointer).Records.Count);

        byte[] truncatedPointer = new byte[13];
        BinaryPrimitives.WriteUInt16BigEndian(truncatedPointer.AsSpan(4, 2), 1);
        truncatedPointer[12] = 0xC0;
        Equal(0, MdnsDiscoveryService.ParseMessage(truncatedPointer).Records.Count);

        Throws<ArgumentException>(() => MdnsDiscoveryService.BuildQuery(" "));
        Throws<ArgumentOutOfRangeException>(() =>
            MdnsDiscoveryService.BuildQuery("_ipp._tcp.local", 0));
        Throws<ArgumentException>(() =>
            MdnsDiscoveryService.BuildQuery($"{new string('a', 64)}.local"));
        Throws<ArgumentException>(() =>
            MdnsDiscoveryService.BuildQuery(
                string.Join('.', Enumerable.Repeat(new string('a', 63), 4))));

        byte[] serviceQuery = MdnsDiscoveryService.BuildQuery("_ipp._tcp.local.", 33);
        Equal((ushort)1, BinaryPrimitives.ReadUInt16BigEndian(serviceQuery.AsSpan(4, 2)));
        Equal((ushort)33, BinaryPrimitives.ReadUInt16BigEndian(
            serviceQuery.AsSpan(serviceQuery.Length - 4, 2)));
        Equal((ushort)0x8001, BinaryPrimitives.ReadUInt16BigEndian(
            serviceQuery.AsSpan(serviceQuery.Length - 2, 2)));

        byte[] pointerQuery = MdnsDiscoveryService.BuildQuery("_ipp._tcp.local");
        Equal((ushort)12, BinaryPrimitives.ReadUInt16BigEndian(
            pointerQuery.AsSpan(pointerQuery.Length - 4, 2)));
    })),
    ("Risk score", () => Sync(() =>
    {
        NetworkDevice device = new()
        {
            IpAddress = IPAddress.Parse("192.168.1.20"),
            Ports =
            [
                new PortScanResult { Port = 23 },
                new PortScanResult { Port = 2375 }
            ]
        };
        new SecurityAssessmentService().Assess(device);
        Equal("Alto", device.RiskLevel);
        True(device.RiskScore >= 60, "A pontuação deveria refletir serviços críticos.");
    })),
    ("Topology evidence", () => Sync(() =>
    {
        LocalNetworkInterface network = CreateInterface();
        NetworkDevice device = new()
        {
            IpAddress = IPAddress.Parse("192.168.1.20"),
            MacAddress = "00:11:22:33:44:55",
            DiscoveryMethods = DiscoveryMethod.Arp
        };
        TopologyAssessment assessment = new TopologyInferenceService().Assess(device, network);
        Equal(true, assessment.SameLayer2Segment);
        Equal(null, assessment.SamePhysicalSwitch);
    })),
    ("NetBIOS MAC is not ARP evidence", () => Sync(() =>
    {
        NetworkDevice device = new()
        {
            IpAddress = IPAddress.Parse("192.168.1.21"),
            MacAddress = "00:11:22:33:44:66",
            DiscoveryMethods = DiscoveryMethod.NetBios
        };
        TopologyAssessment assessment = new TopologyInferenceService().Assess(device, CreateInterface());
        Equal(null, assessment.SameLayer2Segment);
    })),
    ("SNMP FDB does not prove physical switch", () => Sync(() =>
    {
        LocalNetworkInterface network = CreateInterface();
        NetworkDevice device = new()
        {
            IpAddress = IPAddress.Parse("192.168.1.30"),
            MacAddress = "00:11:22:33:44:77"
        };
        SnmpTopologySnapshot snapshot = new()
        {
            SwitchAddress = IPAddress.Parse("192.168.1.2"),
            SwitchName = "core-switch",
            MacTable = new Dictionary<string, IReadOnlyList<SwitchPortObservation>>(StringComparer.OrdinalIgnoreCase)
            {
                ["00:11:22:33:44:77"] =
                [
                    new SwitchPortObservation
                    {
                        MacAddress = "00:11:22:33:44:77",
                        BridgePort = 7,
                        InterfaceName = "Gi1/0/7",
                        VlanId = 20,
                        PortPvid = 1,
                        ForwardingDatabaseId = 200
                    }
                ]
            }
        };
        new SnmpTopologyService().Apply(snapshot, [device], network);
        Equal(true, device.Topology.ObservedOnManagedBridge);
        Equal(null, device.Topology.SamePhysicalSwitch);
        Equal(20, device.Topology.VlanId);
        Equal(1, device.Topology.SwitchPortPvid);
    })),
    ("Network map preserves evidence semantics", () => Sync(() =>
    {
        LocalNetworkInterface network = CreateInterface();
        NetworkDevice arpDevice = new()
        {
            IpAddress = IPAddress.Parse("192.168.1.30"),
            Hostname = "workstation",
            MacAddress = "00:11:22:33:44:77",
            IsOnline = true,
            DiscoveryMethods = DiscoveryMethod.Arp,
            RiskLevel = "Médio",
            Topology = new TopologyAssessment
            {
                SameIpSubnet = true,
                SameLayer2Segment = true,
                Layer2Confidence = ConfidenceLevel.Medium,
                ObservedOnManagedBridge = true,
                SwitchAddress = "192.168.1.2",
                SwitchConfidence = ConfidenceLevel.High
            }
        };
        NetworkDevice routedDevice = new()
        {
            IpAddress = IPAddress.Parse("192.168.1.40"),
            IsOnline = true,
            DiscoveryMethods = DiscoveryMethod.Icmp
        };
        SnmpTopologySnapshot snapshot = new()
        {
            SwitchAddress = IPAddress.Parse("192.168.1.2"),
            SwitchName = "access-a",
            MacTable = new Dictionary<string, IReadOnlyList<SwitchPortObservation>>(StringComparer.OrdinalIgnoreCase)
            {
                ["00:11:22:33:44:77"] =
                [
                    new SwitchPortObservation
                    {
                        MacAddress = "00:11:22:33:44:77",
                        BridgePort = 7,
                        InterfaceName = "Gi1/0/7"
                    },
                    new SwitchPortObservation
                    {
                        MacAddress = "00:11:22:33:44:77",
                        BridgePort = 48,
                        InterfaceName = "Gi1/0/48"
                    }
                ]
            },
            LldpNeighbors =
            [
                CreateLldpNeighbor(500, 7, 1, "dist-a"),
                CreateLldpNeighbor(500, 7, 2, "dist-a")
            ]
        };
        NetworkScanResult result = new()
        {
            NetworkInterface = network,
            StartedAt = new DateTimeOffset(2026, 7, 21, 10, 0, 0, TimeSpan.Zero),
            CompletedAt = new DateTimeOffset(2026, 7, 21, 10, 0, 5, TimeSpan.Zero),
            AddressesScanned = 254,
            Devices = [arpDevice, routedDevice],
            SnmpTopology = snapshot
        };

        NetworkTopologyMapService service = new();
        NetworkMap map = service.Build(result);
        NetworkMap second = service.Build(result);

        Equal(network.NetworkCidr, map.NetworkCidr);
        Equal(result.CompletedAt, map.GeneratedAt);
        Equal(
            string.Join('|', map.Nodes.Select(node => node.Id)),
            string.Join('|', second.Nodes.Select(node => node.Id)));
        Equal(2, map.Nodes.Count(node => node.Kind == NetworkMapNodeKind.LldpNeighbor));
        Equal(1, map.Nodes.Count(node =>
            node.Kind == NetworkMapNodeKind.LldpNeighbor && node.MacAddress is not null));
        Equal(2, map.Edges.Count(edge => edge.Kind == NetworkMapEdgeKind.LldpNeighbor));
        Equal(2, map.Edges.Count(edge => edge.Kind == NetworkMapEdgeKind.MacLearned));
        Equal(1, map.Edges.Count(edge => edge.Kind == NetworkMapEdgeKind.Layer2Observed));
        Equal(1, map.Edges.Count(edge => edge.Kind == NetworkMapEdgeKind.IpReachability));
        True(map.Edges
                .Where(edge => edge.Kind == NetworkMapEdgeKind.MacLearned)
                .All(edge => edge.Evidence.Contains("não prova ligação física direta", StringComparison.Ordinal)),
            "Uma entrada FDB nunca pode ser apresentada como prova de ligação física.");

        HashSet<string> nodeIds = map.Nodes.Select(node => node.Id).ToHashSet(StringComparer.Ordinal);
        True(map.Edges.All(edge => nodeIds.Contains(edge.SourceId) && nodeIds.Contains(edge.TargetId)),
            "Todas as ligações do mapa devem referenciar nós existentes.");
    })),
    ("Network map rejects fabricated topology", () => Sync(() =>
    {
        NetworkDevice device = new()
        {
            IpAddress = IPAddress.Parse("192.168.1.50"),
            IsOnline = true,
            DiscoveryMethods = DiscoveryMethod.Tcp,
            Topology = new TopologyAssessment
            {
                ObservedOnManagedBridge = true,
                SwitchAddress = "not-an-ip",
                SamePhysicalSwitch = true
            }
        };
        NetworkScanResult result = new()
        {
            NetworkInterface = CreateInterface(),
            StartedAt = DateTimeOffset.UtcNow.AddSeconds(-1),
            CompletedAt = DateTimeOffset.UtcNow,
            AddressesScanned = 1,
            Devices = [device]
        };

        NetworkMap map = new NetworkTopologyMapService().Build(result);
        Equal(0, map.Nodes.Count(node => node.Kind == NetworkMapNodeKind.ManagedSwitch));
        Equal(0, map.Edges.Count(edge => edge.Kind == NetworkMapEdgeKind.MacLearned));
        Equal(1, map.Edges.Count(edge => edge.Kind == NetworkMapEdgeKind.IpReachability));
    })),
    ("Gateway and managed switch share one node", () => Sync(() =>
    {
        LocalNetworkInterface network = CreateInterface();
        NetworkDevice gatewayDevice = new()
        {
            IpAddress = network.GatewayAddress!,
            MacAddress = "00:01:02:03:04:05",
            IsOnline = true,
            DiscoveryMethods = DiscoveryMethod.Arp
        };
        SnmpTopologySnapshot snapshot = new()
        {
            SwitchAddress = network.GatewayAddress!,
            SwitchName = "router-switch",
            MacTable = new Dictionary<string, IReadOnlyList<SwitchPortObservation>>(StringComparer.OrdinalIgnoreCase)
            {
                ["00:01:02:03:04:05"] =
                [
                    new SwitchPortObservation
                    {
                        MacAddress = "00:01:02:03:04:05",
                        BridgePort = 1
                    }
                ]
            },
            LldpNeighbors = [CreateLldpNeighbor(10, 1, 1, "access-b")]
        };
        NetworkScanResult result = new()
        {
            NetworkInterface = network,
            StartedAt = DateTimeOffset.UtcNow.AddSeconds(-1),
            CompletedAt = DateTimeOffset.UtcNow,
            AddressesScanned = 1,
            Devices = [gatewayDevice],
            SnmpTopology = snapshot
        };

        NetworkMap map = new NetworkTopologyMapService().Build(result);
        NetworkMapNode[] nodesAtGateway = map.Nodes
            .Where(node => node.IpAddress?.Equals(network.GatewayAddress) == true)
            .ToArray();
        Equal(1, nodesAtGateway.Length);
        Equal(NetworkMapNodeKind.Gateway, nodesAtGateway[0].Kind);
        Equal("Gateway / switch gerido", nodesAtGateway[0].DeviceType);
        Equal(0, map.Nodes.Count(node => node.Kind == NetworkMapNodeKind.ManagedSwitch));
        Equal(0, map.Edges.Count(edge =>
            edge.Kind == NetworkMapEdgeKind.MacLearned && edge.SourceId == edge.TargetId));
        Equal(1, map.Edges.Count(edge =>
            edge.Kind == NetworkMapEdgeKind.LldpNeighbor &&
            edge.SourceId == nodesAtGateway[0].Id));
    })),
    ("History comparison state", async () =>
    {
        string directory = Path.Combine(Path.GetTempPath(), "LocalNetworkScanner.Tests", Guid.NewGuid().ToString("N"));
        try
        {
            NetworkDevice device = new()
            {
                IpAddress = IPAddress.Parse("192.168.1.40"),
                MacAddress = "0:01122334455"
            };
            Equal("Não comparado", device.HistoryText);
            NetworkScanResult result = new()
            {
                NetworkInterface = CreateInterface(),
                StartedAt = DateTimeOffset.UtcNow.AddSeconds(-1),
                CompletedAt = DateTimeOffset.UtcNow,
                AddressesScanned = 1,
                Devices = [device]
            };

            await new NetworkHistoryService(directory).ApplyAndSaveAsync(result);
            Equal(true, device.HistoryCompared);
            Equal(true, device.IsNew);
            Equal("Novo", device.HistoryText);
            string snapshot = await File.ReadAllTextAsync(Directory.GetFiles(directory, "*.json").Single());
            True(!snapshot.Contains("0:01122334455", StringComparison.Ordinal),
                "Um MAC inválido não pode ser persistido no histórico.");
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }),
    ("History preserves identity across IP and MAC transitions", async () =>
    {
        string directory = Path.Combine(Path.GetTempPath(), "LocalNetworkScanner.Tests", Guid.NewGuid().ToString("N"));
        try
        {
            NetworkHistoryService history = new(directory);
            DateTimeOffset firstSeen = new(2026, 7, 20, 10, 0, 0, TimeSpan.Zero);
            NetworkDevice first = new()
            {
                IpAddress = IPAddress.Parse("192.168.1.40"),
                Hostname = "printer",
                FirstSeen = firstSeen,
                LastSeen = firstSeen
            };
            await history.ApplyAndSaveAsync(CreateResult([first], firstSeen));

            NetworkDevice gainedMac = new()
            {
                IpAddress = IPAddress.Parse("192.168.1.40"),
                Hostname = "printer",
                MacAddress = "00:11:22:33:44:55",
                FirstSeen = firstSeen.AddHours(1),
                LastSeen = firstSeen.AddHours(1)
            };
            await history.ApplyAndSaveAsync(CreateResult([gainedMac], firstSeen.AddHours(1)));
            Equal(false, gainedMac.IsNew);
            Equal(firstSeen, gainedMac.FirstSeen);

            NetworkDevice movedIp = new()
            {
                IpAddress = IPAddress.Parse("192.168.1.41"),
                Hostname = "printer",
                MacAddress = "00:11:22:33:44:55",
                FirstSeen = firstSeen.AddHours(2),
                LastSeen = firstSeen.AddHours(2)
            };
            await history.ApplyAndSaveAsync(CreateResult([movedIp], firstSeen.AddHours(2)));
            Equal(false, movedIp.IsNew);
            Equal(firstSeen, movedIp.FirstSeen);
            True(movedIp.Changes.Any(change => change.Contains("IP mudou", StringComparison.Ordinal)),
                "Uma mudança de IP do mesmo MAC deveria ficar registada.");

            NetworkDevice reusedIp = new()
            {
                IpAddress = IPAddress.Parse("192.168.1.41"),
                Hostname = "other-device",
                MacAddress = "00:11:22:33:44:66",
                FirstSeen = firstSeen.AddHours(3),
                LastSeen = firstSeen.AddHours(3)
            };
            await history.ApplyAndSaveAsync(CreateResult([reusedIp], firstSeen.AddHours(3)));
            Equal(true, reusedIp.IsNew);
            Equal(firstSeen.AddHours(3), reusedIp.FirstSeen);
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }),
    ("History migrates network anchors and clears only its files", async () =>
    {
        string directory = Path.Combine(Path.GetTempPath(), "LocalNetworkScanner.Tests", Guid.NewGuid().ToString("N"));
        try
        {
            NetworkHistoryService history = new(directory);
            DateTimeOffset capturedAt = new(2026, 7, 20, 12, 0, 0, TimeSpan.Zero);
            NetworkDevice gatewayWithoutMac = new()
            {
                IpAddress = IPAddress.Parse("192.168.1.1"),
                Hostname = "gateway"
            };
            NetworkDevice stableClient = new()
            {
                IpAddress = IPAddress.Parse("192.168.1.20"),
                MacAddress = "00:11:22:33:44:55",
                FirstSeen = capturedAt,
                LastSeen = capturedAt
            };
            await history.ApplyAndSaveAsync(
                CreateResult([gatewayWithoutMac, stableClient], capturedAt));

            NetworkDevice gatewayWithMac = new()
            {
                IpAddress = IPAddress.Parse("192.168.1.1"),
                Hostname = "gateway",
                MacAddress = "00:AA:BB:CC:DD:01"
            };
            NetworkDevice sameClient = new()
            {
                IpAddress = IPAddress.Parse("192.168.1.20"),
                MacAddress = "00:11:22:33:44:55",
                FirstSeen = capturedAt.AddHours(1),
                LastSeen = capturedAt.AddHours(1)
            };
            await history.ApplyAndSaveAsync(
                CreateResult([gatewayWithMac, sameClient], capturedAt.AddHours(1)));
            Equal(false, sameClient.IsNew);
            Equal(capturedAt, sameClient.FirstSeen);
            Equal(1, Directory.GetFiles(directory, "*.json").Length);

            string unrelated = Path.Combine(directory, "keep.txt");
            string temporary = Directory.GetFiles(directory, "*.json").Single() + ".tmp-orphan";
            await File.WriteAllTextAsync(unrelated, "keep");
            await File.WriteAllTextAsync(temporary, "temporary");
            Equal(2, await history.ClearAsync());
            Equal(false, Directory.EnumerateFiles(directory, "*.json").Any());
            Equal(true, File.Exists(unrelated));
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }),
    ("Device metadata follows MAC and rejects IP reuse", async () =>
    {
        string directory = Path.Combine(Path.GetTempPath(), "LocalNetworkScanner.Tests", Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "devices.json");
        try
        {
            using DeviceMetadataService metadata = new(path);
            NetworkDevice original = new()
            {
                IpAddress = IPAddress.Parse("192.168.1.30"),
                MacAddress = "00:10:20:30:40:50",
                Alias = "NAS principal",
                Notes = "Armário técnico",
                IsFavorite = true
            };
            await metadata.SaveAsync(original, "192.168.1.0/24");

            NetworkDevice moved = new()
            {
                IpAddress = IPAddress.Parse("192.168.1.31"),
                MacAddress = "00:10:20:30:40:50"
            };
            NetworkScanResult movedResult = CreateResult([moved], DateTimeOffset.UtcNow);
            await metadata.ApplyAsync(movedResult);
            Equal("NAS principal", moved.Alias);
            Equal("Armário técnico", moved.Notes);
            Equal(true, moved.IsFavorite);

            NetworkDevice reusedIp = new()
            {
                IpAddress = IPAddress.Parse("192.168.1.30"),
                MacAddress = "00:10:20:30:40:60"
            };
            await metadata.ApplyAsync(CreateResult([reusedIp], DateTimeOffset.UtcNow.AddMinutes(1)));
            Equal<string?>(null, reusedIp.Alias);
            Equal(false, reusedIp.IsFavorite);
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }),
    ("HTML export escapes content", async () =>
    {
        string directory = Path.Combine(Path.GetTempPath(), "LocalNetworkScanner.Tests", Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "report.html");
        try
        {
            NetworkScanResult result = new()
            {
                NetworkInterface = CreateInterface(),
                StartedAt = DateTimeOffset.UtcNow.AddSeconds(-1),
                CompletedAt = DateTimeOffset.UtcNow,
                AddressesScanned = 1,
                IsPartial = true,
                Devices =
                [
                    new NetworkDevice
                    {
                        IpAddress = IPAddress.Parse("192.168.1.20"),
                        Alias = "<script>alert(1)</script>",
                        MacAddress = "00:11:22:33:44:55",
                        MacAddressSource = MacAddressResolutionSource.ActiveArp
                    }
                ]
            };
            await new ExportService().ExportHtmlAsync(result, path);
            string html = await File.ReadAllTextAsync(path);
            True(html.Contains("&lt;script&gt;", StringComparison.Ordinal), "O alias deve ser escapado.");
            True(!html.Contains("<script>alert", StringComparison.Ordinal), "HTML inseguro encontrado.");
            True(html.Contains("RESULTADO PARCIAL", StringComparison.Ordinal), "O HTML deve identificar um resultado parcial.");
            True(html.Contains("ARP ativo deste scan", StringComparison.Ordinal),
                "O HTML deve preservar a proveniência MAC.");
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }),
    ("CSV export neutralizes formulas", async () =>
    {
        string directory = Path.Combine(Path.GetTempPath(), "LocalNetworkScanner.Tests", Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "report.csv");
        try
        {
            NetworkScanResult result = new()
            {
                NetworkInterface = CreateInterface(),
                StartedAt = DateTimeOffset.UtcNow.AddSeconds(-1),
                CompletedAt = DateTimeOffset.UtcNow,
                AddressesScanned = 1,
                IsPartial = true,
                Devices =
                [
                    new NetworkDevice
                    {
                        IpAddress = IPAddress.Parse("192.168.1.20"),
                        Alias = "=WEBSERVICE(\"https://example.invalid\")",
                        Notes = "  @SUM(1+1)",
                        MacAddress = "00:11:22:33:44:55",
                        MacAddressSource = MacAddressResolutionSource.NeighborCache
                    }
                ]
            };

            await new ExportService().ExportCsvAsync(result, path);
            string csv = await File.ReadAllTextAsync(path);
            True(csv.Contains("\"'=WEBSERVICE(\"\"https://example.invalid\"\")\"", StringComparison.Ordinal),
                "Uma fórmula no alias deve ser neutralizada.");
            True(csv.Contains("\"'  @SUM(1+1)\"", StringComparison.Ordinal),
                "Uma fórmula depois de espaços deve ser neutralizada.");
            True(csv.Contains("\"Sim\";\"Não\"", StringComparison.Ordinal),
                "O CSV deve identificar um resultado parcial.");
            True(csv.Contains("Evidência MAC", StringComparison.Ordinal) &&
                    csv.Contains("Cache ARP passiva", StringComparison.Ordinal),
                "O CSV deve preservar a proveniência MAC.");
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }),
    ("JSON export includes topology schema", async () =>
    {
        string directory = Path.Combine(Path.GetTempPath(), "LocalNetworkScanner.Tests", Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "report.json");
        try
        {
            NetworkScanResult result = CreateTopologyExportResult();
            result.Devices[0].MacAddressSource =
                MacAddressResolutionSource.CurrentReachableNeighbor;
            result.Devices[0].Ports =
            [
                new PortScanResult { Port = 443 },
                new PortScanResult
                {
                    Port = 8443,
                    TlsStatus = TlsProbeStatus.HandshakeSucceeded,
                    TlsProtocol = "TLS 1.3"
                }
            ];
            result.Devices[0].MdnsServices =
            [
                new MdnsServiceObservation
                {
                    InstanceName = "Office Printer._ipp._tcp.local",
                    ServiceType = "_ipp._tcp.local",
                    Port = 631,
                    Transport = "TCP",
                    Endpoint = "printer.local:631/tcp",
                    EvidenceSource = "mDNS/DNS-SD (PTR/SRV/A; TCP/631)"
                }
            ];
            await new ExportService().ExportJsonAsync(result, path);

            await using FileStream stream = File.OpenRead(path);
            using JsonDocument document = await JsonDocument.ParseAsync(stream);
            JsonElement root = document.RootElement;
            Equal(7, root.GetProperty("schemaVersion").GetInt32());
            JsonElement diagnostics = root.GetProperty("scan").GetProperty("diagnostics");
            Equal(1, diagnostics.GetArrayLength());
            Equal(DiagnosticCatalog.InvalidMacAddressCode,
                diagnostics[0].GetProperty("code").GetString());
            True(diagnostics[0].GetProperty("recommendedAction").GetString()?.Length > 0,
                "O JSON deve incluir a ação recomendada.");
            JsonElement device = root.GetProperty("devices")[0];
            Equal(
                "CurrentReachableNeighbor",
                device.GetProperty("macAddressSource").GetString());
            JsonElement ports = device.GetProperty("ports");
            Equal("NotProbed", ports[0].GetProperty("TlsStatus").GetString());
            Equal(JsonValueKind.Null, ports[0].GetProperty("IsEncrypted").ValueKind);
            Equal("HandshakeSucceeded", ports[1].GetProperty("TlsStatus").GetString());
            Equal(true, ports[1].GetProperty("IsEncrypted").GetBoolean());
            JsonElement mdnsService = device.GetProperty("mdnsServices")[0];
            Equal("Office Printer._ipp._tcp.local",
                mdnsService.GetProperty("InstanceName").GetString());
            Equal("_ipp._tcp.local", mdnsService.GetProperty("ServiceType").GetString());
            Equal(631, mdnsService.GetProperty("Port").GetInt32());
            Equal("TCP", mdnsService.GetProperty("Transport").GetString());
            Equal("printer.local:631/tcp", mdnsService.GetProperty("Endpoint").GetString());
            JsonElement map = root.GetProperty("topologyMap");
            True(map.GetProperty("nodes").GetArrayLength() >= 3,
                "O JSON deveria conter os nós do mapa de topologia.");
            Equal("Layer2Observed", map.GetProperty("edges")
                .EnumerateArray()
                .First(edge => edge.GetProperty("kind").GetString() == "Layer2Observed")
                .GetProperty("kind")
                .GetString());
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }),
    ("Support export excludes network identifiers", async () =>
    {
        string directory = Path.Combine(Path.GetTempPath(), "LocalNetworkScanner.Tests", Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "support.json");
        try
        {
            NetworkScanResult result = CreateTopologyExportResult();
            result.Devices[0].Hostname = "host-secret.example";
            result.Devices[0].Notes = "note-secret";
            result.NetworkInterface.Ssid = "ssid-secret";
            result.NetworkInterface.Bssid = "02:AA:BB:CC:DD:EE";

            await new ExportService().ExportSupportJsonAsync(result, path);
            string json = await File.ReadAllTextAsync(path);
            foreach (string secret in new[]
                     {
                         "192.168.1.",
                         "00:11:22:33:44:55",
                         "00:AA:BB:CC:DD:EE",
                         "02:AA:BB:CC:DD:EE",
                         "printer <lab>&",
                         "host-secret.example",
                         "note-secret",
                         "ssid-secret",
                         "Interface de teste",
                         "invalid-mac"
                     })
            {
                True(!json.Contains(secret, StringComparison.OrdinalIgnoreCase),
                    $"O relatório de suporte expôs o identificador '{secret}'.");
            }

            using JsonDocument document = JsonDocument.Parse(json);
            JsonElement root = document.RootElement;
            Equal(1, root.GetProperty("schemaVersion").GetInt32());
            Equal("LocalNetworkScanner.Support", root.GetProperty("reportType").GetString());
            Equal(false, root.GetProperty("privacy").GetProperty("containsNetworkIdentifiers").GetBoolean());
            Equal(1, root.GetProperty("devices").GetProperty("total").GetInt32());
            Equal(
                DiagnosticCatalog.InvalidMacAddressCode,
                root.GetProperty("diagnostics")[0].GetProperty("code").GetString());
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }),
    ("GraphML export is valid and preserves evidence", async () =>
    {
        string directory = Path.Combine(Path.GetTempPath(), "LocalNetworkScanner.Tests", Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "topology.graphml");
        try
        {
            NetworkScanResult result = CreateTopologyExportResult();
            await new ExportService().ExportGraphMlAsync(result, path);

            XDocument document = XDocument.Load(path);
            XNamespace graphMl = "http://graphml.graphdrawing.org/xmlns";
            XElement[] nodes = document.Descendants(graphMl + "node").ToArray();
            XElement[] edges = document.Descendants(graphMl + "edge").ToArray();
            HashSet<string> nodeIds = nodes
                .Select(node => (string?)node.Attribute("id"))
                .Where(id => id is not null)
                .Select(id => id!)
                .ToHashSet(StringComparer.Ordinal);

            True(nodes.Length >= 3, "O GraphML deveria conter os nós da rede.");
            True(edges.Length >= 3, "O GraphML deveria conter ligações com evidência.");
            True(edges.All(edge =>
                    nodeIds.Contains((string?)edge.Attribute("source") ?? string.Empty) &&
                    nodeIds.Contains((string?)edge.Attribute("target") ?? string.Empty)),
                "As referências source/target do GraphML devem apontar para nós existentes.");
            True(document.Descendants(graphMl + "data")
                    .Any(data => (string?)data.Attribute("key") == "e_evidence" &&
                                 data.Value.Contains("proxy ARP", StringComparison.Ordinal)),
                "O GraphML deveria preservar a explicação da evidência.");
            True(document.Descendants(graphMl + "data")
                    .Any(data => (string?)data.Attribute("key") == "g_diagnostics" &&
                                 data.Value.Contains(DiagnosticCatalog.InvalidMacAddressCode, StringComparison.Ordinal)),
                "O GraphML deveria preservar os códigos de diagnóstico.");
            True(document.ToString().Contains("printer &lt;lab&gt;&amp;", StringComparison.Ordinal),
                "Os rótulos não confiáveis devem ser escapados no XML.");
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }),
    ("WPF selected-device and topology rendering smoke", () => RunOnSta(() =>
    {
        string directory = Path.Combine(Path.GetTempPath(), "LocalNetworkScanner.Tests", Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "topology.png");
        App application = new();
        application.ShutdownMode = ShutdownMode.OnExplicitShutdown;
        application.InitializeComponent();
        MainWindow window = new(new UiSettingsService(Path.Combine(directory, "settings.json")))
        {
            Opacity = 0,
            ShowActivated = false,
            ShowInTaskbar = false
        };
        TopologyWindow? topologyWindow = null;
        AboutWindow? aboutWindow = null;
        try
        {
            NetworkScanResult result = CreateTopologyExportResult();
            result.Devices[0].MdnsNames = ["office-printer.local"];
            result.Devices[0].MdnsServices =
            [
                new MdnsServiceObservation
                {
                    InstanceName = "Office Printer._ipp._tcp.local",
                    ServiceType = "_ipp._tcp.local",
                    Port = 631,
                    Transport = "TCP",
                    Endpoint = "office-printer.local:631/tcp",
                    EvidenceSource = "mDNS/DNS-SD (PTR/SRV/A; TCP/631)"
                }
            ];
            for (int serviceIndex = 2; serviceIndex <= 8; serviceIndex++)
            {
                result.Devices[0].MdnsServices.Add(new MdnsServiceObservation
                {
                    InstanceName = $"Serviço {serviceIndex}._http._tcp.local",
                    ServiceType = "_http._tcp.local",
                    Port = 8_000 + serviceIndex,
                    Transport = "TCP",
                    Endpoint = $"service-{serviceIndex}.local:{8_000 + serviceIndex}/tcp",
                    EvidenceSource = "mDNS/DNS-SD (PTR/SRV/A; TCP)"
                });
            }
            result.Devices[0].MdnsServices.Add(new MdnsServiceObservation
            {
                InstanceName = "Serviço oculto._scanner._tcp.local",
                ServiceType = "_scanner._tcp.local",
                Port = 9_999,
                Transport = "TCP",
                Endpoint = "ninth-service-only.local:9999/tcp",
                EvidenceSource = "mDNS/DNS-SD (PTR/SRV/A; TCP/9999)"
            });
            DeviceRowViewModel row = new(result.Devices[0]);
            window.ViewModel.Devices.Add(row);
            window.ViewModel.SelectedDevice = row;
            window.Show();
            window.Hide();
            window.Measure(new Size(1_440, 880));
            window.Arrange(new Rect(0, 0, 1_440, 880));
            window.UpdateLayout();

            ToggleButton? configurationToggle =
                window.FindName("ScanConfigurationToggle") as ToggleButton;
            ScrollViewer? configurationPanel =
                window.FindName("ScanConfigurationPanel") as ScrollViewer;
            Expander? customSettingsExpander =
                window.FindName("CustomScanSettingsExpander") as Expander;
            CheckBox? useCustomSettingsToggle =
                window.FindName("UseCustomScanSettingsToggle") as CheckBox;
            Button? resetProfileOverridesButton =
                window.FindName("ResetProfileOverridesButton") as Button;
            TextBox? maximumHostsTextBox =
                window.FindName("MaximumHostsTextBox") as TextBox;
            PasswordBox? snmpCommunityPasswordBox =
                window.FindName("SnmpCommunityPasswordBox") as PasswordBox;
            Button? progressCancelButton =
                window.FindName("ProgressCancelButton") as Button;
            TextBlock? emptyStateTitle =
                window.FindName("EmptyStateTitleText") as TextBlock;
            TextBlock? statusLiveRegion =
                window.FindName("StatusLiveRegion") as TextBlock;
            CheckBox? deviceFavoriteCheckBox =
                window.FindName("DeviceFavoriteCheckBox") as CheckBox;
            TextBox? deviceAliasTextBox =
                window.FindName("DeviceAliasTextBox") as TextBox;
            TextBox? deviceNotesTextBox =
                window.FindName("DeviceNotesTextBox") as TextBox;
            Button? aboutButton = window.FindName("AboutButton") as Button;
            Button? exitButton = window.FindName("ExitButton") as Button;
            NotNull(configurationToggle);
            NotNull(configurationPanel);
            NotNull(customSettingsExpander);
            NotNull(useCustomSettingsToggle);
            NotNull(resetProfileOverridesButton);
            NotNull(maximumHostsTextBox);
            NotNull(snmpCommunityPasswordBox);
            NotNull(progressCancelButton);
            NotNull(emptyStateTitle);
            NotNull(statusLiveRegion);
            NotNull(deviceFavoriteCheckBox);
            NotNull(deviceAliasTextBox);
            NotNull(deviceNotesTextBox);
            NotNull(aboutButton);
            NotNull(exitButton);
            Equal("Abrir informação sobre a aplicação", AutomationProperties.GetName(aboutButton));
            Equal("Sair da aplicação", AutomationProperties.GetName(exitButton));
            AutomationPeer? statusPeer = UIElementAutomationPeer.CreatePeerForElement(statusLiveRegion!);
            NotNull(statusPeer);
            Equal(AutomationLiveSetting.Polite, AutomationProperties.GetLiveSetting(statusLiveRegion));
            Equal(true, window.ViewModel.IsScanConfigurationExpanded);
            Equal("Ocultar configuração", configurationToggle!.Content?.ToString());
            Equal(Visibility.Visible, configurationPanel!.Visibility);
            Equal(Visibility.Collapsed, progressCancelButton!.Visibility);
            Equal("Ainda não existem resultados", emptyStateTitle!.Text);
            Equal(false, window.ViewModel.CanEditSelectedDeviceMetadata);
            Equal(false, deviceFavoriteCheckBox!.IsEnabled);
            Equal(false, deviceAliasTextBox!.IsEnabled);
            Equal(false, deviceNotesTextBox!.IsEnabled);

            FieldInfo lastResultField = typeof(MainViewModel)
                .GetField("_lastResult", BindingFlags.Instance | BindingFlags.NonPublic)!;
            lastResultField.SetValue(window.ViewModel, result);
            window.ViewModel.SelectedDevice = null;
            window.ViewModel.SelectedDevice = row;
            deviceFavoriteCheckBox.GetBindingExpression(UIElement.IsEnabledProperty)?.UpdateTarget();
            deviceAliasTextBox.GetBindingExpression(UIElement.IsEnabledProperty)?.UpdateTarget();
            deviceNotesTextBox.GetBindingExpression(UIElement.IsEnabledProperty)?.UpdateTarget();
            Equal(true, window.ViewModel.CanEditSelectedDeviceMetadata);
            Equal(true, deviceFavoriteCheckBox.IsEnabled);
            Equal(true, deviceAliasTextBox.IsEnabled);
            Equal(true, deviceNotesTextBox.IsEnabled);
            window.ViewModel.NetworkInterfaces.Add(result.NetworkInterface);
            window.ViewModel.SelectedNetworkInterface = result.NetworkInterface;
            window.ViewModel.NetworkCidr = result.NetworkInterface.NetworkCidr;
            True(window.ViewModel.ClearResultsCommand.CanExecute(null),
                "Limpar deve estar disponível antes de começar a guardar metadados.");
            PropertyInfo isSavingMetadataProperty = typeof(MainViewModel)
                .GetProperty(nameof(MainViewModel.IsSavingDeviceMetadata))!;
            isSavingMetadataProperty.SetValue(window.ViewModel, true);
            deviceFavoriteCheckBox.GetBindingExpression(UIElement.IsEnabledProperty)?.UpdateTarget();
            deviceAliasTextBox.GetBindingExpression(UIElement.IsEnabledProperty)?.UpdateTarget();
            deviceNotesTextBox.GetBindingExpression(UIElement.IsEnabledProperty)?.UpdateTarget();
            Equal(false, window.ViewModel.CanEditSelectedDeviceMetadata);
            Equal(false, deviceFavoriteCheckBox.IsEnabled);
            Equal(false, deviceAliasTextBox.IsEnabled);
            Equal(false, deviceNotesTextBox.IsEnabled);
            Equal(false, window.ViewModel.ClearResultsCommand.CanExecute(null));
            isSavingMetadataProperty.SetValue(window.ViewModel, false);
            deviceFavoriteCheckBox.GetBindingExpression(UIElement.IsEnabledProperty)?.UpdateTarget();
            deviceAliasTextBox.GetBindingExpression(UIElement.IsEnabledProperty)?.UpdateTarget();
            deviceNotesTextBox.GetBindingExpression(UIElement.IsEnabledProperty)?.UpdateTarget();
            row.Alias = "Nome por guardar";
            Equal(true, window.ViewModel.HasUnsavedDeviceMetadata);
            row.MarkMetadataSaved();
            Equal(false, window.ViewModel.HasUnsavedDeviceMetadata);

            window.ViewModel.SearchText = "_ipp._tcp.local";
            Equal(1, window.ViewModel.DevicesView.Cast<object>().Count());
            window.ViewModel.SearchText = "office-printer.local";
            Equal(1, window.ViewModel.DevicesView.Cast<object>().Count());
            True(!row.MdnsServiceSummary.Contains("ninth-service-only", StringComparison.Ordinal),
                "O resumo visual deve manter o limite de oito serviços.");
            window.ViewModel.SearchText = "ninth-service-only.local";
            Equal(1, window.ViewModel.DevicesView.Cast<object>().Count());
            window.ViewModel.SearchText = string.Empty;

            window.ViewModel.IsScanConfigurationExpanded = false;
            configurationToggle.GetBindingExpression(ContentControl.ContentProperty)?.UpdateTarget();
            configurationPanel.GetBindingExpression(UIElement.VisibilityProperty)?.UpdateTarget();
            Equal("Configuração do scan", configurationToggle.Content?.ToString());
            Equal(Visibility.Collapsed, configurationPanel.Visibility);
            window.ViewModel.IsScanConfigurationExpanded = true;

            window.ViewModel.UseCustomScanSettings = false;
            window.ViewModel.IsCustomScanSettingsExpanded = false;
            customSettingsExpander!.GetBindingExpression(Expander.IsExpandedProperty)?.UpdateTarget();
            customSettingsExpander.IsExpanded = true;
            customSettingsExpander.GetBindingExpression(Expander.IsExpandedProperty)?.UpdateSource();
            Equal(true, window.ViewModel.IsCustomScanSettingsExpanded);
            Equal(false, window.ViewModel.UseCustomScanSettings);
            useCustomSettingsToggle!.GetBindingExpression(ToggleButton.IsCheckedProperty)?.UpdateTarget();
            Equal(false, useCustomSettingsToggle.IsChecked);
            Equal(window.ViewModel.ResetProfileOverridesCommand, resetProfileOverridesButton!.Command);
            window.ViewModel.UseCustomScanSettings = true;
            maximumHostsTextBox!.Text = "invalid";
            maximumHostsTextBox.GetBindingExpression(TextBox.TextProperty)?.UpdateSource();
            Equal(true, Validation.GetHasError(maximumHostsTextBox));
            Equal(true, window.ViewModel.HasBlockingInputValidationErrors);
            snmpCommunityPasswordBox!.Password = "temporary-test-community";
            Equal("temporary-test-community", window.ViewModel.SnmpCommunity);
            window.ViewModel.ResetProfileOverridesCommand.Execute(null);
            maximumHostsTextBox.GetBindingExpression(TextBox.TextProperty)?.UpdateTarget();
            Equal(IpRangeService.DefaultMaximumAddresses.ToString(CultureInfo.CurrentCulture), maximumHostsTextBox.Text);
            Equal(false, Validation.GetHasError(maximumHostsTextBox));
            Equal(false, window.ViewModel.HasBlockingInputValidationErrors);
            Equal(string.Empty, window.ViewModel.SnmpCommunity);
            Equal(string.Empty, snmpCommunityPasswordBox.Password);

            PropertyInfo isScanningProperty = typeof(MainViewModel)
                .GetProperty(nameof(MainViewModel.IsScanning))!;
            PropertyInfo isCancellingProperty = typeof(MainViewModel)
                .GetProperty(nameof(MainViewModel.IsCancelling))!;
            PropertyInfo progressPhaseProperty = typeof(MainViewModel)
                .GetProperty(nameof(MainViewModel.ProgressPhase))!;
            PropertyInfo statusMessageProperty = typeof(MainViewModel)
                .GetProperty(nameof(MainViewModel.StatusMessage))!;
            FieldInfo activeGenerationField = typeof(MainViewModel)
                .GetField("_activeProgressGeneration", BindingFlags.Instance | BindingFlags.NonPublic)!;
            MethodInfo applyProgressMethod = typeof(MainViewModel)
                .GetMethod("ApplyProgress", BindingFlags.Instance | BindingFlags.NonPublic)!;
            isScanningProperty.SetValue(window.ViewModel, true);
            isCancellingProperty.SetValue(window.ViewModel, true);
            progressPhaseProperty.SetValue(window.ViewModel, "A cancelar");
            statusMessageProperty.SetValue(window.ViewModel, "A cancelar o scan com segurança...");
            activeGenerationField.SetValue(window.ViewModel, 42L);
            applyProgressMethod.Invoke(
                window.ViewModel,
                [42L, new ScanProgress("Descoberta", 1, 2, 0, "Mensagem tardia")]);
            emptyStateTitle.GetBindingExpression(TextBlock.TextProperty)?.UpdateTarget();
            Equal("A cancelar o scan", emptyStateTitle.Text);
            Equal("A cancelar", window.ViewModel.ProgressPhase);
            Equal("A cancelar o scan com segurança...", window.ViewModel.StatusMessage);
            Equal(1, window.ViewModel.ScannedCount);
            activeGenerationField.SetValue(window.ViewModel, 0L);
            isCancellingProperty.SetValue(window.ViewModel, false);
            isScanningProperty.SetValue(window.ViewModel, false);

            result.Devices[0].ResponseTimeMs = 7;
            row.Update(result.Devices[0]);
            window.UpdateLayout();
            Equal("7 ms", row.ResponseTime);

            Equal("Rápido", window.ViewModel.Profiles[0].DisplayName);
            Equal("Normal", window.ViewModel.Profiles[1].DisplayName);
            Equal("Avançado", window.ViewModel.Profiles[2].DisplayName);
            Equal(ScanProfile.Deep, window.ViewModel.Profiles[2].Value);

            Rect workArea = SystemParameters.WorkArea;
            double intendedLeft = workArea.Left + Math.Max(10, (workArea.Width - 640) / 4);
            double intendedTop = workArea.Top + Math.Max(10, (workArea.Height - 620) / 4);
            double intendedCenterX = intendedLeft + 320;
            double intendedCenterY = intendedTop + 310;
            aboutWindow = new AboutWindow
            {
                Owner = window,
                Opacity = 0,
                ShowActivated = false,
                WindowStartupLocation = WindowStartupLocation.Manual,
                Left = intendedLeft,
                Top = intendedTop
            };
            aboutWindow.Show();
            True(
                Math.Abs((aboutWindow.Left + (aboutWindow.Width / 2)) - intendedCenterX) < 1,
                "A janela Sobre não deve ser recentrada à força no monitor principal.");
            True(
                Math.Abs((aboutWindow.Top + (aboutWindow.Height / 2)) - intendedCenterY) < 1,
                "A janela Sobre deve preservar o centro escolhido pelo WPF ao ajustar o tamanho.");
            aboutWindow.Hide();
            aboutWindow.Measure(new Size(640, 620));
            aboutWindow.Arrange(new Rect(0, 0, 640, 620));
            aboutWindow.UpdateLayout();
            string? informationalVersion = typeof(AboutWindow).Assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
                .InformationalVersion;
            string expectedVersion = informationalVersion?.Split('+', 2)[0] ??
                typeof(AboutWindow).Assembly.GetName().Version?.ToString(3) ??
                "0.0.0";
            Equal("Local Network Scanner", aboutWindow.ProductName);
            Equal($"Versão {expectedVersion}", aboutWindow.VersionLabel);
            Equal("p-darksy-r", aboutWindow.Creator);
            True(
                aboutWindow.Summary.Contains("Scanner de redes locais", StringComparison.Ordinal),
                "A janela Sobre deve apresentar o resumo do produto a partir do assembly.");
            True(
                aboutWindow.CopyrightText.Contains("p-darksy-r", StringComparison.Ordinal),
                "A janela Sobre deve apresentar o titular do copyright.");
            Button? closeAboutButton = aboutWindow.FindName("CloseAboutButton") as Button;
            TextBlock? versionTextBlock = aboutWindow.FindName("VersionTextBlock") as TextBlock;
            NotNull(closeAboutButton);
            NotNull(versionTextBlock);
            Equal(
                "Fechar informação sobre a aplicação",
                AutomationProperties.GetName(closeAboutButton));
            Equal(
                application.Resources["SelectionForegroundBrush"],
                versionTextBlock!.Foreground);
            if (workArea.Width > 0 && workArea.Height > 0)
            {
                True(aboutWindow.Width <= workArea.Width,
                    "A janela Sobre deve caber na largura útil do ecrã.");
                True(aboutWindow.Height <= workArea.Height,
                    "A janela Sobre deve caber na altura útil do ecrã.");
            }

            Button? topologyButton = window.FindName("OpenTopologyButton") as Button;
            NotNull(topologyButton);
            var topologyBinding = topologyButton!.GetBindingExpression(UIElement.IsEnabledProperty);
            NotNull(topologyBinding);
            topologyBinding!.UpdateTarget();
            True(
                !topologyButton!.IsEnabled,
                $"A topologia deve estar desativada antes de existir mapa. " +
                $"HasTopologyMap={window.ViewModel.HasTopologyMap}; " +
                $"DataContext={topologyButton.DataContext?.GetType().Name ?? "null"}; " +
                $"Binding={topologyBinding.Status}.");

            NetworkMap map = new NetworkTopologyMapService().Build(result);
            typeof(MainViewModel)
                .GetProperty(nameof(MainViewModel.TopologyMap))!
                .SetValue(window.ViewModel, map);
            topologyBinding.UpdateTarget();
            window.UpdateLayout();
            True(topologyButton.IsEnabled, "A topologia deve ficar disponível depois do scan.");

            topologyWindow = new TopologyWindow(window.ViewModel)
            {
                Opacity = 0,
                ShowActivated = false,
                ShowInTaskbar = false
            };
            topologyWindow.Show();
            topologyWindow.Hide();
            topologyWindow.Measure(new Size(1_240, 760));
            topologyWindow.Arrange(new Rect(0, 0, 1_240, 760));
            topologyWindow.UpdateLayout();
            Equal(window.ViewModel, topologyWindow.DataContext);
            NetworkTopologyControl? optionalTopology =
                topologyWindow.FindName("TopologyGraph") as NetworkTopologyControl;
            TextBlock? topologyZoomText =
                topologyWindow.FindName("TopologyZoomText") as TextBlock;
            NotNull(optionalTopology);
            NotNull(topologyZoomText);
            Equal(map, optionalTopology!.Map);
            optionalTopology.ResetView();
            Equal(100, optionalTopology.ZoomPercent);
            Equal("100%", topologyZoomText!.Text);
            optionalTopology.ZoomIn();
            Equal(115, optionalTopology.ZoomPercent);
            Equal("115%", topologyZoomText.Text);

            NetworkTopologyControl topology = new()
            {
                Width = 900,
                Height = 500,
                Map = new NetworkTopologyMapService().Build(result)
            };
            topology.Measure(new Size(900, 500));
            topology.Arrange(new Rect(0, 0, 900, 500));
            topology.UpdateLayout();
            topology.FitToView();
            topology.ResetView();
            topology.ZoomIn();
            int userZoom = topology.ZoomPercent;
            topology.Arrange(new Rect(0, 0, 960, 540));
            topology.UpdateLayout();
            Equal(userZoom, topology.ZoomPercent);
            topology.ZoomOut();
            Equal(100, topology.ZoomPercent);
            Directory.CreateDirectory(directory);
            topology.ExportVisiblePng(path);
            True(new FileInfo(path).Length > 1_000, "O mapa WPF deveria produzir um PNG não vazio.");
        }
        finally
        {
            aboutWindow?.Close();
            topologyWindow?.Close();
            window.Close();
            application.Shutdown();
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }))
];

if (tests.Count == 0)
{
    Console.Error.WriteLine("FAIL  A suite de testes não contém casos registados.");
    return 1;
}

int passed = 0;
foreach ((string name, Func<Task> run) in tests)
{
    try
    {
        await run();
        passed++;
        Console.WriteLine($"PASS  {name}");
    }
    catch (Exception exception)
    {
        Console.Error.WriteLine($"FAIL  {name}: {exception.Message}");
    }
}

Console.WriteLine($"\n{passed}/{tests.Count} testes concluídos com sucesso.");
return passed == tests.Count ? 0 : 1;

static Task Sync(Action action)
{
    action();
    return Task.CompletedTask;
}

static Task RunOnSta(Action action)
{
    TaskCompletionSource completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    Thread thread = new(() =>
    {
        try
        {
            action();
            completion.SetResult();
        }
        catch (Exception exception)
        {
            completion.SetException(exception);
        }
    });
    thread.SetApartmentState(ApartmentState.STA);
    thread.Start();
    return completion.Task;
}

static LocalNetworkInterface CreateInterface() => new()
{
    Id = "test-interface",
    Name = "Ethernet",
    Description = "Interface de teste",
    IpAddress = IPAddress.Parse("192.168.1.10"),
    SubnetMask = IPAddress.Parse("255.255.255.0"),
    GatewayAddress = IPAddress.Parse("192.168.1.1"),
    MacAddress = "00:AA:BB:CC:DD:EE",
    InterfaceType = NetworkInterfaceType.Ethernet,
    SpeedBitsPerSecond = 1_000_000_000
};

static void SetNeighborRow(
    ref MacAddressService.MibIpNetRow2 row,
    IReadOnlyList<byte> macAddress,
    uint physicalAddressLength,
    int state,
    byte flags = 0)
{
    Equal(6, macAddress.Count);
    row.PhysicalAddressByte0 = macAddress[0];
    row.PhysicalAddressByte1 = macAddress[1];
    row.PhysicalAddressByte2 = macAddress[2];
    row.PhysicalAddressByte3 = macAddress[3];
    row.PhysicalAddressByte4 = macAddress[4];
    row.PhysicalAddressByte5 = macAddress[5];
    row.PhysicalAddressLength = physicalAddressLength;
    row.State = state;
    row.Flags = flags;
}

static NetworkScanResult CreateResult(
    IReadOnlyList<NetworkDevice> devices,
    DateTimeOffset completedAt) => new()
    {
        NetworkInterface = CreateInterface(),
        StartedAt = completedAt.AddSeconds(-1),
        CompletedAt = completedAt,
        AddressesScanned = Math.Max(1, devices.Count),
        Devices = devices
    };

static NetworkScanResult CreateTopologyExportResult()
{
    NetworkDevice device = new()
    {
        IpAddress = IPAddress.Parse("192.168.1.20"),
        Alias = "printer <lab>&",
        MacAddress = "00:11:22:33:44:55",
        IsOnline = true,
        DiscoveryMethods = DiscoveryMethod.Arp,
        Topology = new TopologyAssessment
        {
            SameIpSubnet = true,
            SameLayer2Segment = true,
            Layer2Confidence = ConfidenceLevel.Medium
        }
    };
    return new NetworkScanResult
    {
        NetworkInterface = CreateInterface(),
        StartedAt = new DateTimeOffset(2026, 7, 21, 10, 0, 0, TimeSpan.Zero),
        CompletedAt = new DateTimeOffset(2026, 7, 21, 10, 0, 1, TimeSpan.Zero),
        AddressesScanned = 1,
        Devices = [device],
        Diagnostics = [DiagnosticCatalog.InvalidMacAddress(device.IpAddressText, "invalid-mac")]
    };
}

static LldpNeighborObservation CreateLldpNeighbor(
    uint timeMark,
    int localPortNumber,
    int remoteIndex,
    string systemName) => new()
    {
        TimeMark = timeMark,
        LocalPortNumber = localPortNumber,
        RemoteIndex = remoteIndex,
        LocalPortId = $"Gi1/0/{localPortNumber}",
        PortId = $"Ethernet1/{remoteIndex}",
        SystemName = systemName,
        ChassisIdSubtype = 4,
        ChassisId = remoteIndex == 2 ? "abcdefabcdef-router" : "00:AA:BB:CC:DD:EE"
    };

static byte[] BuildNetBiosResponse()
{
    byte[] data = new byte[43];
    data[0] = 2;
    WriteName(data.AsSpan(1, 18), "MY-PC", 0x00, false);
    WriteName(data.AsSpan(19, 18), "WORKGROUP", 0x00, true);
    new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }.CopyTo(data, 37);

    byte[] packet = new byte[12 + 2 + 10 + data.Length];
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(0, 2), 7);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), 0x8500);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(6, 2), 1);
    int offset = 12;
    packet[offset++] = 0xC0;
    packet[offset++] = 0x0C;
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(offset, 2), 0x21);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(offset + 2, 2), 1);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(offset + 8, 2), (ushort)data.Length);
    offset += 10;
    data.CopyTo(packet, offset);
    return packet;
}

static void WriteName(Span<byte> target, string name, byte suffix, bool isGroup)
{
    target[..15].Fill((byte)' ');
    Encoding.ASCII.GetBytes(name).CopyTo(target);
    target[15] = suffix;
    BinaryPrimitives.WriteUInt16BigEndian(target[16..18], isGroup ? (ushort)0x8000 : (ushort)0);
}

static byte[] BuildMdnsResponse()
{
    using MemoryStream stream = new();
    byte[] header = new byte[12];
    BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(6, 2), 1);
    stream.Write(header);
    foreach (string label in new[] { "printer", "local" })
    {
        stream.WriteByte((byte)label.Length);
        stream.Write(Encoding.ASCII.GetBytes(label));
    }
    stream.WriteByte(0);
    stream.Write([0, 1, 0, 1]);
    stream.Write([0, 0, 0, 60]);
    stream.Write([0, 4, 192, 168, 1, 50]);
    return stream.ToArray();
}

static byte[] BuildCompressedDnsSdResponse()
{
    using MemoryStream stream = new();
    byte[] header = new byte[12];
    BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(2, 2), 0x8400);
    BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(6, 2), 5);
    stream.Write(header);

    List<(int LengthOffset, int DataOffset, int DataEnd)> recordData = [];

    int serviceTypeOffset = checked((int)stream.Position);
    WriteDnsName(stream, "_ipp", "_tcp", "local");
    int pointerLengthOffset = WriteDnsRecordHeader(
        stream,
        type: 12,
        recordClass: 0x8001,
        timeToLive: 120);
    int pointerDataOffset = checked((int)stream.Position);
    WriteDnsLabel(stream, "Office Printer");
    WriteDnsPointer(stream, serviceTypeOffset);
    recordData.Add((
        pointerLengthOffset,
        pointerDataOffset,
        checked((int)stream.Position)));

    int instanceOffset = checked((int)stream.Position);
    WriteDnsLabel(stream, "Office Printer");
    WriteDnsPointer(stream, serviceTypeOffset);
    int serviceLengthOffset = WriteDnsRecordHeader(
        stream,
        type: 33,
        recordClass: 0x8001,
        timeToLive: 120);
    int serviceDataOffset = checked((int)stream.Position);
    WriteDnsUInt16(stream, 0);
    WriteDnsUInt16(stream, 5);
    WriteDnsUInt16(stream, 631);
    int hostOffset = checked((int)stream.Position);
    WriteDnsName(stream, "printer", "local");
    recordData.Add((
        serviceLengthOffset,
        serviceDataOffset,
        checked((int)stream.Position)));

    WriteDnsPointer(stream, instanceOffset);
    int textLengthOffset = WriteDnsRecordHeader(
        stream,
        type: 16,
        recordClass: 0x8001,
        timeToLive: 120);
    int textDataOffset = checked((int)stream.Position);
    WriteDnsText(stream, "ty=Laser");
    WriteDnsText(stream, "note=Lab");
    recordData.Add((
        textLengthOffset,
        textDataOffset,
        checked((int)stream.Position)));

    WriteDnsPointer(stream, hostOffset);
    int addressLengthOffset = WriteDnsRecordHeader(
        stream,
        type: 1,
        recordClass: 0x8001,
        timeToLive: 0);
    int addressDataOffset = checked((int)stream.Position);
    stream.Write(IPAddress.Parse("192.168.1.50").GetAddressBytes());
    recordData.Add((
        addressLengthOffset,
        addressDataOffset,
        checked((int)stream.Position)));

    WriteDnsPointer(stream, hostOffset);
    int addressV6LengthOffset = WriteDnsRecordHeader(
        stream,
        type: 28,
        recordClass: 1,
        timeToLive: 60);
    int addressV6DataOffset = checked((int)stream.Position);
    stream.Write(IPAddress.Parse("fd00::50").GetAddressBytes());
    recordData.Add((
        addressV6LengthOffset,
        addressV6DataOffset,
        checked((int)stream.Position)));

    byte[] packet = stream.ToArray();
    foreach ((int lengthOffset, int dataOffset, int dataEnd) in recordData)
    {
        BinaryPrimitives.WriteUInt16BigEndian(
            packet.AsSpan(lengthOffset, 2),
            checked((ushort)(dataEnd - dataOffset)));
    }

    return packet;
}

static int WriteDnsRecordHeader(
    MemoryStream stream,
    ushort type,
    ushort recordClass,
    uint timeToLive)
{
    WriteDnsUInt16(stream, type);
    WriteDnsUInt16(stream, recordClass);
    Span<byte> ttl = stackalloc byte[4];
    BinaryPrimitives.WriteUInt32BigEndian(ttl, timeToLive);
    stream.Write(ttl);
    int lengthOffset = checked((int)stream.Position);
    WriteDnsUInt16(stream, 0);
    return lengthOffset;
}

static void WriteDnsName(MemoryStream stream, params string[] labels)
{
    foreach (string label in labels)
        WriteDnsLabel(stream, label);

    stream.WriteByte(0);
}

static void WriteDnsLabel(MemoryStream stream, string label)
{
    byte[] bytes = Encoding.UTF8.GetBytes(label);
    stream.WriteByte(checked((byte)bytes.Length));
    stream.Write(bytes);
}

static void WriteDnsPointer(MemoryStream stream, int offset)
{
    True(offset is >= 0 and < 0x4000, "O offset DNS deve caber num ponteiro comprimido.");
    WriteDnsUInt16(stream, checked((ushort)(0xC000 | offset)));
}

static void WriteDnsText(MemoryStream stream, string text)
{
    byte[] bytes = Encoding.UTF8.GetBytes(text);
    stream.WriteByte(checked((byte)bytes.Length));
    stream.Write(bytes);
}

static void WriteDnsUInt16(MemoryStream stream, ushort value)
{
    Span<byte> buffer = stackalloc byte[2];
    BinaryPrimitives.WriteUInt16BigEndian(buffer, value);
    stream.Write(buffer);
}

static byte[] BuildSnmpResponse()
{
    Asn1Tag responseTag = new(TagClass.ContextSpecific, 2, isConstructed: true);
    AsnWriter writer = new(AsnEncodingRules.BER);
    writer.PushSequence();
    writer.WriteInteger(1);
    writer.WriteOctetString(Encoding.ASCII.GetBytes("public"));
    writer.PushSequence(responseTag);
    writer.WriteInteger(42);
    writer.WriteInteger(0);
    writer.WriteInteger(0);
    writer.PushSequence();
    writer.PushSequence();
    writer.WriteObjectIdentifier("1.3.6.1.2.1.1.5.0");
    writer.WriteOctetString(Encoding.ASCII.GetBytes("switch-core"));
    writer.PopSequence();
    writer.PopSequence();
    writer.PopSequence(responseTag);
    writer.PopSequence();
    return writer.Encode();
}

static string VendorCsv(string registry, string assignment, string organization) =>
    "Registry,Assignment,Organization Name,Organization Address\n" +
    $"{registry},{assignment},\"{organization.Replace("\"", "\"\"", StringComparison.Ordinal)}\"," +
    "\"Rua de Teste, Lisboa\"\n";

static HttpResponseMessage CsvResponse(string body) => new(HttpStatusCode.OK)
{
    Content = new StringContent(
        body,
        new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
        "text/csv")
};

static Exception CaptureException(string message)
{
    try
    {
        throw new InvalidOperationException(message);
    }
    catch (InvalidOperationException exception)
    {
        return exception;
    }
}

static string FindRepositoryFile(params string[] relativeSegments)
{
    foreach (string root in new[] { Environment.CurrentDirectory, AppContext.BaseDirectory })
    {
        DirectoryInfo? directory = new(Path.GetFullPath(root));
        while (directory is not null)
        {
            string candidate = Path.Combine(
                [directory.FullName, .. relativeSegments]);
            if (File.Exists(candidate))
                return candidate;

            directory = directory.Parent;
        }
    }

    throw new FileNotFoundException(
        $"Não foi possível localizar o ficheiro do repositório '{Path.Combine(relativeSegments)}'.");
}

static void Equal<T>(T expected, T actual)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
        throw new InvalidOperationException($"Esperado '{expected}', obtido '{actual}'.");
}

static void True(bool condition, string message)
{
    if (!condition)
        throw new InvalidOperationException(message);
}

static void NotNull(object? value)
{
    if (value is null)
        throw new InvalidOperationException("O valor não deveria ser nulo.");
}

static void Throws<TException>(Action action)
    where TException : Exception
{
    try
    {
        action();
    }
    catch (TException)
    {
        return;
    }

    throw new InvalidOperationException($"Era esperada a exceção {typeof(TException).Name}.");
}

static async Task<TException> ThrowsAsync<TException>(Func<Task> action)
    where TException : Exception
{
    try
    {
        await action();
    }
    catch (TException exception)
    {
        return exception;
    }

    throw new InvalidOperationException($"Era esperada a exceção {typeof(TException).Name}.");
}

internal sealed class StubHttpMessageHandler : HttpMessageHandler
{
    private readonly Func<
        HttpRequestMessage,
        CancellationToken,
        Task<HttpResponseMessage>> _handler;

    public StubHttpMessageHandler(
        Func<
            HttpRequestMessage,
            CancellationToken,
            Task<HttpResponseMessage>> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        _handler = handler;
    }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken) =>
        _handler(request, cancellationToken);
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
