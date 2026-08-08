// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

/// <summary>
/// Uses an Nmap installation already present on the computer. The application does not
/// download, install or redistribute Nmap, and this service never requests raw sockets,
/// credentials, operating-system detection or NSE scripts.
/// </summary>
public sealed class NmapDiscoveryService
{
    private const int MaximumTargets = 256;
    private const int MaximumInputPorts = 65_535;
    private const int MaximumPortSpecificationLength = 16 * 1024;
    private const int MaximumXmlCharacters = 32 * 1024 * 1024;
    private const int MaximumDiagnosticCharacters = 32 * 1024;
    private const int MaximumXmlDepth = 64;
    private const int MaximumXmlElements = 500_000;
    private const int MaximumPortObservations = 65_535;
    private static readonly TimeSpan DefaultScanTimeout = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan MaximumScanTimeout = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan VersionCheckTimeout = TimeSpan.FromSeconds(5);

    public static bool IsSafeExplicitExecutablePath(string? path) =>
        TryNormalizeExecutablePath(path) is not null;

    public Task<NmapDiscoveryResult> DiscoverAsync(
        IEnumerable<IPAddress>? targets,
        IEnumerable<int>? ports,
        CancellationToken cancellationToken)
        => DiscoverAsync(targets, ports, null, DefaultScanTimeout, cancellationToken);

    public Task<NmapDiscoveryResult> DiscoverAsync(
        IEnumerable<IPAddress>? targets,
        IEnumerable<int>? ports,
        string? explicitExecutablePath,
        CancellationToken cancellationToken)
        => DiscoverAsync(
            targets,
            ports,
            explicitExecutablePath,
            DefaultScanTimeout,
            cancellationToken);

    public async Task<NmapDiscoveryResult> DiscoverAsync(
        IEnumerable<IPAddress>? targets,
        IEnumerable<int>? ports,
        string? explicitExecutablePath,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!TryValidateTargets(targets, out IReadOnlyList<IPAddress> validatedTargets))
        {
            return Failed(
                "A integração Nmap aceita entre 1 e 256 alvos IPv4 privados explícitos.");
        }

        if (!TryValidatePorts(ports, out IReadOnlyList<int> validatedPorts))
        {
            return Failed(
                "A lista de portas Nmap deve conter apenas portas TCP entre 1 e 65535.");
        }

        string portSpecification = BuildPortSpecification(validatedPorts);
        if (portSpecification.Length > MaximumPortSpecificationLength)
        {
            return Failed(
                "A seleção de portas é demasiado fragmentada para uma execução segura do Nmap.");
        }

        if (timeout < TimeSpan.FromSeconds(1) || timeout > MaximumScanTimeout)
        {
            return Failed("O limite de tempo do Nmap deve estar entre 1 segundo e 30 minutos.");
        }

        string? executablePath = await ResolveExecutableAsync(
            explicitExecutablePath,
            cancellationToken);
        if (executablePath is null)
        {
            return new NmapDiscoveryResult
            {
                Status = NmapDiscoveryStatus.Unavailable,
                Message = "O Nmap não está instalado ou não respondeu à validação de versão."
            };
        }

        List<string> arguments =
        [
            "--unprivileged",
            "-sT",
            "-sV",
            "--version-light",
            "-Pn",
            "-n",
            "--max-retries",
            "1",
            "--max-rtt-timeout",
            "1000ms",
            "--host-timeout",
            BuildHostTimeout(timeout),
            "-p",
            portSpecification,
            "-oX",
            "-"
        ];

        foreach (IPAddress target in validatedTargets)
            arguments.Add(target.ToString());

        ProcessExecutionResult execution = await RunProcessAsync(
            executablePath,
            arguments,
            timeout,
            MaximumXmlCharacters,
            cancellationToken);

        if (execution.TimedOut)
            return Failed("O scan Nmap excedeu o limite de tempo e foi terminado em segurança.");

        if (!execution.Started || execution.ExitCode != 0)
            return Failed("O Nmap não conseguiu concluir o scan opcional.");

        if (execution.StandardOutputTruncated || execution.StandardOutputReadFailed)
            return Failed("A resposta XML do Nmap excedeu os limites de segurança.");

        try
        {
            HashSet<IPAddress> expectedTargets = new(validatedTargets);
            IReadOnlyList<NmapHostObservation> observations = ParseXml(
                execution.StandardOutput,
                expectedTargets);
            return new NmapDiscoveryResult
            {
                Status = NmapDiscoveryStatus.Success,
                Message = $"O Nmap concluiu a análise opcional de {observations.Count} dispositivo(s).",
                Hosts = observations
            };
        }
        catch (Exception exception) when (exception is XmlException or InvalidDataException)
        {
            return Failed("O Nmap devolveu uma resposta XML inválida ou fora dos limites.");
        }
    }

    internal static bool TryValidateTargets(
        IEnumerable<IPAddress>? targets,
        out IReadOnlyList<IPAddress> validatedTargets)
    {
        List<IPAddress> result = [];
        HashSet<IPAddress> seen = [];
        int inputCount = 0;

        if (targets is null)
        {
            validatedTargets = result;
            return false;
        }

        foreach (IPAddress? target in targets)
        {
            inputCount++;
            if (inputCount > MaximumTargets ||
                target is null ||
                target.AddressFamily != AddressFamily.InterNetwork ||
                !IsPrivateIpv4(target))
            {
                validatedTargets = [];
                return false;
            }

            if (!seen.Add(target))
                continue;

            result.Add(target);
            if (result.Count > MaximumTargets)
            {
                validatedTargets = [];
                return false;
            }
        }

        validatedTargets = result;
        return result.Count > 0;
    }

    internal static bool TryValidatePorts(
        IEnumerable<int>? ports,
        out IReadOnlyList<int> validatedPorts)
    {
        SortedSet<int> result = [];
        int inputCount = 0;

        if (ports is null)
        {
            validatedPorts = [];
            return false;
        }

        foreach (int port in ports)
        {
            inputCount++;
            if (inputCount > MaximumInputPorts || port is < 1 or > 65_535)
            {
                validatedPorts = [];
                return false;
            }

            result.Add(port);
        }

        validatedPorts = result.ToList();
        return result.Count > 0;
    }

    internal static string BuildPortSpecification(IReadOnlyList<int> sortedPorts)
    {
        ArgumentNullException.ThrowIfNull(sortedPorts);
        if (sortedPorts.Count == 0)
            throw new ArgumentException("É necessária pelo menos uma porta.", nameof(sortedPorts));

        StringBuilder specification = new();
        int rangeStart = sortedPorts[0];
        int previous = rangeStart;

        for (int index = 1; index <= sortedPorts.Count; index++)
        {
            int? current = index < sortedPorts.Count ? sortedPorts[index] : null;
            if (current == previous + 1)
            {
                previous = current.Value;
                continue;
            }

            if (specification.Length > 0)
                specification.Append(',');

            specification.Append(rangeStart.ToString(CultureInfo.InvariantCulture));
            if (previous != rangeStart)
            {
                specification.Append('-');
                specification.Append(previous.ToString(CultureInfo.InvariantCulture));
            }

            if (current.HasValue)
            {
                rangeStart = current.Value;
                previous = current.Value;
            }
        }

        return specification.ToString();
    }

    internal static IReadOnlyList<NmapHostObservation> ParseXml(
        string xml,
        IReadOnlySet<IPAddress>? expectedTargets = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(xml);
        ValidateXmlShape(xml);

        using StringReader textReader = new(xml);
        using XmlReader reader = XmlReader.Create(textReader, CreateSecureXmlSettings());
        XDocument document = XDocument.Load(reader, LoadOptions.None);
        XElement root = document.Root ?? throw new XmlException("Documento XML vazio.");
        if (!string.Equals(root.Name.LocalName, "nmaprun", StringComparison.Ordinal))
            throw new XmlException("Raiz XML Nmap inválida.");

        List<NmapHostObservation> observations = [];
        HashSet<IPAddress> observedAddresses = [];
        int totalPortObservations = 0;

        foreach (XElement host in ChildElements(root, "host"))
        {
            if (observations.Count >= MaximumTargets)
                throw new InvalidDataException("Demasiados hosts no XML Nmap.");

            XElement? ipv4Element = ChildElements(host, "address")
                .FirstOrDefault(element =>
                    string.Equals(Attribute(element, "addrtype"), "ipv4", StringComparison.OrdinalIgnoreCase));
            string? addressText = Attribute(ipv4Element, "addr");
            if (!IPAddress.TryParse(addressText, out IPAddress? address) ||
                address.AddressFamily != AddressFamily.InterNetwork ||
                !IsPrivateIpv4(address) ||
                (expectedTargets is not null && !expectedTargets.Contains(address)) ||
                !observedAddresses.Add(address))
            {
                continue;
            }

            XElement? statusElement = ChildElements(host, "status").FirstOrDefault();
            XElement? macElement = ChildElements(host, "address")
                .FirstOrDefault(element =>
                    string.Equals(Attribute(element, "addrtype"), "mac", StringComparison.OrdinalIgnoreCase));
            XElement? hostnameElement = ChildElements(host, "hostnames")
                .SelectMany(element => ChildElements(element, "hostname"))
                .FirstOrDefault();
            XElement? osMatch = ChildElements(host, "os")
                .SelectMany(element => ChildElements(element, "osmatch"))
                .OrderByDescending(GetOsAccuracy)
                .FirstOrDefault();

            List<NmapPortObservation> portObservations = [];
            foreach (XElement portElement in ChildElements(host, "ports")
                .SelectMany(element => ChildElements(element, "port")))
            {
                if (++totalPortObservations > MaximumPortObservations)
                    throw new InvalidDataException("Demasiadas portas no XML Nmap.");

                if (!int.TryParse(
                        Attribute(portElement, "portid"),
                        NumberStyles.None,
                        CultureInfo.InvariantCulture,
                        out int port) ||
                    port is < 1 or > 65_535)
                {
                    continue;
                }

                string protocol = Sanitize(Attribute(portElement, "protocol"), 16) ?? "unknown";
                if (!string.Equals(protocol, "tcp", StringComparison.OrdinalIgnoreCase))
                    continue;

                XElement? portState = ChildElements(portElement, "state").FirstOrDefault();
                XElement? service = ChildElements(portElement, "service").FirstOrDefault();
                portObservations.Add(new NmapPortObservation
                {
                    Port = port,
                    Protocol = "tcp",
                    State = Sanitize(Attribute(portState, "state"), 32) ?? "unknown",
                    ServiceName = Sanitize(Attribute(service, "name"), 80),
                    Product = Sanitize(Attribute(service, "product"), 160),
                    Version = Sanitize(Attribute(service, "version"), 120),
                    ExtraInfo = Sanitize(Attribute(service, "extrainfo"), 256),
                    DeviceType = Sanitize(Attribute(service, "devicetype"), 80),
                    OperatingSystem = Sanitize(Attribute(service, "ostype"), 120)
                });
            }

            string? macAddress = NormalizeMacAddress(Attribute(macElement, "addr"));
            observations.Add(new NmapHostObservation
            {
                IpAddress = address,
                State = Sanitize(Attribute(statusElement, "state"), 32) ?? "unknown",
                Hostname = Sanitize(Attribute(hostnameElement, "name"), 255),
                MacAddress = macAddress,
                MacVendor = macAddress is null ? null : Sanitize(Attribute(macElement, "vendor"), 160),
                OperatingSystem = Sanitize(Attribute(osMatch, "name"), 160),
                OperatingSystemAccuracy = osMatch is null ? null : GetOsAccuracy(osMatch),
                Ports = portObservations
            });
        }

        return observations;
    }

    private static NmapDiscoveryResult Failed(string message)
        => new()
        {
            Status = NmapDiscoveryStatus.Failed,
            Message = message
        };

    private static async Task<string?> ResolveExecutableAsync(
        string? explicitExecutablePath,
        CancellationToken cancellationToken)
    {
        foreach (string candidate in ResolveCandidatePaths(explicitExecutablePath))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ProcessExecutionResult validation = await RunProcessAsync(
                candidate,
                ["--version"],
                VersionCheckTimeout,
                MaximumDiagnosticCharacters,
                cancellationToken);

            if (!validation.Started ||
                validation.TimedOut ||
                validation.ExitCode != 0 ||
                validation.StandardOutputTruncated ||
                validation.StandardOutputReadFailed)
            {
                continue;
            }

            string versionText = string.Concat(
                validation.StandardOutput,
                "\n",
                validation.StandardError);
            if (versionText.Contains("Nmap version ", StringComparison.OrdinalIgnoreCase))
                return candidate;
        }

        return null;
    }

    internal static IReadOnlyList<string> ResolveCandidatePaths(string? explicitExecutablePath)
    {
        List<string> candidates = [];
        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);

        void AddCandidate(string? path, bool mustBeRooted = true)
        {
            string? normalized = TryNormalizeExecutablePath(path, mustBeRooted);
            if (normalized is not null && seen.Add(normalized))
                candidates.Add(normalized);
        }

        if (!string.IsNullOrWhiteSpace(explicitExecutablePath))
        {
            AddCandidate(explicitExecutablePath);
            return candidates;
        }

        AddCandidate(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "Nmap",
            "nmap.exe"));
        AddCandidate(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Nmap",
            "nmap.exe"));
        return candidates;
    }

    internal static string? TryNormalizeExecutablePath(string? path, bool mustBeRooted = true)
    {
        if (string.IsNullOrWhiteSpace(path))
            return null;

        try
        {
            string expanded = Environment.ExpandEnvironmentVariables(path.Trim().Trim('"'));
            if ((mustBeRooted && !Path.IsPathFullyQualified(expanded)) ||
                IsRemoteOrDevicePath(expanded) ||
                !string.Equals(Path.GetFileName(expanded), "nmap.exe", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            string fullPath = Path.GetFullPath(expanded);
            if (IsRemoteOrDevicePath(fullPath) || !IsLocalDrivePath(fullPath))
                return null;

            return File.Exists(fullPath) ? fullPath : null;
        }
        catch (Exception exception) when (
            exception is ArgumentException or IOException or NotSupportedException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static bool IsRemoteOrDevicePath(string path)
    {
        if (path.StartsWith(@"\\", StringComparison.Ordinal) ||
            path.StartsWith(@"\\?\", StringComparison.Ordinal) ||
            path.StartsWith(@"\\.\", StringComparison.Ordinal))
        {
            return true;
        }

        return Uri.TryCreate(path, UriKind.Absolute, out Uri? uri) && uri.IsUnc;
    }

    private static bool IsLocalDrivePath(string path)
    {
        string? root = Path.GetPathRoot(path);
        if (string.IsNullOrWhiteSpace(root))
            return false;

        try
        {
            DriveType type = new DriveInfo(root).DriveType;
            return type is DriveType.Fixed or DriveType.Removable or DriveType.Ram;
        }
        catch (Exception exception) when (
            exception is ArgumentException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static async Task<ProcessExecutionResult> RunProcessAsync(
        string executablePath,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        int maximumOutputCharacters,
        CancellationToken cancellationToken)
    {
        ProcessStartInfo startInfo = new(executablePath)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            WorkingDirectory = Path.GetDirectoryName(executablePath) ?? AppContext.BaseDirectory
        };

        foreach (string argument in arguments)
            startInfo.ArgumentList.Add(argument);

        using Process process = new() { StartInfo = startInfo };
        try
        {
            if (!process.Start())
                return ProcessExecutionResult.NotStarted;
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return ProcessExecutionResult.NotStarted;
        }

        Task<BoundedCapture> standardOutputTask = ReadBoundedAsync(
            process.StandardOutput,
            maximumOutputCharacters);
        Task<BoundedCapture> standardErrorTask = ReadBoundedAsync(
            process.StandardError,
            MaximumDiagnosticCharacters);

        using CancellationTokenSource timeoutSource =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);

        try
        {
            await process.WaitForExitAsync(timeoutSource.Token);
        }
        catch (OperationCanceledException)
        {
            TryKillProcessTree(process);
            await DrainAfterTerminationAsync(process, standardOutputTask, standardErrorTask);

            cancellationToken.ThrowIfCancellationRequested();
            return ProcessExecutionResult.TimedOutResult;
        }

        await Task.WhenAll(standardOutputTask, standardErrorTask);
        BoundedCapture standardOutput = await standardOutputTask;
        BoundedCapture standardError = await standardErrorTask;
        return new ProcessExecutionResult(
            true,
            false,
            process.ExitCode,
            standardOutput.Text,
            standardError.Text,
            standardOutput.Truncated,
            standardOutput.ReadFailed);
    }

    private static async Task<BoundedCapture> ReadBoundedAsync(
        StreamReader reader,
        int maximumCharacters)
    {
        char[] buffer = new char[4096];
        StringBuilder captured = new(Math.Min(maximumCharacters, 64 * 1024));
        bool truncated = false;

        try
        {
            while (true)
            {
                int read = await reader.ReadAsync(buffer.AsMemory());
                if (read == 0)
                    break;

                int remaining = maximumCharacters - captured.Length;
                if (remaining > 0)
                    captured.Append(buffer, 0, Math.Min(read, remaining));

                if (read > remaining)
                    truncated = true;
            }

            return new BoundedCapture(captured.ToString(), truncated, false);
        }
        catch (Exception exception) when (
            exception is IOException or ObjectDisposedException or InvalidOperationException)
        {
            return new BoundedCapture(captured.ToString(), truncated, true);
        }
    }

    private static void TryKillProcessTree(Process process)
    {
        try
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
        {
            try
            {
                if (!process.HasExited)
                    process.Kill();
            }
            catch (Exception fallbackException) when (
                fallbackException is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
            {
                // O processo pode ter terminado entre a verificação e o pedido de terminação.
            }
        }
    }

    private static async Task DrainAfterTerminationAsync(
        Process process,
        Task<BoundedCapture> standardOutputTask,
        Task<BoundedCapture> standardErrorTask)
    {
        try
        {
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(2));
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or TimeoutException)
        {
            // A limpeza é best-effort; o Process será libertado ao sair do método.
        }

        try
        {
            await Task.WhenAll(standardOutputTask, standardErrorTask)
                .WaitAsync(TimeSpan.FromSeconds(2));
        }
        catch (TimeoutException)
        {
            // Os streams serão fechados ao libertar o Process.
        }
    }

    private static void ValidateXmlShape(string xml)
    {
        using StringReader textReader = new(xml);
        using XmlReader reader = XmlReader.Create(textReader, CreateSecureXmlSettings());
        int elements = 0;
        while (reader.Read())
        {
            if (reader.Depth > MaximumXmlDepth)
                throw new InvalidDataException("XML Nmap demasiado profundo.");

            if (reader.NodeType == XmlNodeType.Element && ++elements > MaximumXmlElements)
                throw new InvalidDataException("XML Nmap com demasiados elementos.");
        }
    }

    private static XmlReaderSettings CreateSecureXmlSettings()
        => new()
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaximumXmlCharacters,
            MaxCharactersFromEntities = 1024,
            IgnoreComments = true,
            IgnoreProcessingInstructions = true,
            CheckCharacters = true
        };

    private static IEnumerable<XElement> ChildElements(XElement parent, string localName)
        => parent.Elements().Where(element =>
            string.Equals(element.Name.LocalName, localName, StringComparison.Ordinal));

    private static string? Attribute(XElement? element, string localName)
        => element?.Attributes()
            .FirstOrDefault(attribute =>
                string.Equals(attribute.Name.LocalName, localName, StringComparison.Ordinal))
            ?.Value;

    private static int GetOsAccuracy(XElement osMatch)
        => int.TryParse(
            Attribute(osMatch, "accuracy"),
            NumberStyles.None,
            CultureInfo.InvariantCulture,
            out int accuracy) && accuracy is >= 0 and <= 100
                ? accuracy
                : 0;

    private static string? NormalizeMacAddress(string? value)
    {
        string? sanitized = Sanitize(value, 32);
        if (sanitized is null)
            return null;

        string hexadecimal = sanitized.Replace(":", string.Empty, StringComparison.Ordinal)
            .Replace("-", string.Empty, StringComparison.Ordinal);
        if (hexadecimal.Length != 12 || hexadecimal.Any(character => !Uri.IsHexDigit(character)))
            return null;

        return string.Join(
            ':',
            Enumerable.Range(0, 6)
                .Select(index => hexadecimal.Substring(index * 2, 2).ToUpperInvariant()));
    }

    private static string? Sanitize(string? value, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value) || maximumLength <= 0)
            return null;

        StringBuilder sanitized = new(Math.Min(value.Length, maximumLength));
        bool pendingSpace = false;
        foreach (char character in value)
        {
            if (char.IsControl(character) || char.IsWhiteSpace(character))
            {
                pendingSpace = sanitized.Length > 0;
                continue;
            }

            if (pendingSpace && sanitized.Length < maximumLength)
                sanitized.Append(' ');

            pendingSpace = false;
            if (sanitized.Length >= maximumLength)
                break;

            sanitized.Append(character);
        }

        return sanitized.Length == 0 ? null : sanitized.ToString();
    }

    private static bool IsPrivateIpv4(IPAddress address)
    {
        byte[] bytes = address.GetAddressBytes();
        return bytes.Length == 4 &&
            (bytes[0] == 10 ||
             (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) ||
             (bytes[0] == 192 && bytes[1] == 168));
    }

    private static string BuildHostTimeout(TimeSpan timeout)
    {
        int seconds = (int)Math.Clamp(timeout.TotalSeconds / 4, 5, 60);
        return string.Create(CultureInfo.InvariantCulture, $"{seconds}s");
    }

    private sealed record BoundedCapture(string Text, bool Truncated, bool ReadFailed);

    private sealed record ProcessExecutionResult(
        bool Started,
        bool TimedOut,
        int ExitCode,
        string StandardOutput,
        string StandardError,
        bool StandardOutputTruncated,
        bool StandardOutputReadFailed)
    {
        public static ProcessExecutionResult NotStarted { get; } =
            new(false, false, -1, string.Empty, string.Empty, false, false);

        public static ProcessExecutionResult TimedOutResult { get; } =
            new(true, true, -1, string.Empty, string.Empty, false, false);
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
