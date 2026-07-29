// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

public sealed class PingScannerService
{
    private const int DefaultTimeToLive = 128;
    private const int ErrorIoPending = 997;
    private const uint IpSuccess = 0;
    private static readonly byte[] Payload = "LocalNetworkScanner"u8.ToArray();

    public Task<PingProbeResult> ProbeAsync(
        IPAddress ipAddress,
        int timeoutMs,
        CancellationToken cancellationToken) =>
        ProbeAsync(ipAddress, timeoutMs, sourceAddress: null, cancellationToken);

    public async Task<PingProbeResult> ProbeAsync(
        IPAddress ipAddress,
        int timeoutMs,
        IPAddress? sourceAddress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ipAddress);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(timeoutMs);
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            if (OperatingSystem.IsWindows() && sourceAddress is not null)
            {
                if (!TryGetIpv4Address(ipAddress, out uint destination) ||
                    !TryGetIpv4Address(sourceAddress, out uint source))
                {
                    // IcmpSendEcho2Ex apenas permite fixar uma origem IPv4. Não
                    // usar Ping como fallback evita sair silenciosamente por
                    // outra interface quando foi pedida uma origem explícita.
                    return new PingProbeResult(false, null, null);
                }

                Task<PingProbeResult> nativeProbe = WindowsIcmpOperation.Start(
                    source,
                    destination,
                    timeoutMs,
                    cancellationToken);
                return await nativeProbe.WaitAsync(
                    TimeSpan.FromMilliseconds(timeoutMs + 200L),
                    cancellationToken);
            }

            return await ProbeWithManagedPingAsync(
                ipAddress,
                timeoutMs,
                cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is PingException or
                TimeoutException or
                OperationCanceledException or
                DllNotFoundException or
                EntryPointNotFoundException or
                InvalidOperationException)
        {
            return new PingProbeResult(false, null, null);
        }
    }

    private static async Task<PingProbeResult> ProbeWithManagedPingAsync(
        IPAddress ipAddress,
        int timeoutMs,
        CancellationToken cancellationToken)
    {
        using Ping ping = new();
        PingOptions options = new(DefaultTimeToLive, dontFragment: false);
        Task<PingReply> pingTask = ping.SendPingAsync(ipAddress, timeoutMs, Payload, options);
        PingReply reply = await pingTask.WaitAsync(
                TimeSpan.FromMilliseconds(timeoutMs + 200),
                cancellationToken);

        return reply.Status == IPStatus.Success
            ? new PingProbeResult(true, reply.RoundtripTime, reply.Options?.Ttl)
            : new PingProbeResult(false, null, null);
    }

    private static bool TryGetIpv4Address(IPAddress address, out uint nativeAddress)
    {
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        byte[] bytes = address.GetAddressBytes();
        if (bytes.Length == 4)
        {
            nativeAddress = BitConverter.ToUInt32(bytes, 0);
            return true;
        }

        nativeAddress = 0;
        return false;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IcmpIpOptionInformation
    {
        public byte Ttl;
        public byte TypeOfService;
        public byte Flags;
        public byte OptionsSize;
        public IntPtr OptionsData;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IcmpEchoReply
    {
        public uint Address;
        public uint Status;
        public uint RoundTripTime;
        public ushort DataSize;
        public ushort Reserved;
        public IntPtr Data;
        public IcmpIpOptionInformation Options;
    }

    private enum NativeStartOutcome
    {
        NotStarted,
        Pending,
        ImmediateReply,
        Failed
    }

    private sealed class WindowsIcmpOperation : IDisposable
    {
        private readonly uint _sourceAddress;
        private readonly uint _destinationAddress;
        private readonly int _timeoutMs;
        private readonly object _startGate = new();
        private readonly TaskCompletionSource<PingProbeResult> _completion =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        private SafeIcmpHandle? _icmpHandle;
        private EventWaitHandle? _completionEvent;
        private RegisteredWaitHandle? _registeredWait;
        private IntPtr _requestBuffer;
        private IntPtr _requestOptionsBuffer;
        private IntPtr _replyBuffer;
        private int _replySize;
        private NativeStartOutcome _startOutcome;
        private bool _startFinished;
        private bool _signalObserved;
        private int _completionStarted;
        private int _cleanupStarted;

        private WindowsIcmpOperation(
            uint sourceAddress,
            uint destinationAddress,
            int timeoutMs)
        {
            _sourceAddress = sourceAddress;
            _destinationAddress = destinationAddress;
            _timeoutMs = timeoutMs;
        }

        public static Task<PingProbeResult> Start(
            uint sourceAddress,
            uint destinationAddress,
            int timeoutMs,
            CancellationToken cancellationToken)
        {
            WindowsIcmpOperation operation = new(
                sourceAddress,
                destinationAddress,
                timeoutMs);
            return operation.StartCore(cancellationToken);
        }

        private Task<PingProbeResult> StartCore(CancellationToken cancellationToken)
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                InitializeNativeResources();

                // A segunda verificação impede que trabalho cancelado enquanto
                // os buffers eram preparados seja enviado para a rede.
                cancellationToken.ThrowIfCancellationRequested();
                uint replies = IcmpSendEcho2Ex(
                    _icmpHandle!,
                    _completionEvent!.SafeWaitHandle.DangerousGetHandle(),
                    IntPtr.Zero,
                    IntPtr.Zero,
                    _sourceAddress,
                    _destinationAddress,
                    _requestBuffer,
                    checked((ushort)Payload.Length),
                    _requestOptionsBuffer,
                    _replyBuffer,
                    checked((uint)_replySize),
                    checked((uint)_timeoutMs));
                int error = replies == 0 ? Marshal.GetLastPInvokeError() : 0;
                NativeStartOutcome outcome = replies > 0
                    ? NativeStartOutcome.ImmediateReply
                    : error == ErrorIoPending
                        ? NativeStartOutcome.Pending
                        : NativeStartOutcome.Failed;

                bool signalObserved;
                lock (_startGate)
                {
                    _startOutcome = outcome;
                    _startFinished = true;
                    signalObserved = _signalObserved;
                }

                if (outcome != NativeStartOutcome.Pending || signalObserved)
                    Complete(outcome);
            }
            catch
            {
                lock (_startGate)
                {
                    _startOutcome = NativeStartOutcome.Failed;
                    _startFinished = true;
                }

                Cleanup();
                throw;
            }

            return _completion.Task;
        }

        private void InitializeNativeResources()
        {
            _icmpHandle = IcmpCreateFile();
            if (_icmpHandle.IsInvalid)
                throw new InvalidOperationException("Não foi possível criar o handle ICMP do Windows.");

            _completionEvent = new EventWaitHandle(
                initialState: false,
                EventResetMode.AutoReset);
            _requestBuffer = Marshal.AllocHGlobal(Payload.Length);
            Marshal.Copy(Payload, 0, _requestBuffer, Payload.Length);

            IcmpIpOptionInformation requestOptions = new()
            {
                Ttl = DefaultTimeToLive
            };
            _requestOptionsBuffer = Marshal.AllocHGlobal(
                Marshal.SizeOf<IcmpIpOptionInformation>());
            Marshal.StructureToPtr(
                requestOptions,
                _requestOptionsBuffer,
                fDeleteOld: false);

            _replySize = checked(Marshal.SizeOf<IcmpEchoReply>() + Payload.Length + 8);
            _replyBuffer = Marshal.AllocHGlobal(_replySize);

            // O registo existe antes do envio. Se o kernel sinalizar o evento
            // antes de o P/Invoke regressar, OnSignaled apenas memoriza o sinal
            // e StartCore conclui a operação depois de a chamada nativa sair.
            _registeredWait = ThreadPool.RegisterWaitForSingleObject(
                _completionEvent,
                static (state, _) => ((WindowsIcmpOperation)state!).OnSignaled(),
                this,
                Timeout.Infinite,
                executeOnlyOnce: false);
        }

        private void OnSignaled()
        {
            NativeStartOutcome outcome;
            lock (_startGate)
            {
                _signalObserved = true;
                if (!_startFinished)
                    return;

                outcome = _startOutcome;
            }

            Complete(outcome);
        }

        private void Complete(NativeStartOutcome outcome)
        {
            if (Interlocked.Exchange(ref _completionStarted, 1) != 0)
                return;

            PingProbeResult result;
            try
            {
                if (outcome == NativeStartOutcome.Pending &&
                    IcmpParseReplies(_replyBuffer, checked((uint)_replySize)) == 0)
                {
                    result = new PingProbeResult(false, null, null);
                }
                else if (outcome is NativeStartOutcome.Pending or NativeStartOutcome.ImmediateReply)
                {
                    IcmpEchoReply reply =
                        Marshal.PtrToStructure<IcmpEchoReply>(_replyBuffer);
                    result = reply.Status == IpSuccess
                        ? new PingProbeResult(true, reply.RoundTripTime, reply.Options.Ttl)
                        : new PingProbeResult(false, null, null);
                }
                else
                {
                    result = new PingProbeResult(false, null, null);
                }
            }
            catch (Exception exception) when (
                exception is ArgumentException or
                    ExternalException)
            {
                result = new PingProbeResult(false, null, null);
            }

            NativeCleanupQueue.Enqueue(this, result);
        }

        private void CompleteCleanupAfterRegistration(PingProbeResult result)
        {
            try
            {
                RegisteredWaitHandle? registeredWait = _registeredWait;
                if (registeredWait is not null)
                {
                    using EventWaitHandle unregisterCompleted = new(
                        initialState: false,
                        EventResetMode.AutoReset);
                    if (registeredWait.Unregister(unregisterCompleted))
                        unregisterCompleted.WaitOne();

                    _registeredWait = null;
                }
            }
            catch (InvalidOperationException)
            {
                // O registo pode já ter sido libertado durante o encerramento
                // do runtime. O callback já não usa os buffers neste ponto.
                _registeredWait = null;
            }
            finally
            {
                Cleanup();
                _completion.TrySetResult(result);
            }
        }

        private void Cleanup()
        {
            if (Interlocked.Exchange(ref _cleanupStarted, 1) != 0)
                return;

            _registeredWait?.Unregister(null);
            _registeredWait = null;
            _completionEvent?.Dispose();
            _completionEvent = null;
            _icmpHandle?.Dispose();
            _icmpHandle = null;
            FreeBuffer(ref _replyBuffer);
            FreeBuffer(ref _requestOptionsBuffer);
            FreeBuffer(ref _requestBuffer);
        }

        public void Dispose() => Cleanup();

        private static void FreeBuffer(ref IntPtr buffer)
        {
            IntPtr allocatedBuffer = buffer;
            buffer = IntPtr.Zero;
            if (allocatedBuffer != IntPtr.Zero)
                Marshal.FreeHGlobal(allocatedBuffer);
        }

        private static class NativeCleanupQueue
        {
            private static readonly Channel<CleanupRequest> Requests =
                Channel.CreateUnbounded<CleanupRequest>(
                    new UnboundedChannelOptions
                    {
                        SingleReader = true,
                        SingleWriter = false,
                        AllowSynchronousContinuations = false
                    });

            private static readonly Task Worker = Task.Run(ProcessAsync);

            public static void Enqueue(
                WindowsIcmpOperation operation,
                PingProbeResult result)
            {
                _ = Worker;
                if (!Requests.Writer.TryWrite(new CleanupRequest(operation, result)))
                    throw new InvalidOperationException("A fila de limpeza ICMP foi encerrada.");
            }

            private static async Task ProcessAsync()
            {
                await foreach (CleanupRequest request in Requests.Reader.ReadAllAsync())
                {
                    request.Operation.CompleteCleanupAfterRegistration(request.Result);
                }
            }

            private readonly record struct CleanupRequest(
                WindowsIcmpOperation Operation,
                PingProbeResult Result);
        }
    }

    private sealed class SafeIcmpHandle : SafeHandle
    {
        private SafeIcmpHandle()
            : base(IntPtr.Zero, ownsHandle: true)
        {
        }

        public override bool IsInvalid =>
            handle == IntPtr.Zero || handle == new IntPtr(-1);

        protected override bool ReleaseHandle() => IcmpCloseHandle(handle);
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern SafeIcmpHandle IcmpCreateFile();

    [DllImport("iphlpapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IcmpCloseHandle(IntPtr icmpHandle);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint IcmpSendEcho2Ex(
        SafeIcmpHandle icmpHandle,
        IntPtr eventHandle,
        IntPtr apcRoutine,
        IntPtr apcContext,
        uint sourceAddress,
        uint destinationAddress,
        IntPtr requestData,
        ushort requestSize,
        IntPtr requestOptions,
        IntPtr replyBuffer,
        uint replySize,
        uint timeout);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint IcmpParseReplies(
        IntPtr replyBuffer,
        uint replySize);
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
