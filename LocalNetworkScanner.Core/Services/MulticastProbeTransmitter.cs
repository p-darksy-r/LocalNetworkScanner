// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Net;
using System.Net.Sockets;

namespace LocalNetworkScanner.Core.Services;

/// <summary>
/// Aplica um orçamento comum e retransmissões espaçadas a sondas UDP multicast.
/// </summary>
internal static class MulticastProbeTransmitter
{
    internal const int DefaultMaximumTransmissions = 3;

    public static async ValueTask<bool> SendAsync(
        UdpClient client,
        ReadOnlyMemory<byte> payload,
        IPEndPoint destination,
        MulticastSendBudget budget,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(budget);

        if (!budget.TryConsumeDatagram())
            return false;

        _ = await client.SendAsync(payload, destination, cancellationToken);
        return true;
    }

    public static async Task RetransmitAsync(
        UdpClient client,
        ReadOnlyMemory<byte> payload,
        IPEndPoint destination,
        int timeoutMs,
        MulticastSendBudget budget,
        CancellationToken cancellationToken,
        int maximumTransmissions = DefaultMaximumTransmissions)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(budget);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(timeoutMs);
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumTransmissions, 1);

        if (maximumTransmissions == 1)
            return;

        // A primeira transmissão é feita pelo chamador. Os intervalos usam apenas
        // uma fração do prazo total, deixando a parte final para receber respostas.
        int baseDelayMs = Math.Max(20, timeoutMs / maximumTransmissions);
        int maximumJitterMs = Math.Min(75, Math.Max(4, baseDelayMs / 4));

        try
        {
            for (int transmission = 1; transmission < maximumTransmissions; transmission++)
            {
                int jitterMs = Random.Shared.Next(-maximumJitterMs, maximumJitterMs + 1);
                int delayMs = Math.Max(1, baseDelayMs + jitterMs);
                await Task.Delay(delayMs, cancellationToken);

                if (!await SendAsync(
                        client,
                        payload,
                        destination,
                        budget,
                        cancellationToken))
                {
                    break;
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // O ciclo de receção é responsável por distinguir o prazo interno
            // do cancelamento pedido pelo utilizador.
        }
        catch (Exception exception) when (
            exception is SocketException or InvalidOperationException or ObjectDisposedException)
        {
            // Uma retransmissão é best effort. A primeira sonda e qualquer evidência
            // já recebida continuam válidas se a interface desaparecer entretanto.
        }
    }
}

internal sealed class MulticastSendBudget
{
    private readonly int _maximumDatagrams;
    private int _datagramsConsumed;

    public MulticastSendBudget(int maximumDatagrams)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumDatagrams);
        _maximumDatagrams = maximumDatagrams;
    }

    public int DatagramsConsumed => Volatile.Read(ref _datagramsConsumed);

    public bool TryConsumeDatagram()
    {
        while (true)
        {
            int consumed = Volatile.Read(ref _datagramsConsumed);
            if (consumed >= _maximumDatagrams)
                return false;

            if (Interlocked.CompareExchange(
                    ref _datagramsConsumed,
                    consumed + 1,
                    consumed) == consumed)
            {
                return true;
            }
        }
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
