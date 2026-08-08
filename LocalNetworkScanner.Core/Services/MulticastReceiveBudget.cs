// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

namespace LocalNetworkScanner.Core.Services;

internal sealed class MulticastReceiveBudget
{
    private readonly int _maximumDatagrams;
    private readonly int _maximumBytes;
    private readonly int _maximumItems;

    public MulticastReceiveBudget(int maximumDatagrams, int maximumBytes, int maximumItems)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumDatagrams);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumItems);

        _maximumDatagrams = maximumDatagrams;
        _maximumBytes = maximumBytes;
        _maximumItems = maximumItems;
    }

    public int DatagramsConsumed { get; private set; }

    public int BytesConsumed { get; private set; }

    public int ItemsConsumed { get; private set; }

    public bool TryConsumeDatagram(int byteCount)
    {
        if (byteCount < 0 ||
            DatagramsConsumed >= _maximumDatagrams ||
            byteCount > _maximumBytes - BytesConsumed)
        {
            return false;
        }

        DatagramsConsumed++;
        BytesConsumed += byteCount;
        return true;
    }

    public bool TryConsumeItems(int itemCount)
    {
        if (itemCount < 0 || itemCount > _maximumItems - ItemsConsumed)
            return false;

        ItemsConsumed += itemCount;
        return true;
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
