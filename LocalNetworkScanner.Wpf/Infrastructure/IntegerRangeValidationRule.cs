// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Globalization;
using System.Windows.Controls;

namespace LocalNetworkScanner.Wpf.Infrastructure;

public sealed class IntegerRangeValidationRule : ValidationRule
{
    public string FieldName { get; set; } = "Valor";

    public int Minimum { get; set; } = int.MinValue;

    public int Maximum { get; set; } = int.MaxValue;

    public override ValidationResult Validate(object value, CultureInfo cultureInfo)
    {
        string text = value?.ToString()?.Trim() ?? string.Empty;
        if (text.Length == 0)
        {
            return new ValidationResult(
                false,
                $"{FieldName}: introduz um número inteiro entre {Minimum:N0} e {Maximum:N0}.");
        }

        if (!int.TryParse(text, NumberStyles.Integer, cultureInfo, out int number))
        {
            return new ValidationResult(
                false,
                $"{FieldName}: “{text}” não é um número inteiro válido.");
        }

        return number < Minimum || number > Maximum
            ? new ValidationResult(
                false,
                $"{FieldName}: usa um valor entre {Minimum:N0} e {Maximum:N0}.")
            : ValidationResult.ValidResult;
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
