// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Globalization;
using System.Windows.Controls;
using LocalNetworkScanner.Wpf.Services;

namespace LocalNetworkScanner.Wpf.Infrastructure;

public sealed class IntegerRangeValidationRule : ValidationRule
{
    public string FieldName { get; set; } = "Valor";

    public int Minimum { get; set; } = int.MinValue;

    public int Maximum { get; set; } = int.MaxValue;

    public override ValidationResult Validate(object value, CultureInfo cultureInfo)
    {
        cultureInfo = LocalizationService.CurrentCulture;
        string fieldName = LocalizationService.Translate(FieldName);
        string text = value?.ToString()?.Trim() ?? string.Empty;
        if (text.Length == 0)
        {
            return new ValidationResult(
                false,
                LocalizationService.CurrentLanguage == AppLanguage.EnUs
                    ? $"{fieldName}: enter an integer between {Minimum.ToString("N0", cultureInfo)} and {Maximum.ToString("N0", cultureInfo)}."
                    : $"{fieldName}: introduz um número inteiro entre {Minimum.ToString("N0", cultureInfo)} e {Maximum.ToString("N0", cultureInfo)}.");
        }

        if (!int.TryParse(text, NumberStyles.Integer, cultureInfo, out int number))
        {
            return new ValidationResult(
                false,
                LocalizationService.CurrentLanguage == AppLanguage.EnUs
                    ? $"{fieldName}: “{text}” is not a valid integer."
                    : $"{fieldName}: “{text}” não é um número inteiro válido.");
        }

        return number < Minimum || number > Maximum
            ? new ValidationResult(
                false,
                LocalizationService.CurrentLanguage == AppLanguage.EnUs
                    ? $"{fieldName}: use a value between {Minimum.ToString("N0", cultureInfo)} and {Maximum.ToString("N0", cultureInfo)}."
                    : $"{fieldName}: usa um valor entre {Minimum.ToString("N0", cultureInfo)} e {Maximum.ToString("N0", cultureInfo)}.")
            : ValidationResult.ValidResult;
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
