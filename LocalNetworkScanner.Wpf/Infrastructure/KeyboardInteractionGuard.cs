// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.

using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Media3D;

namespace LocalNetworkScanner.Wpf.Infrastructure;

internal static class KeyboardInteractionGuard
{
    public static bool ShouldDeferEscape(KeyEventArgs e)
    {
        ArgumentNullException.ThrowIfNull(e);

        DependencyObject? source = Keyboard.FocusedElement as DependencyObject ??
            e.OriginalSource as DependencyObject;
        if (source is null)
            return false;

        ComboBox? comboBox = FindSelfOrAncestor<ComboBox>(source);
        if (comboBox?.IsDropDownOpen == true)
            return true;

        ComboBoxItem? comboBoxItem = FindSelfOrAncestor<ComboBoxItem>(source);
        if (comboBoxItem is not null &&
            ItemsControl.ItemsControlFromItemContainer(comboBoxItem) is ComboBox owner &&
            owner.IsDropDownOpen)
        {
            return true;
        }

        return FindSelfOrAncestor<TextBoxBase>(source) is not null ||
            FindSelfOrAncestor<PasswordBox>(source) is not null ||
            FindSelfOrAncestor<MenuItem>(source) is not null;
    }

    private static T? FindSelfOrAncestor<T>(DependencyObject? source)
        where T : DependencyObject
    {
        DependencyObject? current = source;
        while (current is not null)
        {
            if (current is T match)
                return match;

            current = GetParent(current);
        }

        return null;
    }

    private static DependencyObject? GetParent(DependencyObject source)
    {
        if (source is ContentElement contentElement)
        {
            return ContentOperations.GetParent(contentElement) ??
                (contentElement as FrameworkContentElement)?.Parent;
        }

        return source is Visual or Visual3D
            ? VisualTreeHelper.GetParent(source)
            : LogicalTreeHelper.GetParent(source);
    }
}

// Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
