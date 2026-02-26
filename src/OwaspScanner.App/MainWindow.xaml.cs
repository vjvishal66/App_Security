using Microsoft.Win32;
using OwaspScanner.Core;

namespace OwaspScanner.App;

public partial class MainWindow : Window
{
    private readonly WebsiteScanner _scanner = new();
    private ScanResult? _latestResult;

    public MainWindow()
    {
        InitializeComponent();
    }

    private async void ScanButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (!Uri.TryCreate(TargetUrlBox.Text.Trim(), UriKind.Absolute, out var target))
        {
            MessageBox.Show("Please enter a valid absolute URL.", "Invalid URL", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        ScanButton.IsEnabled = false;
        SaveButton.IsEnabled = false;
        StatusText.Text = "Scanning...";

        try
        {
            var options = new ScanOptions(target);
            _latestResult = await _scanner.ScanAsync(options);
            FindingsGrid.ItemsSource = _latestResult.Findings;
            SaveButton.IsEnabled = true;
            StatusText.Text = $"Done: {_latestResult.Findings.Count} findings | HTTP {_latestResult.StatusCode} | {_latestResult.Duration.TotalMilliseconds:N0} ms";
        }
        catch (Exception ex)
        {
            StatusText.Text = "Scan failed.";
            MessageBox.Show($"Scan failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            ScanButton.IsEnabled = true;
        }
    }

    private void SaveButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (_latestResult is null)
        {
            return;
        }

        var dialog = new SaveFileDialog
        {
            Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*",
            FileName = $"scan-{DateTime.Now:yyyyMMdd-HHmmss}.json"
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        File.WriteAllText(dialog.FileName, WebsiteScanner.ToJson(_latestResult));
        StatusText.Text = $"Report exported to {dialog.FileName}";
    }
}
