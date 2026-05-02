using System;
using System.IO;
using System.Windows;
using System.Runtime.InteropServices;

namespace RblxExecutorUI;

public partial class App : Application
{
    [DllImport("kernel32.dll")]
    static extern bool AllocConsole();

    public App()
    {
        this.DispatcherUnhandledException += (s, e) => {
            LogException(e.Exception, "Dispatcher");
            e.Handled = true;
        };

        AppDomain.CurrentDomain.UnhandledException += (s, args) => {
            LogException(args.ExceptionObject as Exception, "AppDomain");
        };
    }

    public static void LogException(Exception? ex, string source)
    {
        if (ex == null) return;
        string logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "crash_log.txt");
        string content = $"[CRASH-{source}] {DateTime.Now}\n{ex.Message}\n{ex.StackTrace}\n\nInner: {ex.InnerException?.Message}\n{ex.InnerException?.StackTrace}";
        try { File.AppendAllText(logPath, content + "\n\n"); } catch { }
        Console.WriteLine($"[CRASH-{source}] {ex.Message}");
        MessageBox.Show($"Error [{source}]:\n{ex.Message}", "Antigravity Error");
    }
}
