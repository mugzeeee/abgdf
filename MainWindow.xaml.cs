using System;
using System.IO;
using System.Diagnostics;
using System.Linq;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Media;
using System.Windows.Input;
using System.Windows.Threading;
using System.Windows.Media.Animation;
using ICSharpCode.AvalonEdit.Highlighting;
using System.Runtime.CompilerServices;
using System.Windows.Controls;
using System.Xml;
using ICSharpCode.AvalonEdit.Highlighting.Xshd;
using System.Runtime.InteropServices;

namespace RblxExecutorUI
{
    public class ScriptItem
    {
        public string Name { get; set; }
        public string FullPath { get; set; }
    }

    public partial class MainWindow : Window
    {
        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("kernel32.dll")]
        static extern bool AllocConsole();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        const int SW_HIDE = 0;
        const int SW_SHOW = 5;

        private DispatcherTimer _notificationTimer;
        public ObservableCollection<ScriptItem> ScriptsList { get; set; } = new ObservableCollection<ScriptItem>();

        private bool _isExecuting = false;
        public MainWindow()
        {
            InitializeComponent();
            this.Loaded += MainWindow_Loaded;

            _notificationTimer = new DispatcherTimer();
            _notificationTimer.Interval = TimeSpan.FromSeconds(3);
            _notificationTimer.Tick += (s, e) => CloseNotification();

            ScriptHubList.ItemsSource = ScriptsList;
            LoadScriptsFolder();
            
            try 
            {
                string xshdPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Lua.xshd");
                if (File.Exists(xshdPath))
                {
                    using (XmlTextReader reader = new XmlTextReader(xshdPath))
                    {
                        Editor.SyntaxHighlighting = HighlightingLoader.Load(reader, HighlightingManager.Instance);
                    }
                }
            } 
            catch { }
        }

        private void LoadScriptsFolder()
        {
            try
            {
                string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Scripts");
                if (!Directory.Exists(path))
                {
                    Directory.CreateDirectory(path);
                }

                ScriptsList.Clear();
                var files = Directory.GetFiles(path, "*.*")
                                     .Where(s => s.EndsWith(".lua") || s.EndsWith(".luau") || s.EndsWith(".txt"));

                foreach (var file in files)
                {
                    ScriptsList.Add(new ScriptItem 
                    { 
                        Name = Path.GetFileName(file), 
                        FullPath = file 
                    });
                }
            }
            catch (Exception ex)
            {
                App.LogException(ex, "LoadScriptsFolder");
            }
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                var luaDef = HighlightingManager.Instance.GetDefinition("Lua");
                if (luaDef != null)
                {
                    Editor.SyntaxHighlighting = luaDef;
                }
                Editor.Text = "-- Syntax Executor Premium\n-- Version: 1.0.0\n\nlocal player = game.Players.LocalPlayer\nprint(\"Hello, \" .. player.Name)";
                
                InitializeCore();
            }
            catch (Exception ex)
            {
                InjectionStatus.Text = "INIT ERROR";
                InjectionStatus.Foreground = Brushes.Orange;
                App.LogException(ex, "MainWindow_Loaded");
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private void InitializeCore()
        {
            bool init = RblxCore.Initialize();
            if (init)
            {
                InjectionStatus.Text = "NOT ATTACHED";
                InjectionStatus.Foreground = new SolidColorBrush(Color.FromRgb(142, 142, 142)); // SilverText
            }
            else
            {
                InjectionStatus.Text = "SYSCALL FAILED";
                InjectionStatus.Foreground = Brushes.Red;
            }
        }

        // Window controls
        private void TitleBar_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left) DragMove();
        }

        private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
        private void Close_Click(object sender, RoutedEventArgs e) => Close();

        // Tabs
        private void Tab_Editor(object sender, RoutedEventArgs e) => SwitchTab(ViewEditor);
        private void Tab_ScriptHub(object sender, RoutedEventArgs e) => SwitchTab(ViewScriptHub);
        private void Tab_Clients(object sender, RoutedEventArgs e) => SwitchTab(ViewClients);
        private void Tab_Settings(object sender, RoutedEventArgs e) => SwitchTab(ViewSettings);

        private void SwitchTab(Grid target)
        {
            if (ViewEditor == null) return; // Prevent init crash
            ViewEditor.Visibility = Visibility.Collapsed;
            ViewScriptHub.Visibility = Visibility.Collapsed;
            ViewClients.Visibility = Visibility.Collapsed;
            ViewSettings.Visibility = Visibility.Collapsed;

            target.Visibility = Visibility.Visible;
            DoubleAnimation fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(200));
            target.BeginAnimation(UIElement.OpacityProperty, fadeIn);
        }

        // Notification System
        private void ShowNotification(string message, bool isError = false)
        {
            NotificationText.Text = message;
            
            if (isError)
            {
                NotificationBox.BorderBrush = Brushes.OrangeRed;
                NotificationIcon.Data = Geometry.Parse("M 2,14 L 14,14 L 8,2 Z M 8,11 L 8,12 M 8,6 L 8,9"); // Alert triangle
                NotificationIcon.Stroke = Brushes.OrangeRed;
            }
            else
            {
                NotificationBox.BorderBrush = new SolidColorBrush(Color.FromRgb(0, 255, 136)); // AccentGreen
                NotificationIcon.Data = Geometry.Parse("M 8,2 A 6,6 0 1 1 7.9,2.1 Z M 6,8 L 8,10 L 12,5"); // Check circle
                NotificationIcon.Stroke = new SolidColorBrush(Color.FromRgb(0, 255, 136));
            }

            NotificationBox.Visibility = Visibility.Visible;
            
            // Slide in animation
            TranslateTransform transform = new TranslateTransform(50, 0);
            NotificationBox.RenderTransform = transform;
            
            DoubleAnimation slideIn = new DoubleAnimation(50, 0, TimeSpan.FromMilliseconds(300))
            {
                EasingFunction = new QuarticEase() { EasingMode = EasingMode.EaseOut }
            };
            DoubleAnimation fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(300));

            transform.BeginAnimation(TranslateTransform.XProperty, slideIn);
            NotificationBox.BeginAnimation(UIElement.OpacityProperty, fadeIn);

            _notificationTimer.Stop();
            _notificationTimer.Start();
        }

        private void CloseNotification()
        {
            _notificationTimer.Stop();
            
            TranslateTransform transform = new TranslateTransform(0, 0);
            NotificationBox.RenderTransform = transform;
            
            DoubleAnimation slideOut = new DoubleAnimation(0, 20, TimeSpan.FromMilliseconds(200));
            DoubleAnimation fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(200));
            
            fadeOut.Completed += (s, e) => NotificationBox.Visibility = Visibility.Collapsed;

            transform.BeginAnimation(TranslateTransform.XProperty, slideOut);
            NotificationBox.BeginAnimation(UIElement.OpacityProperty, fadeOut);
        }

        private void Execute_Click(object sender, RoutedEventArgs e)
        {
            if (_isExecuting) return;
            _isExecuting = true;
            try
            {
                string script = Editor.Text;
                if (string.IsNullOrWhiteSpace(script))
                {
                    ShowNotification("No script to execute", true);
                    _isExecuting = false;
                    return;
                }

                Console.WriteLine($"[C# UI] Executing EDITOR script ({script.Length} chars)...");
                ShowNotification("Executing Script...", false);

                int result = RblxCore.ExecuteScript(script, script.Length);
                e.Handled = true;

                if (result == 0)
                {
                    ShowNotification("Executed Successfully!", false);
                }
                else
                {
                    string error = RblxCore.GetLastError();
                    ShowNotification($"Error: {error}", true);
                }
            }
            catch (Exception ex)
            {
                ShowNotification("Execution Exception", true);
                App.LogException(ex, "Execute_Click");
            }
            finally
            {
                _isExecuting = false;
            }
        }

        private void Clear_Click(object sender, RoutedEventArgs e)
        {
            Editor.Text = "";
            ShowNotification("Editor Cleared", false);
        }

        private void Save_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string scriptPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Scripts");
                if (!Directory.Exists(scriptPath)) Directory.CreateDirectory(scriptPath);

                var dialog = new Microsoft.Win32.SaveFileDialog()
                {
                    InitialDirectory = scriptPath,
                    Filter = "Lua Scripts (*.lua;*.luau;*.txt)|*.lua;*.luau;*.txt|All Files (*.*)|*.*",
                    DefaultExt = "lua"
                };

                if (dialog.ShowDialog() == true)
                {
                    File.WriteAllText(dialog.FileName, Editor.Text);
                    ShowNotification("Script Saved Successfully", false);
                    LoadScriptsFolder(); // Refresh the hub
                }
            }
            catch (Exception)
            {
                ShowNotification("Failed to save file", true);
            }
        }

        private void Open_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string scriptPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Scripts");
                if (!Directory.Exists(scriptPath)) Directory.CreateDirectory(scriptPath);
                
                Process.Start("explorer.exe", scriptPath);
                ShowNotification("Opened Scripts Folder", false);
            }
            catch (Exception)
            {
                ShowNotification("Failed to open folder", true);
            }
        }

        private void ExecuteScriptHub_Click(object sender, RoutedEventArgs e)
        {
            if (_isExecuting) return;
            _isExecuting = true;
            try 
            {
                var btn = sender as Button;
                if (btn != null && btn.Tag != null)
                {
                    string path = btn.Tag.ToString();
                    if (File.Exists(path))
                    {
                        string content = File.ReadAllText(path);
                        Console.WriteLine($"[C# UI] Executing HUB script: {Path.GetFileName(path)} ({content.Length} chars)...");
                        ShowNotification($"Executing {Path.GetFileName(path)}...", false);
                        RblxCore.ExecuteScript(content, content.Length);
                        e.Handled = true;
                    }
                }
            }
            catch (Exception ex)
            {
                ShowNotification("Hub script error!", true);
                App.LogException(ex, "ExecuteScriptHub_Click");
            }
            finally
            {
                _isExecuting = false;
            }
        }

        private void CopyScriptHub_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var btn = sender as Button;
                if (btn != null && btn.Tag != null)
                {
                    string path = btn.Tag.ToString();
                    if (File.Exists(path))
                    {
                        Clipboard.SetText(File.ReadAllText(path));
                        ShowNotification("Code Copied!", false);
                    }
                }
            }
            catch (Exception)
            {
                ShowNotification("Copy Failed!", true);
            }
        }

        private void DeleteScriptHub_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var btn = sender as Button;
                if (btn != null && btn.Tag != null)
                {
                    string path = btn.Tag.ToString();
                    if (File.Exists(path))
                    {
                        File.Delete(path);
                        ShowNotification("Script Deleted!", false);
                        LoadScriptsFolder();
                    }
                }
            }
            catch (Exception)
            {
                ShowNotification("Delete Failed!", true);
            }
        }

        private void KillRoblox_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var procs = System.Diagnostics.Process.GetProcessesByName("RobloxPlayerBeta");
                foreach (var p in procs) { p.Kill(); }
                ShowNotification("Roblox Terminated", false);
            }
            catch { ShowNotification("No Roblox to Kill", true); }
        }

        private void StartProcessMonitor(uint pid)
        {
            var timer = new DispatcherTimer();
            timer.Interval = TimeSpan.FromSeconds(3);
            timer.Tick += (s, ev) => 
            {
                try {
                    var proc = System.Diagnostics.Process.GetProcessById((int)pid);
                    if (proc.HasExited) throw new Exception();
                } catch {
                    timer.Stop();
                    // Reset UI
                    InjectionStatus.Text = "NOT INJECTED";
                    InjectionStatus.Foreground = Brushes.Red;
                    ClientPidText.Text = "PID: None | Place: None";
                    ClientStatusBadge.Text = "READY";
                    ClientStatusBadge.Foreground = Brushes.White;
                    ClientBadgeBg.Background = new SolidColorBrush(Color.FromArgb(25, 255, 255, 255));
                    ClientAccountName.Text = "Not Connected";
                    ClientAvatarImage.Source = null;
                    RblxCore.Disconnect();
                }
            };
            timer.Start();
        }

        private void StartClientDataPoller(uint pid)
        {
            var timer = new DispatcherTimer();
            timer.Interval = TimeSpan.FromSeconds(2);
            int attempts = 0;
            
            timer.Tick += (s, ev) => 
            {
                attempts++;
                if (attempts > 15) {
                    timer.Stop();
                    return; // Give up after 30 seconds
                }

                var sb = new System.Text.StringBuilder(512);
                if (RblxCore.GetClientInfo(sb, sb.Capacity))
                {
                    string body = sb.ToString();
                    var parts = body.Split('|');
                    if (parts.Length >= 4 && parts[0] != "Unknown") // Now expects 4 parts (Name, UserId, JobId, PlaceId)
                    {
                        timer.Stop(); // Data found, stop polling
                        
                        string accountName = parts[0];
                        string userId = parts[1];
                        string jobId = parts[2];
                        string placeId = parts[3];

                        // Run the web requests asynchronously so UI doesn't freeze
                        System.Threading.Tasks.Task.Run(async () =>
                        {
                            string finalPlaceName = $"Place: {placeId}";
                            try
                            {
                                using (var client = new System.Net.Http.HttpClient())
                                {
                                    client.DefaultRequestHeaders.Add("User-Agent", "Roblox/WinInet");
                                    
                                    // 1. Resolve PlaceId -> Game Name
                                    if (placeId != "0")
                                    {
                                        string apiRes = await client.GetStringAsync($"https://economy.roblox.com/v2/assets/{placeId}/details");
                                        var match = System.Text.RegularExpressions.Regex.Match(apiRes, "\"Name\"\\s*:\\s*\"([^\"]+)\"");
                                        if (match.Success) finalPlaceName = match.Groups[1].Value;
                                    }

                                    // 2. Resolve UserId -> Avatar JSON -> Actual Image URL -> Download Stream
                                    string avatarMetaUrl = $"https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds={userId}&size=150x150&format=Png&isCircular=false";
                                    string metaRes = await client.GetStringAsync(avatarMetaUrl);
                                    string actualImgUrl = "";
                                    
                                    var imgMatch = System.Text.RegularExpressions.Regex.Match(metaRes, "\"imageUrl\"\\s*:\\s*\"([^\"]+)\"");
                                    if (imgMatch.Success) actualImgUrl = imgMatch.Groups[1].Value;

                                    byte[] imgBytes = null;
                                    if (!string.IsNullOrEmpty(actualImgUrl))
                                    {
                                        imgBytes = await client.GetByteArrayAsync(actualImgUrl);
                                    }

                                    Dispatcher.Invoke(() =>
                                    {
                                        ClientAccountName.Text = accountName;
                                        ClientPidText.Text = $"PID: {pid} | {finalPlaceName}";

                                        if (imgBytes != null)
                                        {
                                            try
                                            {
                                                var bmp = new System.Windows.Media.Imaging.BitmapImage();
                                                bmp.BeginInit();
                                                bmp.StreamSource = new System.IO.MemoryStream(imgBytes);
                                                bmp.CacheOption = System.Windows.Media.Imaging.BitmapCacheOption.OnLoad;
                                                bmp.EndInit();
                                                ClientAvatarImage.Source = bmp;
                                            }
                                            catch { }
                                        }
                                    });
                                }
                            }
                            catch
                            {
                                // Fallback if web request fails
                                Dispatcher.Invoke(() =>
                                {
                                    ClientAccountName.Text = accountName;
                                    ClientPidText.Text = $"PID: {pid} | Place: {placeId}";
                                });
                            }
                        });
                    }
                }
            };
            timer.Start();
        }

        private async void Attach_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ShowNotification("Attaching to Roblox...", false);
                await System.Threading.Tasks.Task.Run(() => 
                {
                    uint pid = RblxCore.FindRobloxProcess();
                    
                    if (pid == 0)
                    {
                        Dispatcher.Invoke(() => ShowNotification("Roblox not found!", true));
                        return;
                    }

                    Dispatcher.Invoke(() => ShowNotification($"Connecting to PID {pid}...", false));
                    bool connected = RblxCore.Connect(pid);
                    
                    Dispatcher.Invoke(() => 
                    {
                        if (connected)
                        {
                            ShowNotification("Successfully attached to game!", false);
                            
                            InjectionStatus.Text = "STABLE";
                            InjectionStatus.Foreground = new SolidColorBrush(Color.FromRgb(0, 255, 136));
                            
                            // Update client page
                            ClientPidText.Text = $"PID: {pid} | Place: Active";
                            ClientStatusBadge.Text = "ACTIVE SESSION";
                            ClientStatusBadge.Foreground = new SolidColorBrush(Color.FromRgb(0, 255, 136));
                            ClientBadgeBg.Background = new SolidColorBrush(Color.FromArgb(25, 0, 255, 136)); // 10% opacity
                            
                            // Start native polling and monitors
                            StartClientDataPoller(pid);
                            StartProcessMonitor(pid);
                        }
                        else
                        {
                            ShowNotification("Connect failed!", true);
                            InjectionStatus.Text = "FAILED";
                            InjectionStatus.Foreground = Brushes.Red;
                        }
                    });
                });
            }
            catch (Exception ex)
            {
                ShowNotification("Attach Exception", true);
                App.LogException(ex, "Attach_Click");
            }
        }

        private void ToggleConsole_Checked(object sender, RoutedEventArgs e)
        {
            var handle = GetConsoleWindow();
            if (handle == IntPtr.Zero)
            {
                AllocConsole();
                RblxCore.RedirConsole(); // Sync C++ stdout to new console
                Console.WriteLine("[C# UI] Console allocated on user request.");
                handle = GetConsoleWindow();
            }
            
            if (handle != IntPtr.Zero) ShowWindow(handle, SW_SHOW);
        }

        private void ToggleConsole_Unchecked(object sender, RoutedEventArgs e)
        {
            var handle = GetConsoleWindow();
            if (handle != IntPtr.Zero) ShowWindow(handle, SW_HIDE);
        }
    }
}