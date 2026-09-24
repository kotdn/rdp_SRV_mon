using System;
using System.IO;
using System.Text;
using System.Windows.Forms;

namespace RDPMonitor
{
    static class Program
    {
        public static string CurrentLanguage = "UA";

        private static void WriteBootstrapLog(string message)
        {
            try
            {
                string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RDPSecurityService");
                Directory.CreateDirectory(dir);
                string path = Path.Combine(dir, "monitor-bootstrap.log");
                string line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}";
                File.AppendAllText(path, line + Environment.NewLine, Encoding.UTF8);
            }
            catch
            {
            }
        }

        [STAThread]
        static void Main(string[] args)
        {
            if (args != null && args.Length > 0 && string.Equals(args[0], "--healthcheck", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    WriteBootstrapLog("Healthcheck start.");
                    Application.EnableVisualStyles();
                    Application.SetCompatibleTextRenderingDefault(false);
                    using (var form = new MainForm())
                    {
                    }
                    WriteBootstrapLog("Healthcheck passed.");
                    Environment.ExitCode = 0;
                }
                catch (Exception ex)
                {
                    WriteBootstrapLog($"Healthcheck failed: {ex}");
                    Environment.ExitCode = 2;
                }

                return;
            }

            Application.ThreadException += (_, e) =>
            {
                string details = e.Exception?.ToString() ?? "Unknown UI thread exception";
                WriteBootstrapLog($"ThreadException: {details}");
                MessageBox.Show($"RDP Monitor failed on UI thread.\r\n\r\n{details}", "RDP Monitor Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            };

            AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            {
                string details = e.ExceptionObject?.ToString() ?? "Unknown fatal exception";
                WriteBootstrapLog($"UnhandledException: {details}");
            };

            try
            {
                WriteBootstrapLog("Monitor startup begin.");
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);

                // Default language is UA, can be changed in UI
                CurrentLanguage = "UA";

                Application.Run(new MainForm());
                WriteBootstrapLog("Monitor exited normally.");
            }
            catch (Exception ex)
            {
                WriteBootstrapLog($"Fatal startup error: {ex}");
                MessageBox.Show($"RDP Monitor failed to start.\r\n\r\n{ex}", "RDP Monitor Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}
