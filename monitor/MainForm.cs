using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Globalization;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.IO.Compression;

namespace RDPMonitor
{
    public class MainForm : Form
    {
        private const string SERVICE_NAME = "RDPSecurityService";
        private const string LOG_DIR = @"C:\ProgramData\RDPSecurityService";
        private const string SUPPORT_CONTACT_URL = "https://github.com/kotdn/rdp_SRV_mon/issues";

        // Must match RDPSecurityService.ServiceControlResyncFirewall in WinService/Program.cs.
        // Custom service control codes are only valid in the 128-255 range.
        private const int ServiceControlResyncFirewall = 128;
        
        // Top panels
        private Panel pnlTopContainer;
        private Panel pnlServiceStatusContainer;
        private Panel pnlConfigurationContainer;
        private Label lblServiceStatusHeader;
        private Label lblConfigurationHeader;
        private Label lblServiceStatus;
        private Label lblConfig;
        private Button btnRefresh;
        private Button btnStartService;
        private Button btnStopService;
        private MenuStrip mainMenu;
        private ToolStripMenuItem menuLanguage;
        private ToolStripMenuItem menuLanguageUa;
        private ToolStripMenuItem menuLanguageEn;
        
        // TabControl
        private TabControl tabControl;
        
        // Tab: Current Logs
        private TextBox txtLogs;
        
        // Tab: Banned IPs  
        private ListBox lstBannedIPs;
        private Label lblBannedTitle;
        private Label lblBannedUnblock;
        private Button btnUnblockIP;
        private Button btnClearAllBlocks;
        private TextBox txtIPToUnblock;
        
        // Tab: White List
        private ListBox lstWhiteList;
        private Label lblWhiteTitle;
        private Label lblWhiteAdd;
        private TextBox txtNewWhiteIP;
        private Button btnAddWhiteIP;
        private Button btnRemoveWhiteIP;
        
        // Tab: Manual Block
        private Label lblManualTitle;
        private Label lblManualIp;
        private Label lblManualDuration;
        private TextBox txtIPToBlock;
        private TextBox txtBlockMinutes;
        private Button btnManualBlock;
        private Label lblBlockStatus;

        // Tab: Settings
        private TextBox txtPort;
        private Label lblSettingsServiceConfigTitle;
        private Label lblSettingsRdpPort;
        private Label lblSettingsBlockLevels;
        private Label lblFailedAttemptsWindowDays;
        private TextBox txtFailedAttemptsWindowDays;
        private DataGridView dgvBlockLevels;
        private Button btnSaveConfig;
        private Button btnAddLevel;
        private Button btnRemoveLevel;
        private DataGridView dgvInterfaces;
        private Button btnReloadInterfaces;
        private Button btnSaveInterfaces;
        private Label lblInterfacesHint;
        private CheckBox chkAntiBruteEnabled;
        private CheckBox chkSprayEnabled;
        private TextBox txtSprayWindowMinutes;
        private TextBox txtSprayUniqueIpsThreshold;
        private TextBox txtSprayBlockMinutes;
        private TextBox txtIpAbuseWindowMinutes;
        private TextBox txtIpAbuseDistinctUsersThreshold;
        private CheckBox chkRecurrenceEnabled;
        private TextBox txtRecurrenceLookbackHours;
        private TextBox txtRecurrenceStepMultiplier;
        private TextBox txtRecurrenceMaxMultiplier;
        private CheckBox chkSubnetEnabled;
        private TextBox txtSubnetWindowMinutes;
        private TextBox txtSubnetUniqueIpsThreshold;
        private TextBox txtSubnetBlockMinutes;
        private Label lblAntiBruteSectionTitle;
        private Label lblSprayTitle;
        private Label lblIpAbuseTitle;
        private Label lblRecurrenceTitle;
        private Label lblSubnetTitle;
        private Label lblAntiBruteSprayWindow;
        private Label lblAntiBruteSprayThreshold;
        private Label lblAntiBruteSprayBlock;
        private Label lblAntiBruteIpAbuseWindow;
        private Label lblAntiBruteIpAbuseUsers;
        private Label lblAntiBruteRecurrenceLookback;
        private Label lblAntiBruteRecurrenceStep;
        private Label lblAntiBruteRecurrenceMax;
        private Label lblAntiBruteSubnetWindow;
        private Label lblAntiBruteSubnetThreshold;
        private Label lblAntiBruteSubnetBlock;
        private ToolTip antiBruteHelpToolTip;
        private Label lblHelpAntiBrute;
        private Label lblHelpSpray;
        private Label lblHelpIpAbuse;
        private Label lblHelpRecurrence;
        private Label lblHelpSubnet;
        private Label lblInterfacesTitle;
        private Label lblAlertsHeader;
        private Label lblAlertsBotToken;
        private Label lblAlertsChatId;
        private Label lblAlertsTemplatesHeader;
        private Label lblAlertsPlaceholders;
        private readonly List<Label> lblAlertsLevelCaptions = new List<Label>();
        private Label lblAlertsDefaultTemplate;
        private Label lblAlertsHelpTitle;
        private readonly List<Label> lblAlertsHelpSteps = new List<Label>();
        private Label lblMessageSettingsHeader;
        private Label lblMessageSettingsMonitorSection;
        private Label lblMessageSettingsServiceSection;
        
        // Tab: Telegram/Alerts
        private CheckBox chkTelegramEnabled;
        private TextBox txtTelegramBotToken;
        private TextBox txtTelegramChatId;
        private Button btnTestTelegram;
        private Button btnSaveTelegram;
        private Label lblTelegramStatus;
        private Dictionary<string, TextBox> txtMessageTemplates = new Dictionary<string, TextBox>();
        
        // Tab: Message Settings
        private CheckBox chkNotifyMonitorStart;
        private CheckBox chkNotifyMonitorClose;
        private CheckBox chkNotifyServiceStart;
        private CheckBox chkNotifyServiceStop;
        private CheckBox chkNotifyConfigSave;
        private Button btnSaveMessageSettings;
        private Button btnPrepareSupportReport;
        
        // Timers and watchers
        private System.Windows.Forms.Timer refreshTimer;
        private FileSystemWatcher fileWatcher;
        private long lastAccessLogPosition = 0;
        private long lastBlockLogPosition = 0;
        private long lastServiceLogPosition = 0;
        private readonly Dictionary<string, DateTime> recentFileLogEntries = new Dictionary<string, DateTime>();
        private static readonly TimeSpan DuplicateLogWindow = TimeSpan.FromSeconds(20);
        private bool suppressIpMaskUpdate = false;

        public MainForm()
        {
            InitializeComponents();
            LoadInitialData();
            SetupFileWatcher();
            StartAutoRefresh();
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            BeginInvoke(new Action(() =>
            {
                NotifyMonitorLifecycle("MonitorStart", "\uD83D\uDDA5\uFE0F RDP Security Monitor \u0437\u0430\u043F\u0443\u0449\u0435\u043D\u043E", fireAndForget: true);
            }));
        }

        private void NotifyMonitorLifecycle(string eventType, string message, bool fireAndForget)
        {
            if (!ShouldNotify(eventType))
            {
                WriteMonitorEventLog($"[MONITOR_UI] Telegram notify skipped for {eventType}: setting disabled");
                return;
            }

            WriteMonitorEventLog($"[MONITOR_UI] Sending Telegram notify for {eventType}");

            if (fireAndForget)
            {
                Task.Run(() => SendSimpleTelegramMessage(message));
            }
            else
            {
                SendSimpleTelegramMessage(message);
            }
        }

        private void InitializeComponents()
        {
            this.Text = Lang.Get("MAIN_TITLE");
            this.Size = new Size(1000, 750);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.BackColor = Color.FromArgb(240, 240, 240);
            this.Font = new Font("Segoe UI", 9);

            this.ShowIcon = true;
            try
            {
                var iconPath = Path.Combine(AppContext.BaseDirectory, "app.ico");
                if (File.Exists(iconPath))
                {
                    using var fileIcon = new Icon(iconPath);
                    this.Icon = (Icon)fileIcon.Clone();
                }
                else
                {
                    this.Icon = SystemIcons.Shield;
                }
            }
            catch
            {
                this.Icon = SystemIcons.Shield;
            }

            mainMenu = new MenuStrip
            {
                Dock = DockStyle.Top,
                Font = new Font("Segoe UI", 9),
                ImageScalingSize = new Size(24, 16)
            };

            var uaFlag = CreateLanguageFlagImage("UA");
            var enFlag = CreateLanguageFlagImage("EN");

            menuLanguage = new ToolStripMenuItem("Мова");
            menuLanguageUa = new ToolStripMenuItem("UA") { Image = uaFlag };
            menuLanguageEn = new ToolStripMenuItem("EN") { Image = enFlag };
            menuLanguageUa.Click += (s, e) => SetLanguage("UA");
            menuLanguageEn.Click += (s, e) => SetLanguage("EN");
            menuLanguage.DropDownItems.Add(menuLanguageUa);
            menuLanguage.DropDownItems.Add(menuLanguageEn);
            mainMenu.Items.Add(menuLanguage);

            this.Controls.Add(mainMenu);
            SyncLanguageMenuChecks();

            // ===== TOP STATUS PANEL =====
            pnlTopContainer = new Panel
            {
                Location = new Point(10, 34),
                Size = new Size(980, 120),
                BackColor = Color.White,
                BorderStyle = BorderStyle.None
            };

            // Left panel - Service Status
            pnlServiceStatusContainer = new Panel
            {
                Location = new Point(0, 0),
                Size = new Size(500, 120),
                BackColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle
            };
            pnlTopContainer.Controls.Add(pnlServiceStatusContainer);

            // Right panel - Configuration
            pnlConfigurationContainer = new Panel
            {
                Location = new Point(515, 0),
                Size = new Size(465, 120),
                BackColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle
            };
            pnlTopContainer.Controls.Add(pnlConfigurationContainer);

            lblServiceStatusHeader = new Label
            {
                Text = Lang.Get("SERVICE_STATUS_HEADER"),
                Location = new Point(10, 10),
                Size = new Size(300, 20),
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                ForeColor = Color.FromArgb(0, 102, 204)
            };
            pnlServiceStatusContainer.Controls.Add(lblServiceStatusHeader);

            lblServiceStatus = new Label
            {
                Location = new Point(10, 35),
                Size = new Size(400, 25),
                Font = new Font("Segoe UI", 11),
                Text = Lang.Get("SERVICE_CHECKING"),
                ForeColor = Color.FromArgb(100, 100, 100)
            };
            pnlServiceStatusContainer.Controls.Add(lblServiceStatus);

            btnStartService = new Button
            {
                Text = Lang.Get("BTN_START"),
                Location = new Point(10, 65),
                Size = new Size(80, 25),
                BackColor = Color.FromArgb(76, 175, 80),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            btnStartService.FlatAppearance.BorderSize = 0;
            btnStartService.Click += BtnStartService_Click;
            pnlServiceStatusContainer.Controls.Add(btnStartService);

            btnStopService = new Button
            {
                Text = Lang.Get("BTN_STOP"),
                Location = new Point(100, 65),
                Size = new Size(80, 25),
                BackColor = Color.FromArgb(244, 67, 54),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            btnStopService.FlatAppearance.BorderSize = 0;
            btnStopService.Click += BtnStopService_Click;
            pnlServiceStatusContainer.Controls.Add(btnStopService);

            btnRefresh = new Button
            {
                Text = Lang.Get("BTN_REFRESH"),
                Location = new Point(190, 65),
                Size = new Size(80, 25),
                BackColor = Color.FromArgb(33, 150, 243),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            btnRefresh.FlatAppearance.BorderSize = 0;
            btnRefresh.Click += BtnRefresh_Click;
            pnlServiceStatusContainer.Controls.Add(btnRefresh);

            // Config on right side of top panel
            lblConfigurationHeader = new Label
            {
                Text = Lang.Get("CONFIG_HEADER"),
                Location = new Point(10, 10),
                Size = new Size(300, 20),
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                ForeColor = Color.FromArgb(0, 102, 204)
            };
            pnlConfigurationContainer.Controls.Add(lblConfigurationHeader);

            lblConfig = new Label
            {
                Location = new Point(10, 35),
                Size = new Size(450, 75),
                Font = new Font("Consolas", 8),
                Text = Lang.Get("LOADING"),
                AutoSize = false,
                BackColor = Color.FromArgb(250, 250, 250)
            };
            pnlConfigurationContainer.Controls.Add(lblConfig);

            this.Controls.Add(pnlTopContainer);

            // ===== TAB CONTROL =====
            tabControl = new TabControl
            {
                Location = new Point(10, 164),
                Size = new Size(980, 560),
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom,
                Font = new Font("Segoe UI", 9)
            };

            // Tab 1: Current Logs
            var tabLogs = new TabPage(Lang.Get("TAB_CURRENT_LOGS"));
            CreateCurrentLogsTab(tabLogs);
            tabControl.TabPages.Add(tabLogs);

            // Tab 2: Banned IPs
            var tabBanned = new TabPage(Lang.Get("TAB_BANNED_IPS"));
            CreateBannedIPsTab(tabBanned);
            tabControl.TabPages.Add(tabBanned);

            // Tab 3: White List
            var tabWhite = new TabPage(Lang.Get("TAB_WHITE_LIST"));
            CreateWhiteListTab(tabWhite);
            tabControl.TabPages.Add(tabWhite);

            // Tab 4: Manual Block
            var tabManual = new TabPage(Lang.Get("TAB_MANUAL_BLOCK"));
            CreateManualBlockTab(tabManual);
            tabControl.TabPages.Add(tabManual);

            // Tab 5: Settings
            var tabSettings = new TabPage(Lang.Get("TAB_SETTINGS"));
            CreateSettingsTab(tabSettings);
            tabControl.TabPages.Add(tabSettings);

            // Tab 6: Interfaces
            var tabInterfaces = new TabPage(Lang.Get("TAB_INTERFACES"));
            CreateInterfacesTab(tabInterfaces);
            tabControl.TabPages.Add(tabInterfaces);

            // Tab 7: Alerts (Telegram)
            var tabAlerts = new TabPage(Lang.Get("TAB_ALERTS"));
            CreateAlertsTab(tabAlerts);
            tabControl.TabPages.Add(tabAlerts);

            // Tab 8: Message Settings
            var tabMessageSettings = new TabPage(Lang.Get("TAB_MESSAGE_SETTINGS"));
            CreateMessageSettingsTab(tabMessageSettings);
            tabControl.TabPages.Add(tabMessageSettings);

            this.Controls.Add(tabControl);

            this.Resize += (s, e) => ApplyMainLayout();
            ApplyMainLayout();

            // ===== BACKGROUND SHIELD IMAGE (ADD LAST SO IT STAYS BEHIND) =====
            AddBackgroundShield();
        }

        private void ApplyMainLayout()
        {
            if (mainMenu == null || pnlTopContainer == null || pnlServiceStatusContainer == null || pnlConfigurationContainer == null || tabControl == null)
                return;

            int margin = 10;
            int topY = mainMenu.Bottom + 6;
            int topHeight = 120;
            int totalWidth = Math.Max(500, this.ClientSize.Width - margin * 2);
            int gap = 15;

            pnlTopContainer.Location = new Point(margin, topY);
            pnlTopContainer.Size = new Size(totalWidth, topHeight);

            int leftWidth = (totalWidth - gap) / 2;
            int rightWidth = totalWidth - gap - leftWidth;

            pnlServiceStatusContainer.Location = new Point(0, 0);
            pnlServiceStatusContainer.Size = new Size(leftWidth, topHeight);

            pnlConfigurationContainer.Location = new Point(leftWidth + gap, 0);
            pnlConfigurationContainer.Size = new Size(rightWidth, topHeight);

            if (lblServiceStatusHeader != null)
                lblServiceStatusHeader.Size = new Size(Math.Max(120, leftWidth - 20), 20);
            if (lblServiceStatus != null)
                lblServiceStatus.Size = new Size(Math.Max(120, leftWidth - 20), 25);
            if (lblConfigurationHeader != null)
                lblConfigurationHeader.Size = new Size(Math.Max(120, rightWidth - 20), 20);
            if (lblConfig != null)
                lblConfig.Size = new Size(Math.Max(120, rightWidth - 20), 75);

            int tabY = pnlTopContainer.Bottom + 10;
            int tabHeight = Math.Max(200, this.ClientSize.Height - tabY - margin);
            tabControl.Location = new Point(margin, tabY);
            tabControl.Size = new Size(totalWidth, tabHeight);
        }

        private void AddBackgroundShield()
        {
            try
            {
                var resourcePath = Path.Combine(AppContext.BaseDirectory, "Resources", "shield_bg.png");
                if (!File.Exists(resourcePath))
                    return;

                var backgroundImage = Image.FromFile(resourcePath);
                
                // Calculate centered position and scaled size
                int imageSize = 400; // Max size for the shield
                int x = (this.ClientSize.Width - imageSize) / 2;
                int y = (this.ClientSize.Height - imageSize) / 2 + 50; // Offset down slightly

                var picShield = new TransparentPictureBox
                {
                    Image = backgroundImage,
                    Location = new Point(x, y),
                    Size = new Size(imageSize, imageSize),
                    SizeMode = PictureBoxSizeMode.Zoom,
                    BackColor = Color.Transparent
                };

                // Add as first control (behind everything)
                this.Controls.Add(picShield);
                picShield.SendToBack();

                // Reposition on resize
                this.Resize += (s, e) =>
                {
                    int newX = (this.ClientSize.Width - imageSize) / 2;
                    int newY = (this.ClientSize.Height - imageSize) / 2 + 50;
                    picShield.Location = new Point(newX, newY);
                };
            }
            catch
            {
                // Silently fail if image not found
            }
        }

        private void CreateCurrentLogsTab(TabPage tab)
        {
            txtLogs = new TextBox
            {
                Dock = DockStyle.Fill,
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                ReadOnly = true,
                Font = new Font("Consolas", 9),
                BackColor = Color.FromArgb(30, 30, 30),
                ForeColor = Color.FromArgb(0, 255, 0),
                BorderStyle = BorderStyle.None
            };
            tab.Controls.Add(txtLogs);
        }

        private void CreateBannedIPsTab(TabPage tab)
        {
            var pnl = new Panel { Dock = DockStyle.Fill, Padding = new Padding(20, 20, 20, 50), AutoScroll = true };
            pnl.HorizontalScroll.Enabled = false;
            pnl.HorizontalScroll.Visible = false;

            lblBannedTitle = new Label
            {
                Text = Lang.Get("SECTION_BLOCKED_IPS_FIREWALL"),
                AutoSize = true,
                Location = new Point(10, 10),
                MaximumSize = new Size(950, 0),
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            pnl.Controls.Add(lblBannedTitle);

            lstBannedIPs = new ListBox
            {
                Location = new Point(10, 45),
                Size = new Size(950, 330),
                Font = new Font("Consolas", 10),
                BackColor = Color.FromArgb(250, 250, 250)
            };
            lstBannedIPs.DoubleClick += LstBannedIPs_DoubleClick;
            lstBannedIPs.MouseDown += LstBannedIPs_MouseDown;
            pnl.Controls.Add(lstBannedIPs);

            lblBannedUnblock = new Label
            {
                Text = Lang.Get("SECTION_IP_TO_UNBLOCK"),
                Location = new Point(10, 385),
                AutoSize = true,
                Font = new Font("Segoe UI", 9)
            };
            pnl.Controls.Add(lblBannedUnblock);

            txtIPToUnblock = new TextBox
            {
                Location = new Point(10, 410),
                Size = new Size(200, 25),
                Font = new Font("Segoe UI", 9),
                Padding = new Padding(5)
            };
            AttachIpInputMask(txtIPToUnblock);
            pnl.Controls.Add(txtIPToUnblock);

            btnUnblockIP = new Button
            {
                Text = "🔓 " + Lang.Get("BTN_UNBLOCK_IP"),
                Location = new Point(220, 410),
                Size = new Size(160, 25),
                BackColor = Color.FromArgb(255, 152, 0),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            btnUnblockIP.FlatAppearance.BorderSize = 0;
            btnUnblockIP.Click += BtnUnblockIP_Click;
            pnl.Controls.Add(btnUnblockIP);

            btnClearAllBlocks = new Button
            {
                Text = "🧹 " + Lang.Get("BTN_CLEAR_ALL_BLOCKS"),
                Location = new Point(390, 410),
                Size = new Size(220, 25),
                BackColor = Color.FromArgb(198, 40, 40),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            btnClearAllBlocks.FlatAppearance.BorderSize = 0;
            btnClearAllBlocks.Click += BtnClearAllBlocks_Click;
            pnl.Controls.Add(btnClearAllBlocks);

            tab.Controls.Add(pnl);
        }

        private void CreateWhiteListTab(TabPage tab)
        {
            var pnl = new Panel { Dock = DockStyle.Fill, Padding = new Padding(20, 20, 20, 50), AutoScroll = true };
            pnl.HorizontalScroll.Enabled = false;
            pnl.HorizontalScroll.Visible = false;

            lblWhiteTitle = new Label
            {
                Text = Lang.Get("SECTION_WHITE_LIST"),
                AutoSize = true,
                Location = new Point(10, 10),
                MaximumSize = new Size(950, 0),
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            pnl.Controls.Add(lblWhiteTitle);

            lstWhiteList = new ListBox
            {
                Location = new Point(10, 45),
                Size = new Size(950, 330),
                Font = new Font("Consolas", 10),
                BackColor = Color.FromArgb(250, 250, 250)
            };
            
            // Context menu for whitelist
            var contextMenu = new ContextMenuStrip();
            var deleteItem = new ToolStripMenuItem("🗑️ Видалити", null, (s, e) => 
            {
                if (lstWhiteList.SelectedIndex >= 0)
                {
                    string ip = lstWhiteList.SelectedItem.ToString();
                    if (ip != Lang.Get("MSG_NO_WHITELISTED_IPS"))
                    {
                        txtNewWhiteIP.Text = ip;
                        BtnRemoveWhiteIP_Click(null, null);
                    }
                }
            });
            contextMenu.Items.Add(deleteItem);
            lstWhiteList.ContextMenuStrip = contextMenu;
            
            pnl.Controls.Add(lstWhiteList);

            lblWhiteAdd = new Label
            {
                Text = Lang.Get("SECTION_ADD_WHITELIST_IP"),
                Location = new Point(10, 385),
                AutoSize = true,
                Font = new Font("Segoe UI", 9)
            };
            pnl.Controls.Add(lblWhiteAdd);

            txtNewWhiteIP = new TextBox
            {
                Location = new Point(10, 410),
                Size = new Size(200, 25),
                Font = new Font("Segoe UI", 9),
                PlaceholderText = "192.168.1.100"
            };
            AttachIpInputMask(txtNewWhiteIP);
            pnl.Controls.Add(txtNewWhiteIP);

            btnAddWhiteIP = new Button
            {
                Text = Lang.Get("BTN_ADD_WITH_PLUS"),
                Location = new Point(220, 410),
                Size = new Size(80, 25),
                BackColor = Color.FromArgb(76, 175, 80),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            btnAddWhiteIP.FlatAppearance.BorderSize = 0;
            btnAddWhiteIP.Click += BtnAddWhiteIP_Click;
            pnl.Controls.Add(btnAddWhiteIP);

            btnRemoveWhiteIP = new Button
            {
                Text = Lang.Get("BTN_REMOVE_WITH_X"),
                Location = new Point(310, 410),
                Size = new Size(100, 25),
                BackColor = Color.FromArgb(244, 67, 54),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            btnRemoveWhiteIP.FlatAppearance.BorderSize = 0;
            btnRemoveWhiteIP.Click += BtnRemoveWhiteIP_Click;
            pnl.Controls.Add(btnRemoveWhiteIP);

            tab.Controls.Add(pnl);
        }

        private void CreateManualBlockTab(TabPage tab)
        {
            var pnl = new Panel { Dock = DockStyle.Fill, Padding = new Padding(20, 20, 20, 50), AutoScroll = true };
            pnl.HorizontalScroll.Enabled = false;
            pnl.HorizontalScroll.Visible = false;

            lblManualTitle = new Label
            {
                Text = Lang.Get("SECTION_MANUAL_BLOCK"),
                AutoSize = true,
                Location = new Point(10, 10),
                Font = new Font("Segoe UI", 11, FontStyle.Bold),
                ForeColor = Color.FromArgb(244, 67, 54)
            };
            pnl.Controls.Add(lblManualTitle);

            lblManualIp = new Label
            {
                Text = Lang.Get("LABEL_IP_ADDRESS"),
                AutoSize = true,
                Location = new Point(10, 50),
                Font = new Font("Segoe UI", 9)
            };
            pnl.Controls.Add(lblManualIp);

            txtIPToBlock = new TextBox
            {
                Location = new Point(10, 75),
                Size = new Size(300, 28),
                Font = new Font("Segoe UI", 10),
                PlaceholderText = "192.168.1.50"
            };
            AttachIpInputMask(txtIPToBlock);
            pnl.Controls.Add(txtIPToBlock);

            lblManualDuration = new Label
            {
                Text = Lang.Get("LABEL_BLOCK_DURATION_FULL"),
                AutoSize = true,
                Location = new Point(10, 115),
                Font = new Font("Segoe UI", 9)
            };
            pnl.Controls.Add(lblManualDuration);

            txtBlockMinutes = new TextBox
            {
                Location = new Point(10, 140),
                Size = new Size(300, 28),
                Font = new Font("Segoe UI", 10),
                Text = "60",
                PlaceholderText = "60 / 12h / 7d / 2w"
            };
            pnl.Controls.Add(txtBlockMinutes);

            btnManualBlock = new Button
            {
                Text = "🔒 " + Lang.Get("BTN_BLOCK_THIS_IP"),
                Location = new Point(10, 185),
                Size = new Size(300, 40),
                BackColor = Color.FromArgb(244, 67, 54),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 11, FontStyle.Bold)
            };
            btnManualBlock.FlatAppearance.BorderSize = 0;
            btnManualBlock.Click += BtnManualBlock_Click;
            pnl.Controls.Add(btnManualBlock);

            lblBlockStatus = new Label
            {
                Location = new Point(10, 240),
                Size = new Size(900, 180),
                Font = new Font("Segoe UI", 9),
                BackColor = Color.FromArgb(250, 250, 250),
                BorderStyle = BorderStyle.FixedSingle,
                Text = Lang.Get("LABEL_BLOCK_STATUS_PLACEHOLDER"),
                AutoSize = false
            };
            pnl.Controls.Add(lblBlockStatus);

            tab.Controls.Add(pnl);
        }

        private void AttachIpInputMask(TextBox textBox)
        {
            textBox.KeyPress += IpTextBox_KeyPress;
            textBox.TextChanged += IpTextBox_TextChanged;
        }

        private void IpTextBox_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (char.IsControl(e.KeyChar))
                return;

            if (char.IsDigit(e.KeyChar) || e.KeyChar == '.')
                return;

            e.Handled = true;
        }

        private void IpTextBox_TextChanged(object sender, EventArgs e)
        {
            if (suppressIpMaskUpdate || sender is not TextBox textBox)
                return;

            string original = textBox.Text;
            string normalized = NormalizePartialIpv4(original);
            if (normalized == original)
                return;

            int caret = textBox.SelectionStart;
            string leftPart = NormalizePartialIpv4(original.Substring(0, Math.Min(caret, original.Length)));

            suppressIpMaskUpdate = true;
            textBox.Text = normalized;
            textBox.SelectionStart = Math.Min(leftPart.Length, textBox.Text.Length);
            suppressIpMaskUpdate = false;
        }

        private string NormalizePartialIpv4(string input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            var output = new StringBuilder(input.Length);
            int dots = 0;
            int octetDigits = 0;
            int octetValue = 0;
            bool hasDigitInCurrentOctet = false;

            foreach (char ch in input)
            {
                if (char.IsDigit(ch))
                {
                    if (dots > 3 || octetDigits >= 3)
                        continue;

                    int digit = ch - '0';
                    int candidate = octetDigits == 0 ? digit : (octetValue * 10) + digit;
                    if (candidate > 255)
                        continue;

                    output.Append(ch);
                    octetValue = candidate;
                    octetDigits++;
                    hasDigitInCurrentOctet = true;
                    continue;
                }

                if (ch == '.')
                {
                    if (!hasDigitInCurrentOctet || dots >= 3)
                        continue;

                    output.Append(ch);
                    dots++;
                    octetDigits = 0;
                    octetValue = 0;
                    hasDigitInCurrentOctet = false;
                }
            }

            return output.ToString();
        }

        private void CreateSettingsTab(TabPage tab)
        {
            var pnl = new Panel { Dock = DockStyle.Fill, Padding = new Padding(20, 20, 20, 50), AutoScroll = true };
            pnl.HorizontalScroll.Enabled = false;
            pnl.HorizontalScroll.Visible = false;

            lblSettingsServiceConfigTitle = new Label
            {
                Text = Lang.Get("SECTION_SERVICE_CONFIG"),
                AutoSize = true,
                Location = new Point(10, 10),
                Font = new Font("Segoe UI", 11, FontStyle.Bold),
                ForeColor = Color.FromArgb(0, 102, 204)
            };
            pnl.Controls.Add(lblSettingsServiceConfigTitle);

            // RDP Port
            lblSettingsRdpPort = new Label
            {
                Text = Lang.Get("LABEL_RDP_PORT"),
                AutoSize = true,
                Location = new Point(10, 50),
                Font = new Font("Segoe UI", 9)
            };
            pnl.Controls.Add(lblSettingsRdpPort);

            txtPort = new TextBox
            {
                Location = new Point(10, 75),
                Size = new Size(150, 28),
                Font = new Font("Segoe UI", 10),
                Text = "3389"
            };
            pnl.Controls.Add(txtPort);

            // Block Levels
            lblSettingsBlockLevels = new Label
            {
                Text = Lang.Get("LABEL_BLOCK_LEVELS_TABLE") + " (60 / 12h / 7d / 2w)",
                AutoSize = true,
                Location = new Point(10, 120),
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            pnl.Controls.Add(lblSettingsBlockLevels);

            dgvBlockLevels = new DataGridView
            {
                Location = new Point(10, 145),
                Size = new Size(400, 200),
                Font = new Font("Segoe UI", 9),
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
                AllowUserToAddRows = false,
                AllowUserToDeleteRows = false
            };
            dgvBlockLevels.Columns.Add("Attempts", Lang.Get("COL_ATTEMPTS"));
            dgvBlockLevels.Columns.Add("BlockMinutes", Lang.Get("COL_BLOCK_MINUTES"));

            for (int i = 0; i < dgvBlockLevels.Columns.Count; i++)
            {
                dgvBlockLevels.Columns[i].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
            }

            pnl.Controls.Add(dgvBlockLevels);

            btnAddLevel = new Button
            {
                Text = Lang.Get("BTN_ADD_LEVEL_WITH_PLUS"),
                Location = new Point(10, 355),
                Size = new Size(100, 28),
                BackColor = Color.FromArgb(76, 175, 80),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            btnAddLevel.FlatAppearance.BorderSize = 0;
            btnAddLevel.Click += BtnAddLevel_Click;
            pnl.Controls.Add(btnAddLevel);

            btnRemoveLevel = new Button
            {
                Text = Lang.Get("BTN_REMOVE_WITH_X"),
                Location = new Point(120, 355),
                Size = new Size(100, 28),
                BackColor = Color.FromArgb(244, 67, 54),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            btnRemoveLevel.FlatAppearance.BorderSize = 0;
            btnRemoveLevel.Click += BtnRemoveLevel_Click;
            pnl.Controls.Add(btnRemoveLevel);

            // How many days a single failed attempt stays on the per-IP counter above before
            // aging out — keeps unrelated typos by different people behind one shared IP,
            // spread across days, from adding up into a false lockout of everyone on that IP.
            lblFailedAttemptsWindowDays = new Label
            {
                Text = Lang.Get("LABEL_FAILED_ATTEMPTS_WINDOW_DAYS"),
                AutoSize = true,
                Location = new Point(10, 395),
                Font = new Font("Segoe UI", 9)
            };
            pnl.Controls.Add(lblFailedAttemptsWindowDays);

            txtFailedAttemptsWindowDays = new TextBox
            {
                Location = new Point(10, 420),
                Size = new Size(150, 28),
                Font = new Font("Segoe UI", 10),
                Text = "1"
            };
            pnl.Controls.Add(txtFailedAttemptsWindowDays);

            lblAntiBruteSectionTitle = new Label
            {
                Text = Lang.Get("ANTI_BRUTE_SECTION"),
                AutoSize = true,
                Location = new Point(440, 50),
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                ForeColor = Color.FromArgb(0, 102, 204)
            };
            pnl.Controls.Add(lblAntiBruteSectionTitle);

            lblHelpAntiBrute = CreateHelpBadge(0, 0);
            pnl.Controls.Add(lblHelpAntiBrute);

            chkAntiBruteEnabled = new CheckBox
            {
                Text = Lang.Get("ANTI_BRUTE_ENABLED"),
                AutoSize = true,
                Location = new Point(440, 78),
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            pnl.Controls.Add(chkAntiBruteEnabled);

            lblSprayTitle = new Label
            {
                Text = Lang.Get("ANTI_BRUTE_SPRAY"),
                AutoSize = true,
                Location = new Point(440, 110),
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            pnl.Controls.Add(lblSprayTitle);

            lblHelpSpray = CreateHelpBadge(0, 0);
            pnl.Controls.Add(lblHelpSpray);

            chkSprayEnabled = new CheckBox
            {
                Text = Lang.Get("ANTI_BRUTE_ENABLED_SHORT"),
                AutoSize = true,
                Location = new Point(440, 132)
            };
            pnl.Controls.Add(chkSprayEnabled);

            lblAntiBruteSprayWindow = new Label
            {
                Text = Lang.Get("ANTI_BRUTE_WINDOW_MIN"),
                AutoSize = true,
                Location = new Point(440, 158)
            };
            pnl.Controls.Add(lblAntiBruteSprayWindow);

            txtSprayWindowMinutes = new TextBox
            {
                Location = new Point(690, 154),
                Size = new Size(90, 24),
                Text = "10"
            };
            pnl.Controls.Add(txtSprayWindowMinutes);

            lblAntiBruteSprayThreshold = new Label
            {
                Text = Lang.Get("ANTI_BRUTE_UNIQUE_IPS"),
                AutoSize = true,
                Location = new Point(440, 186)
            };
            pnl.Controls.Add(lblAntiBruteSprayThreshold);

            txtSprayUniqueIpsThreshold = new TextBox
            {
                Location = new Point(690, 182),
                Size = new Size(90, 24),
                Text = "4"
            };
            pnl.Controls.Add(txtSprayUniqueIpsThreshold);

            lblAntiBruteSprayBlock = new Label
            {
                Text = Lang.Get("ANTI_BRUTE_BLOCK_MIN"),
                AutoSize = true,
                Location = new Point(440, 214)
            };
            pnl.Controls.Add(lblAntiBruteSprayBlock);

            txtSprayBlockMinutes = new TextBox
            {
                Location = new Point(690, 210),
                Size = new Size(90, 24),
                Text = "240"
            };
            pnl.Controls.Add(txtSprayBlockMinutes);

            lblIpAbuseTitle = new Label
            {
                Text = Lang.Get("ANTI_BRUTE_IP_ABUSE"),
                AutoSize = true,
                Location = new Point(440, 242),
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            pnl.Controls.Add(lblIpAbuseTitle);

            lblHelpIpAbuse = CreateHelpBadge(0, 0);
            pnl.Controls.Add(lblHelpIpAbuse);

            lblAntiBruteIpAbuseWindow = new Label
            {
                Text = Lang.Get("ANTI_BRUTE_WINDOW_MIN") + " (NAT: M=10)",
                AutoSize = true,
                Location = new Point(440, 268)
            };
            pnl.Controls.Add(lblAntiBruteIpAbuseWindow);

            txtIpAbuseWindowMinutes = new TextBox
            {
                Location = new Point(690, 264),
                Size = new Size(90, 24),
                Text = "10"
            };
            pnl.Controls.Add(txtIpAbuseWindowMinutes);

            lblAntiBruteIpAbuseUsers = new Label
            {
                Text = Lang.Get("ANTI_BRUTE_UNIQUE_USERS") + " (NAT: N=3)",
                AutoSize = true,
                Location = new Point(440, 296)
            };
            pnl.Controls.Add(lblAntiBruteIpAbuseUsers);

            txtIpAbuseDistinctUsersThreshold = new TextBox
            {
                Location = new Point(690, 292),
                Size = new Size(90, 24),
                Text = "3"
            };
            pnl.Controls.Add(txtIpAbuseDistinctUsersThreshold);

            lblRecurrenceTitle = new Label
            {
                Text = Lang.Get("ANTI_BRUTE_RECURRENCE"),
                AutoSize = true,
                Location = new Point(440, 328),
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            pnl.Controls.Add(lblRecurrenceTitle);

            lblHelpRecurrence = CreateHelpBadge(0, 0);
            pnl.Controls.Add(lblHelpRecurrence);

            chkRecurrenceEnabled = new CheckBox
            {
                Text = Lang.Get("ANTI_BRUTE_ENABLED_SHORT"),
                AutoSize = true,
                Location = new Point(440, 350)
            };
            pnl.Controls.Add(chkRecurrenceEnabled);

            lblAntiBruteRecurrenceLookback = new Label
            {
                Text = Lang.Get("ANTI_BRUTE_LOOKBACK_H"),
                AutoSize = true,
                Location = new Point(440, 376)
            };
            pnl.Controls.Add(lblAntiBruteRecurrenceLookback);

            txtRecurrenceLookbackHours = new TextBox
            {
                Location = new Point(690, 372),
                Size = new Size(90, 24),
                Text = "24"
            };
            pnl.Controls.Add(txtRecurrenceLookbackHours);

            lblAntiBruteRecurrenceStep = new Label
            {
                Text = Lang.Get("ANTI_BRUTE_STEP"),
                AutoSize = true,
                Location = new Point(440, 404)
            };
            pnl.Controls.Add(lblAntiBruteRecurrenceStep);

            txtRecurrenceStepMultiplier = new TextBox
            {
                Location = new Point(690, 400),
                Size = new Size(90, 24),
                Text = "0.5"
            };
            pnl.Controls.Add(txtRecurrenceStepMultiplier);

            lblAntiBruteRecurrenceMax = new Label
            {
                Text = Lang.Get("ANTI_BRUTE_MAX"),
                AutoSize = true,
                Location = new Point(440, 432)
            };
            pnl.Controls.Add(lblAntiBruteRecurrenceMax);

            txtRecurrenceMaxMultiplier = new TextBox
            {
                Location = new Point(690, 428),
                Size = new Size(90, 24),
                Text = "4.0"
            };
            pnl.Controls.Add(txtRecurrenceMaxMultiplier);

            lblSubnetTitle = new Label
            {
                Text = Lang.Get("ANTI_BRUTE_SUBNET"),
                AutoSize = true,
                Location = new Point(440, 464),
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            pnl.Controls.Add(lblSubnetTitle);

            lblHelpSubnet = CreateHelpBadge(0, 0);
            pnl.Controls.Add(lblHelpSubnet);

            chkSubnetEnabled = new CheckBox
            {
                Text = Lang.Get("ANTI_BRUTE_ENABLED_SHORT"),
                AutoSize = true,
                Location = new Point(440, 486)
            };
            pnl.Controls.Add(chkSubnetEnabled);

            lblAntiBruteSubnetWindow = new Label
            {
                Text = Lang.Get("ANTI_BRUTE_WINDOW_MIN"),
                AutoSize = true,
                Location = new Point(440, 512)
            };
            pnl.Controls.Add(lblAntiBruteSubnetWindow);

            txtSubnetWindowMinutes = new TextBox
            {
                Location = new Point(690, 508),
                Size = new Size(90, 24),
                Text = "30"
            };
            pnl.Controls.Add(txtSubnetWindowMinutes);

            lblAntiBruteSubnetThreshold = new Label
            {
                Text = Lang.Get("ANTI_BRUTE_UNIQUE_IPS"),
                AutoSize = true,
                Location = new Point(440, 540)
            };
            pnl.Controls.Add(lblAntiBruteSubnetThreshold);

            txtSubnetUniqueIpsThreshold = new TextBox
            {
                Location = new Point(690, 536),
                Size = new Size(90, 24),
                Text = "3"
            };
            pnl.Controls.Add(txtSubnetUniqueIpsThreshold);

            lblAntiBruteSubnetBlock = new Label
            {
                Text = Lang.Get("ANTI_BRUTE_BLOCK_MIN"),
                AutoSize = true,
                Location = new Point(440, 568)
            };
            pnl.Controls.Add(lblAntiBruteSubnetBlock);

            txtSubnetBlockMinutes = new TextBox
            {
                Location = new Point(690, 564),
                Size = new Size(90, 24),
                Text = "240"
            };
            pnl.Controls.Add(txtSubnetBlockMinutes);

            btnSaveConfig = new Button
            {
                Text = "💾 " + Lang.Get("BTN_SAVE_CONFIGURATION"),
                Location = new Point(10, 622),
                Size = new Size(900, 42),
                BackColor = Color.FromArgb(33, 150, 243),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 10, FontStyle.Bold)
            };
            btnSaveConfig.FlatAppearance.BorderSize = 0;
            btnSaveConfig.Click += BtnSaveConfig_Click;
            pnl.Controls.Add(btnSaveConfig);

            tab.Controls.Add(pnl);

            PositionAntiBruteHelpBadges();
            ApplyAntiBruteHelpTooltips();
            
            // Load initial config
            LoadConfigToSettings();
        }

        private Label CreateHelpBadge(int x, int y)
        {
            return new Label
            {
                Text = "?",
                Location = new Point(x, y),
                AutoSize = true,
                Font = new Font("Segoe UI", 11, FontStyle.Bold),
                ForeColor = Color.FromArgb(198, 40, 40),
                BackColor = Color.Transparent,
                BorderStyle = BorderStyle.None,
                Cursor = Cursors.Help
            };
        }

        private void PositionAntiBruteHelpBadges()
        {
            PositionHelpBadge(lblHelpAntiBrute, lblAntiBruteSectionTitle);
            PositionHelpBadge(lblHelpSpray, lblSprayTitle);
            PositionHelpBadge(lblHelpIpAbuse, lblIpAbuseTitle);
            PositionHelpBadge(lblHelpRecurrence, lblRecurrenceTitle);
            PositionHelpBadge(lblHelpSubnet, lblSubnetTitle);
        }

        private void PositionHelpBadge(Label helpBadge, Label titleLabel)
        {
            if (helpBadge == null || titleLabel == null)
                return;

            helpBadge.Left = titleLabel.Right + 6;
            helpBadge.Top = titleLabel.Top - 1;
            helpBadge.BringToFront();
        }

        private void ApplyAntiBruteHelpTooltips()
        {
            if (antiBruteHelpToolTip == null)
            {
                antiBruteHelpToolTip = new ToolTip
                {
                    AutoPopDelay = 20000,
                    InitialDelay = 250,
                    ReshowDelay = 100,
                    ShowAlways = true
                };
            }

            if (lblHelpAntiBrute != null)
                antiBruteHelpToolTip.SetToolTip(lblHelpAntiBrute, Lang.Get("ANTI_BRUTE_HELP_OVERVIEW"));
            if (lblHelpSpray != null)
                antiBruteHelpToolTip.SetToolTip(lblHelpSpray, Lang.Get("ANTI_BRUTE_HELP_SPRAY"));
            if (lblHelpIpAbuse != null)
                antiBruteHelpToolTip.SetToolTip(lblHelpIpAbuse, Lang.Get("ANTI_BRUTE_HELP_IP_ABUSE"));
            if (lblHelpRecurrence != null)
                antiBruteHelpToolTip.SetToolTip(lblHelpRecurrence, Lang.Get("ANTI_BRUTE_HELP_RECURRENCE"));
            if (lblHelpSubnet != null)
                antiBruteHelpToolTip.SetToolTip(lblHelpSubnet, Lang.Get("ANTI_BRUTE_HELP_SUBNET"));
        }

        private void CreateInterfacesTab(TabPage tab)
        {
            var pnl = new Panel { Dock = DockStyle.Fill, Padding = new Padding(20, 20, 20, 50), AutoScroll = true };
            pnl.HorizontalScroll.Enabled = false;
            pnl.HorizontalScroll.Visible = false;

            lblInterfacesTitle = new Label
            {
                Text = Lang.Get("IFACE_HEADER"),
                AutoSize = true,
                Location = new Point(10, 10),
                Font = new Font("Segoe UI", 11, FontStyle.Bold),
                ForeColor = Color.FromArgb(0, 102, 204)
            };
            pnl.Controls.Add(lblInterfacesTitle);

            lblInterfacesHint = new Label
            {
                Text = Lang.Get("IFACE_HINT"),
                AutoSize = true,
                Location = new Point(10, 40),
                Font = new Font("Segoe UI", 9),
                ForeColor = Color.FromArgb(80, 80, 80)
            };
            pnl.Controls.Add(lblInterfacesHint);

            dgvInterfaces = new DataGridView
            {
                Location = new Point(10, 70),
                Size = new Size(900, 430),
                Font = new Font("Segoe UI", 9),
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
                AllowUserToAddRows = false,
                AllowUserToDeleteRows = false,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect
            };

            var colEnabled = new DataGridViewCheckBoxColumn
            {
                Name = "Enabled",
                HeaderText = Lang.Get("IFACE_COL_ENABLED"),
                FillWeight = 20
            };
            dgvInterfaces.Columns.Add(colEnabled);
            dgvInterfaces.Columns.Add("Address", Lang.Get("IFACE_COL_IP"));
            dgvInterfaces.Columns.Add("Name", Lang.Get("IFACE_COL_NAME"));
            dgvInterfaces.Columns["Address"].ReadOnly = true;
            dgvInterfaces.Columns["Name"].ReadOnly = true;
            dgvInterfaces.Columns["Address"].FillWeight = 35;
            dgvInterfaces.Columns["Name"].FillWeight = 45;
            pnl.Controls.Add(dgvInterfaces);

            btnReloadInterfaces = new Button
            {
                Text = Lang.Get("IFACE_BTN_RELOAD"),
                Location = new Point(10, 515),
                Size = new Size(150, 30),
                BackColor = Color.FromArgb(33, 150, 243),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            btnReloadInterfaces.FlatAppearance.BorderSize = 0;
            btnReloadInterfaces.Click += (s, e) => LoadInterfacesFromConfig();
            pnl.Controls.Add(btnReloadInterfaces);

            btnSaveInterfaces = new Button
            {
                Text = Lang.Get("IFACE_BTN_SAVE"),
                Location = new Point(170, 515),
                Size = new Size(200, 30),
                BackColor = Color.FromArgb(76, 175, 80),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            btnSaveInterfaces.FlatAppearance.BorderSize = 0;
            btnSaveInterfaces.Click += BtnSaveInterfaces_Click;
            pnl.Controls.Add(btnSaveInterfaces);

            tab.Controls.Add(pnl);

            LoadInterfacesFromConfig();
        }

        private List<InterfaceBindingConfig> EnumerateLocalIpv4Interfaces()
        {
            var result = new List<InterfaceBindingConfig>();
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    IPInterfaceProperties props;
                    try
                    {
                        props = nic.GetIPProperties();
                    }
                    catch
                    {
                        continue;
                    }

                    foreach (var uni in props.UnicastAddresses)
                    {
                        if (uni.Address.AddressFamily != AddressFamily.InterNetwork)
                            continue;

                        string ip = uni.Address.ToString();
                        if (!System.Net.IPAddress.TryParse(ip, out _))
                            continue;

                        result.Add(new InterfaceBindingConfig
                        {
                            Address = ip,
                            Enabled = true,
                            Name = nic.Name
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                AppendLog($"[ERROR] Enumerate interfaces failed: {ex.Message}");
            }

            return result
                .GroupBy(i => i.Address, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First())
                .OrderBy(i => i.Address, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private void LoadInterfacesFromConfig()
        {
            if (dgvInterfaces == null)
                return;

            try
            {
                string configPath = Path.Combine(LOG_DIR, "config.json");
                ServiceConfig? config = null;
                if (File.Exists(configPath))
                {
                    var json = ConfigCrypto.ReadConfigText(configPath);
                    var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                    config = JsonSerializer.Deserialize<ServiceConfig>(json, options);
                }

                config ??= new ServiceConfig();
                config.Interfaces ??= new List<InterfaceBindingConfig>();

                var discovered = EnumerateLocalIpv4Interfaces();
                var byIp = discovered.ToDictionary(i => i.Address, StringComparer.OrdinalIgnoreCase);

                foreach (var cfg in config.Interfaces.Where(i => !string.IsNullOrWhiteSpace(i.Address)))
                {
                    if (byIp.TryGetValue(cfg.Address, out var existing))
                    {
                        existing.Enabled = cfg.Enabled;
                        if (string.IsNullOrWhiteSpace(existing.Name) && !string.IsNullOrWhiteSpace(cfg.Name))
                            existing.Name = cfg.Name;
                    }
                    else
                    {
                        discovered.Add(new InterfaceBindingConfig
                        {
                            Address = cfg.Address,
                            Enabled = cfg.Enabled,
                            Name = string.IsNullOrWhiteSpace(cfg.Name) ? "Configured (not present)" : cfg.Name
                        });
                    }
                }

                discovered = discovered
                    .OrderByDescending(i => i.Enabled)
                    .ThenBy(i => i.Address, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                dgvInterfaces.Rows.Clear();
                foreach (var item in discovered)
                    dgvInterfaces.Rows.Add(item.Enabled, item.Address, item.Name ?? string.Empty);
            }
            catch (Exception ex)
            {
                AppendLog($"[ERROR] Load interfaces failed: {ex.Message}");
            }
        }

        private void BtnSaveInterfaces_Click(object? sender, EventArgs e)
        {
            try
            {
                string configPath = Path.Combine(LOG_DIR, "config.json");
                ServiceConfig config;
                if (File.Exists(configPath))
                {
                    var currentJson = ConfigCrypto.ReadConfigText(configPath);
                    var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                    config = JsonSerializer.Deserialize<ServiceConfig>(currentJson, options) ?? new ServiceConfig();
                }
                else
                {
                    config = new ServiceConfig();
                }

                var list = new List<InterfaceBindingConfig>();
                foreach (DataGridViewRow row in dgvInterfaces.Rows)
                {
                    if (row.IsNewRow)
                        continue;

                    string address = row.Cells["Address"].Value?.ToString()?.Trim() ?? string.Empty;
                    if (!System.Net.IPAddress.TryParse(address, out _))
                        continue;

                    bool enabled = row.Cells["Enabled"].Value is bool b && b;
                    string name = row.Cells["Name"].Value?.ToString()?.Trim() ?? string.Empty;
                    list.Add(new InterfaceBindingConfig
                    {
                        Address = address,
                        Enabled = enabled,
                        Name = name
                    });
                }

                config.Interfaces = list
                    .GroupBy(i => i.Address, StringComparer.OrdinalIgnoreCase)
                    .Select(g => g.First())
                    .OrderBy(i => i.Address, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                var saveOptions = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                };

                ConfigCrypto.WriteConfigText(configPath, JsonSerializer.Serialize(config, saveOptions));

                AppendLog("[MONITOR] Interfaces settings saved");
                LoadConfiguration();
                MessageBox.Show(
                    Program.CurrentLanguage == "UA"
                        ? "Налаштування інтерфейсів збережено."
                        : "Interface settings saved.",
                    Program.CurrentLanguage == "UA" ? "Успіх" : "Success",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                AppendLog($"[ERROR] Save interfaces failed: {ex.Message}");
                MessageBox.Show($"Error saving interfaces: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void CreateAlertsTab(TabPage tab)
        {
            var pnl = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(245, 245, 245),
                Padding = new Padding(20, 20, 20, 50),
                AutoScroll = true
            };
            pnl.HorizontalScroll.Enabled = false;
            pnl.HorizontalScroll.Visible = false;

            int yPos = 10;

            // Section header
            lblAlertsHeader = new Label
            {
                Location = new Point(10, yPos),
                Size = new Size(900, 30),
                Text = Lang.Get("TELEGRAM_SECTION_HEADER"),
                Font = new Font("Segoe UI", 12, FontStyle.Bold),
                ForeColor = Color.FromArgb(0, 102, 204)
            };
            pnl.Controls.Add(lblAlertsHeader);
            yPos += 40;

            // Enable checkbox
            chkTelegramEnabled = new CheckBox
            {
                Location = new Point(10, yPos),
                Size = new Size(400, 25),
                Text = Lang.Get("TELEGRAM_ENABLE"),
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                ForeColor = Color.FromArgb(50, 50, 50)
            };
            chkTelegramEnabled.CheckedChanged += ChkTelegramEnabled_CheckedChanged;
            pnl.Controls.Add(chkTelegramEnabled);
            yPos += 35;

            // Bot Token label
            lblAlertsBotToken = new Label
            {
                Location = new Point(10, yPos),
                Size = new Size(150, 25),
                Text = Lang.Get("TELEGRAM_BOT_TOKEN"),
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            pnl.Controls.Add(lblAlertsBotToken);
            yPos += 25;

            // Bot Token textbox
            txtTelegramBotToken = new TextBox
            {
                Location = new Point(10, yPos),
                Size = new Size(850, 25),
                Font = new Font("Consolas", 9),
                PlaceholderText = Lang.Get("TELEGRAM_BOT_TOKEN_PLACEHOLDER")
            };
            pnl.Controls.Add(txtTelegramBotToken);
            yPos += 35;

            // Chat ID label
            lblAlertsChatId = new Label
            {
                Location = new Point(10, yPos),
                Size = new Size(150, 25),
                Text = Lang.Get("TELEGRAM_CHAT_ID"),
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            pnl.Controls.Add(lblAlertsChatId);
            yPos += 25;

            // Chat ID textbox
            txtTelegramChatId = new TextBox
            {
                Location = new Point(10, yPos),
                Size = new Size(300, 25),
                Font = new Font("Consolas", 9),
                PlaceholderText = Lang.Get("TELEGRAM_CHAT_ID_PLACEHOLDER")
            };
            pnl.Controls.Add(txtTelegramChatId);
            yPos += 40;

            // --- MESSAGE TEMPLATES SECTION ---
            lblAlertsTemplatesHeader = new Label
            {
                Location = new Point(10, yPos),
                Size = new Size(900, 30),
                Text = Lang.Get("TELEGRAM_MESSAGE_TEMPLATES"),
                Font = new Font("Segoe UI", 11, FontStyle.Bold),
                ForeColor = Color.FromArgb(0, 102, 204)
            };
            pnl.Controls.Add(lblAlertsTemplatesHeader);
            yPos += 35;

            // Placeholders info
            lblAlertsPlaceholders = new Label
            {
                Location = new Point(10, yPos),
                Size = new Size(900, 20),
                Text = Lang.Get("TELEGRAM_PLACEHOLDERS"),
                Font = new Font("Segoe UI", 8, FontStyle.Italic),
                ForeColor = Color.Gray
            };
            pnl.Controls.Add(lblAlertsPlaceholders);
            yPos += 30;

            // Get current config to determine how many levels exist
            ServiceConfig? config = null;
            try 
            {
                string configPath = Path.Combine(LOG_DIR, "config.json");
                if (File.Exists(configPath))
                {
                    var json = ConfigCrypto.ReadConfigText(configPath);
                    var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                    config = JsonSerializer.Deserialize<ServiceConfig>(json, options);
                }
            }
            catch { }
            int levelCount = config?.Levels?.Count ?? 3;
            
            // Create template editors for each level
            txtMessageTemplates.Clear();
            lblAlertsLevelCaptions.Clear();
            for (int i = 0; i < levelCount; i++)
            {
                string key = $"level{i + 1}";
                
                var lblLevel = new Label
                {
                    Location = new Point(10, yPos),
                    Size = new Size(900, 22),
                    Text = $"{Lang.Get("TELEGRAM_TEMPLATE_LEVEL")} {i + 1}:",
                    Font = new Font("Segoe UI", 9, FontStyle.Bold),
                    ForeColor = Color.FromArgb(70, 70, 70)
                };
                pnl.Controls.Add(lblLevel);
                lblAlertsLevelCaptions.Add(lblLevel);
                yPos += 25;

                var txtTemplate = new TextBox
                {
                    Location = new Point(10, yPos),
                    Size = new Size(900, 60),
                    Font = new Font("Consolas", 8),
                    Multiline = true,
                    ScrollBars = ScrollBars.Vertical
                };
                txtMessageTemplates[key] = txtTemplate;
                pnl.Controls.Add(txtTemplate);
                yPos += 70;
            }

            // Default template
            lblAlertsDefaultTemplate = new Label
            {
                Location = new Point(10, yPos),
                Size = new Size(900, 22),
                Text = Lang.Get("TELEGRAM_TEMPLATE_DEFAULT"),
                Font = new Font("Segoe UI", 9, FontStyle.Bold),
                ForeColor = Color.FromArgb(70, 70, 70)
            };
            pnl.Controls.Add(lblAlertsDefaultTemplate);
            yPos += 25;

            var txtDefaultTemplate = new TextBox
            {
                Location = new Point(10, yPos),
                Size = new Size(900, 60),
                Font = new Font("Consolas", 8),
                Multiline = true,
                ScrollBars = ScrollBars.Vertical
            };
            txtMessageTemplates["default"] = txtDefaultTemplate;
            pnl.Controls.Add(txtDefaultTemplate);
            yPos += 75;

            // Buttons panel
            var btnPanel = new FlowLayoutPanel
            {
                Location = new Point(10, yPos),
                Size = new Size(900, 40),
                FlowDirection = FlowDirection.LeftToRight
            };

            btnTestTelegram = new Button
            {
                Size = new Size(180, 35),
                Text = Lang.Get("TELEGRAM_TEST_BUTTON"),
                BackColor = Color.FromArgb(0, 120, 215),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9, FontStyle.Bold)
            };
            btnTestTelegram.FlatAppearance.BorderSize = 0;
            btnTestTelegram.Click += BtnTestTelegram_Click;
            btnPanel.Controls.Add(btnTestTelegram);

            btnSaveTelegram = new Button
            {
                Size = new Size(180, 35),
                Text = Lang.Get("TELEGRAM_SAVE_BUTTON"),
                BackColor = Color.FromArgb(76, 175, 80),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9, FontStyle.Bold),
                Margin = new Padding(10, 0, 0, 0)
            };
            btnSaveTelegram.FlatAppearance.BorderSize = 0;
            btnSaveTelegram.Click += BtnSaveTelegram_Click;
            btnPanel.Controls.Add(btnSaveTelegram);

            pnl.Controls.Add(btnPanel);
            yPos += 50;

            // Status label
            lblTelegramStatus = new Label
            {
                Location = new Point(10, yPos),
                Size = new Size(900, 25),
                Font = new Font("Segoe UI", 9, FontStyle.Italic),
                ForeColor = Color.Gray
            };
            pnl.Controls.Add(lblTelegramStatus);
            yPos += 40;

            // Help section
            lblAlertsHelpTitle = new Label
            {
                Location = new Point(10, yPos),
                Size = new Size(900, 25),
                Text = Lang.Get("TELEGRAM_HELP_TITLE"),
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                ForeColor = Color.FromArgb(100, 100, 100)
            };
            pnl.Controls.Add(lblAlertsHelpTitle);
            yPos += 30;

            lblAlertsHelpSteps.Clear();
            for (int i = 1; i <= 5; i++)
            {
                var step = new Label
                {
                    Location = new Point(20, yPos),
                    Size = new Size(880, 20),
                    Text = Lang.Get($"TELEGRAM_HELP_STEP{i}"),
                    Font = new Font("Segoe UI", 9),
                    ForeColor = Color.FromArgb(80, 80, 80)
                };
                pnl.Controls.Add(step);
                lblAlertsHelpSteps.Add(step);
                yPos += 25;
            }

            tab.Controls.Add(pnl);

            // Load initial Telegram config
            LoadTelegramConfig();
        }

        private void ChkTelegramEnabled_CheckedChanged(object sender, EventArgs e)
        {
            bool enabled = chkTelegramEnabled.Checked;
            txtTelegramBotToken.Enabled = enabled;
            txtTelegramChatId.Enabled = enabled;
            btnTestTelegram.Enabled = enabled;
            lblTelegramStatus.Text = enabled ? Lang.Get("TELEGRAM_STATUS_ENABLED") : Lang.Get("TELEGRAM_STATUS_DISABLED");
        }

        private async void BtnTestTelegram_Click(object sender, EventArgs e)
        {
            try
            {
                string botToken = txtTelegramBotToken.Text.Trim();
                string chatId = txtTelegramChatId.Text.Trim();

                if (string.IsNullOrWhiteSpace(botToken) || string.IsNullOrWhiteSpace(chatId))
                {
                    lblTelegramStatus.Text = "Please fill Bot Token and Chat ID";
                    lblTelegramStatus.ForeColor = Color.Red;
                    return;
                }

                string message = "✅ *RDP Security Service*\n\nTelegram notifications are working!\n\n_This is a test message._";

                using (var client = new System.Net.Http.HttpClient())
                {
                    client.Timeout = TimeSpan.FromSeconds(10);
                    var url = $"https://api.telegram.org/bot{botToken}/sendMessage";
                    var content = new System.Net.Http.FormUrlEncodedContent(new[]
                    {
                        new KeyValuePair<string, string>("chat_id", chatId),
                        new KeyValuePair<string, string>("text", message),
                        new KeyValuePair<string, string>("parse_mode", "Markdown")
                    });

                    var response = await client.PostAsync(url, content);
                    if (response.IsSuccessStatusCode)
                    {
                        if (chkTelegramEnabled.Checked)
                        {
                            lblTelegramStatus.Text = Lang.Get("TELEGRAM_TEST_SUCCESS");
                            lblTelegramStatus.ForeColor = Color.Green;
                        }
                        else
                        {
                            string warn = string.Equals(Program.CurrentLanguage, "UA", StringComparison.OrdinalIgnoreCase)
                                ? "Тест пройшов, але служба НЕ буде надсилати повідомлення, поки не увімкнете 'Enable Telegram Notifications' і не натиснете 'Save Settings'."
                                : "Test passed, but the service will NOT send notifications until you enable 'Enable Telegram Notifications' and click 'Save Settings'.";

                            lblTelegramStatus.Text = warn;
                            lblTelegramStatus.ForeColor = Color.DarkOrange;
                            MessageBox.Show(warn, "Telegram Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        }
                    }
                    else
                    {
                        lblTelegramStatus.Text = $"{Lang.Get("TELEGRAM_TEST_FAIL")} HTTP {response.StatusCode}";
                        lblTelegramStatus.ForeColor = Color.Red;
                    }
                }
            }
            catch (Exception ex)
            {
                lblTelegramStatus.Text = $"{Lang.Get("TELEGRAM_TEST_FAIL")} {ex.Message}";
                lblTelegramStatus.ForeColor = Color.Red;
            }
        }

        private void BtnSaveTelegram_Click(object sender, EventArgs e)
        {
            try
            {
                string configPath = Path.Combine(LOG_DIR, "config.json");
                if (!File.Exists(configPath))
                {
                    lblTelegramStatus.Text = Lang.Get("TELEGRAM_SAVE_FAIL");
                    lblTelegramStatus.ForeColor = Color.Red;
                    return;
                }

                var json = ConfigCrypto.ReadConfigText(configPath);
                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                var config = JsonSerializer.Deserialize<ServiceConfig>(json, options);
                
                if (config == null)
                {
                    lblTelegramStatus.Text = Lang.Get("TELEGRAM_SAVE_FAIL");
                    lblTelegramStatus.ForeColor = Color.Red;
                    return;
                }

                // Collect message templates
                var templates = new Dictionary<string, string>();
                foreach (var kvp in txtMessageTemplates)
                {
                    templates[kvp.Key] = kvp.Value.Text.Trim();
                }

                // Preserve fields with no GUI control yet (limitedPhones, selfUnbanIp,
                // hereProbe*) — rebuilding TelegramConfig below must not silently reset them.
                var existingTelegram = config.Telegram;
                config.Telegram = new TelegramConfig
                {
                    Enabled = chkTelegramEnabled.Checked,
                    BotToken = txtTelegramBotToken.Text.Trim(),
                    ChatId = txtTelegramChatId.Text.Trim(),
                    MessageTemplates = templates,
                    LimitedPhones = existingTelegram?.LimitedPhones ?? new List<string>(),
                    SelfUnbanIp = existingTelegram?.SelfUnbanIp ?? "",
                    HereProbeEnabled = existingTelegram?.HereProbeEnabled ?? false,
                    HereProbePublicUrl = existingTelegram?.HereProbePublicUrl ?? "",
                    HereProbeListenPrefix = existingTelegram?.HereProbeListenPrefix ?? ""
                };

                var saveOptions = new JsonSerializerOptions 
                { 
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                };
                var saveJson = JsonSerializer.Serialize(config, saveOptions);
                ConfigCrypto.WriteConfigText(configPath, saveJson);

                lblTelegramStatus.Text = Lang.Get("TELEGRAM_SAVE_SUCCESS");
                lblTelegramStatus.ForeColor = Color.Green;
                LoadConfiguration(); // Refresh display
            }
            catch (Exception ex)
            {
                lblTelegramStatus.Text = $"{Lang.Get("TELEGRAM_SAVE_FAIL")} {ex.Message}";
                lblTelegramStatus.ForeColor = Color.Red;
            }
        }

        private void LoadTelegramConfig()
        {
            try
            {
                ServiceConfig? config = null;
                string configPath = Path.Combine(LOG_DIR, "config.json");
                if (File.Exists(configPath))
                {
                    var json = ConfigCrypto.ReadConfigText(configPath);
                    var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                    config = JsonSerializer.Deserialize<ServiceConfig>(json, options);
                }
                
                if (config?.Telegram != null)
                {
                    chkTelegramEnabled.Checked = config.Telegram.Enabled;
                    txtTelegramBotToken.Text = config.Telegram.BotToken ?? "";
                    txtTelegramChatId.Text = config.Telegram.ChatId ?? "";

                    // Load message templates
                    if (config.Telegram.MessageTemplates != null)
                    {
                        foreach (var kvp in txtMessageTemplates)
                        {
                            if (config.Telegram.MessageTemplates.ContainsKey(kvp.Key))
                            {
                                kvp.Value.Text = config.Telegram.MessageTemplates[kvp.Key];
                            }
                            else
                            {
                                // Set default templates if not found
                                kvp.Value.Text = GetDefaultTemplate(kvp.Key);
                            }
                        }
                    }
                    else
                    {
                        // No templates in config, use defaults
                        foreach (var kvp in txtMessageTemplates)
                        {
                            kvp.Value.Text = GetDefaultTemplate(kvp.Key);
                        }
                    }
                }
                else
                {
                    chkTelegramEnabled.Checked = false;
                    txtTelegramBotToken.Text = "";
                    txtTelegramChatId.Text = "";
                    
                    // Load default templates
                    foreach (var kvp in txtMessageTemplates)
                    {
                        kvp.Value.Text = GetDefaultTemplate(kvp.Key);
                    }
                }
            }
            catch { }
        }

        private string GetDefaultTemplate(string key)
        {
            switch (key)
            {
                case "level1":
                    return "🟡 RDP ALERT - Рівень 1\n\nЗаблоковано IP: {ip}\nСпроб входу: {attempts}\nБлокування: {duration} хв";
                case "level2":
                    return "🟠 RDP ALERT - Рівень 2\n\nЗаблоковано IP: {ip}\nСпроб входу: {attempts}\nБлокування: {duration} хв";
                case "level3":
                    return "🔴 RDP ALERT - Рівень 3\n\nЗаблоковано IP: {ip}\nСпроб входу: {attempts}\nБлокування: {duration} хв";
                case "default":
                    return "🚨 RDP Security Alert\n\nЗаблоковано IP: {ip}\nСпроб атаки: {attempts}\nБлокування: {duration} хв";
                default:
                    return $"🔴 RDP Alert {key.ToUpper()}\n\nIP: {{ip}}\nСпроб: {{attempts}}\nБлокування: {{duration}} хв";
            }
        }

        private void SendSimpleTelegramMessage(string message)
        {
            try
            {
                string configPath = Path.Combine(LOG_DIR, "config.json");
                if (!File.Exists(configPath))
                {
                    WriteMonitorEventLog("[MONITOR_UI] Telegram notify skipped: config.json missing");
                    return;
                }

                var json = ConfigCrypto.ReadConfigText(configPath);
                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                var config = JsonSerializer.Deserialize<ServiceConfig>(json, options);

                var telegram = config?.Telegram;
                if (telegram == null || !telegram.Enabled || string.IsNullOrWhiteSpace(telegram.BotToken) || string.IsNullOrWhiteSpace(telegram.ChatId))
                {
                    WriteMonitorEventLog("[MONITOR_UI] Telegram notify skipped: telegram is disabled or credentials are empty");
                    return;
                }
                
                using (var client = new System.Net.Http.HttpClient())
                {
                    client.Timeout = TimeSpan.FromSeconds(10);
                    var url = $"https://api.telegram.org/bot{telegram.BotToken}/sendMessage";
                    var content = new System.Net.Http.FormUrlEncodedContent(new[]
                    {
                        new KeyValuePair<string, string>("chat_id", telegram.ChatId),
                        new KeyValuePair<string, string>("text", message)
                    });

                    var response = client.PostAsync(url, content).GetAwaiter().GetResult();
                    if (!response.IsSuccessStatusCode)
                    {
                        AppendLog($"[TELEGRAM] Startup notification failed: {response.StatusCode}");
                        WriteMonitorEventLog($"[MONITOR_UI] Telegram notify failed: {response.StatusCode}");
                    }
                    else
                    {
                        WriteMonitorEventLog("[MONITOR_UI] Telegram notify sent successfully");
                    }
                }
            }
            catch (Exception ex)
            {
                AppendLog($"[TELEGRAM] Startup notification error: {ex.Message}");
                WriteMonitorEventLog($"[MONITOR_UI] Telegram notify error: {ex.Message}");
            }
        }

        private void WriteMonitorEventLog(string message)
        {
            try
            {
                Directory.CreateDirectory(LOG_DIR);
                string line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}{Environment.NewLine}";
                File.AppendAllText(Path.Combine(LOG_DIR, "service.log"), line, Encoding.UTF8);
            }
            catch
            {
                // Avoid throwing from diagnostics path.
            }
        }

        private void CreateMessageSettingsTab(TabPage tab)
        {
            var pnl = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(245, 245, 245),
                Padding = new Padding(20, 20, 20, 50),
                AutoScroll = true
            };
            pnl.HorizontalScroll.Enabled = false;
            pnl.HorizontalScroll.Visible = false;

            int yPos = 10;

            // Section header
            lblMessageSettingsHeader = new Label
            {
                Location = new Point(10, yPos),
                Size = new Size(900, 30),
                Text = Lang.Get("MSG_SETTINGS_HEADER"),
                Font = new Font("Segoe UI", 12, FontStyle.Bold),
                ForeColor = Color.FromArgb(0, 102, 204)
            };
            pnl.Controls.Add(lblMessageSettingsHeader);
            yPos += 45;

            // Monitor section
            lblMessageSettingsMonitorSection = new Label
            {
                Location = new Point(10, yPos),
                Size = new Size(300, 25),
                Text = Lang.Get("MSG_SETTINGS_MONITOR"),
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                ForeColor = Color.FromArgb(50, 50, 50)
            };
            pnl.Controls.Add(lblMessageSettingsMonitorSection);
            yPos += 30;

            chkNotifyMonitorStart = new CheckBox
            {
                Location = new Point(30, yPos),
                Size = new Size(500, 25),
                Text = Lang.Get("MSG_SETTINGS_MONITOR_START"),
                Font = new Font("Segoe UI", 9),
                Checked = false
            };
            pnl.Controls.Add(chkNotifyMonitorStart);
            yPos += 30;

            chkNotifyMonitorClose = new CheckBox
            {
                Location = new Point(30, yPos),
                Size = new Size(500, 25),
                Text = Lang.Get("MSG_SETTINGS_MONITOR_CLOSE"),
                Font = new Font("Segoe UI", 9),
                Checked = false
            };
            pnl.Controls.Add(chkNotifyMonitorClose);
            yPos += 45;

            // Service section
            lblMessageSettingsServiceSection = new Label
            {
                Location = new Point(10, yPos),
                Size = new Size(300, 25),
                Text = Lang.Get("MSG_SETTINGS_SERVICE"),
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                ForeColor = Color.FromArgb(50, 50, 50)
            };
            pnl.Controls.Add(lblMessageSettingsServiceSection);
            yPos += 30;

            chkNotifyServiceStart = new CheckBox
            {
                Location = new Point(30, yPos),
                Size = new Size(500, 25),
                Text = Lang.Get("MSG_SETTINGS_SERVICE_START"),
                Font = new Font("Segoe UI", 9),
                Checked = true
            };
            pnl.Controls.Add(chkNotifyServiceStart);
            yPos += 30;

            chkNotifyServiceStop = new CheckBox
            {
                Location = new Point(30, yPos),
                Size = new Size(500, 25),
                Text = Lang.Get("MSG_SETTINGS_SERVICE_STOP"),
                Font = new Font("Segoe UI", 9),
                Checked = true
            };
            pnl.Controls.Add(chkNotifyServiceStop);
            yPos += 45;

            // Configuration section
            chkNotifyConfigSave = new CheckBox
            {
                Location = new Point(10, yPos),
                Size = new Size(500, 25),
                Text = Lang.Get("MSG_SETTINGS_CONFIG_SAVE"),
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                ForeColor = Color.FromArgb(50, 50, 50),
                Checked = false
            };
            pnl.Controls.Add(chkNotifyConfigSave);
            yPos += 50;

            // Save button
            btnSaveMessageSettings = new Button
            {
                Location = new Point(10, yPos),
                Size = new Size(200, 35),
                Text = Lang.Get("MSG_SETTINGS_SAVE_BTN"),
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                BackColor = Color.FromArgb(0, 120, 212),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand
            };
            btnSaveMessageSettings.FlatAppearance.BorderSize = 0;
            btnSaveMessageSettings.Click += BtnSaveMessageSettings_Click;
            pnl.Controls.Add(btnSaveMessageSettings);

            btnPrepareSupportReport = new Button
            {
                Location = new Point(230, yPos),
                Size = new Size(340, 35),
                Text = GetSupportReportButtonText(),
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                BackColor = Color.FromArgb(0, 153, 102),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand
            };
            btnPrepareSupportReport.FlatAppearance.BorderSize = 0;
            btnPrepareSupportReport.Click += BtnPrepareSupportReport_Click;
            pnl.Controls.Add(btnPrepareSupportReport);

            tab.Controls.Add(pnl);

            // Load initial settings
            LoadMessageNotificationSettings();
        }

        private void BtnSaveMessageSettings_Click(object sender, EventArgs e)
        {
            try
            {
                var settings = new MessageNotificationSettings
                {
                    MonitorStart = chkNotifyMonitorStart.Checked,
                    MonitorClose = chkNotifyMonitorClose.Checked,
                    ServiceStart = chkNotifyServiceStart.Checked,
                    ServiceStop = chkNotifyServiceStop.Checked,
                    ConfigSave = chkNotifyConfigSave.Checked
                };

                string settingsPath = Path.Combine(LOG_DIR, "monitor-notifications.json");
                var options = new JsonSerializerOptions { WriteIndented = true };
                var json = JsonSerializer.Serialize(settings, options);
                File.WriteAllText(settingsPath, json, Encoding.UTF8);

                bool isUa = string.Equals(Program.CurrentLanguage, "UA", StringComparison.OrdinalIgnoreCase);
                string message = isUa ? "Налаштування збережено!" : "Settings saved!";
                MessageBox.Show(message, "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                AppendLog("[MONITOR] Message notification settings saved");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                AppendLog($"[ERROR] Failed to save message notification settings: {ex.Message}");
            }
        }

        private string GetSupportReportButtonText()
        {
            bool isUa = string.Equals(Program.CurrentLanguage, "UA", StringComparison.OrdinalIgnoreCase);
            return isUa ? "Підготувати звіт для issue" : "Prepare support report";
        }

        private void BtnPrepareSupportReport_Click(object sender, EventArgs e)
        {
            try
            {
                string reportId;
                string mailSubject;
                string mailBody;
                string zipPath = BuildSupportReportPackage(out reportId, out mailSubject, out mailBody);

                try { Clipboard.SetText(mailBody); } catch { }
                TryOpenSupportContactPage();
                TryRevealFileInExplorer(zipPath);

                bool isUa = string.Equals(Program.CurrentLanguage, "UA", StringComparison.OrdinalIgnoreCase);
                string text = isUa
                    ? $"Звіт сформовано: {zipPath}\n\nВідкрито сторінку issues: {SUPPORT_CONTACT_URL}\nТекст опису скопійовано в буфер.\n\nБудь ласка, додайте ZIP у вкладення до issue."
                    : $"Report created: {zipPath}\n\nOpened issues page: {SUPPORT_CONTACT_URL}\nDescription text copied to clipboard.\n\nPlease attach the ZIP file to the issue.";
                MessageBox.Show(text, isUa ? "Готово" : "Done", MessageBoxButtons.OK, MessageBoxIcon.Information);

                AppendLog($"[MONITOR] Support report prepared: id={reportId}, zip={zipPath}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                AppendLog($"[ERROR] Support report generation failed: {ex.Message}");
            }
        }

        private string BuildSupportReportPackage(out string reportId, out string mailSubject, out string mailBody)
        {
            string reportsRoot = Path.Combine(LOG_DIR, "support-reports");
            Directory.CreateDirectory(reportsRoot);

            reportId = $"{DateTime.Now:yyyyMMdd-HHmmss}-{Environment.MachineName}";
            string reportDir = Path.Combine(reportsRoot, $"report-{reportId}");
            Directory.CreateDirectory(reportDir);

            var report = CollectSupportStats(reportId);
            var jsonOptions = new JsonSerializerOptions { WriteIndented = true };

            string jsonPath = Path.Combine(reportDir, "support-report.json");
            File.WriteAllText(jsonPath, JsonSerializer.Serialize(report, jsonOptions), Encoding.UTF8);

            string txtPath = Path.Combine(reportDir, "support-report.txt");
            File.WriteAllText(txtPath, BuildSupportReportText(report), Encoding.UTF8);

            TryCopyIfExists(Path.Combine(LOG_DIR, "config.json"), reportDir);
            TryCopyIfExists(Path.Combine(LOG_DIR, "service.log"), reportDir);
            TryCopyIfExists(Path.Combine(LOG_DIR, "access.log"), reportDir);
            TryCopyIfExists(Path.Combine(LOG_DIR, "block_list.log"), reportDir);
            TryCopyIfExists(Path.Combine(LOG_DIR, "whiteList.log"), reportDir);
            TryCopyIfExists(Path.Combine(LOG_DIR, "monitor-notifications.json"), reportDir);

            string zipPath = Path.Combine(reportsRoot, $"rdp-security-stats-{reportId}.zip");
            if (File.Exists(zipPath))
                File.Delete(zipPath);

            ZipFile.CreateFromDirectory(reportDir, zipPath, CompressionLevel.Optimal, includeBaseDirectory: false);

            mailSubject = $"RDP Security Stats [{Environment.MachineName}] {DateTime.Now:yyyy-MM-dd HH:mm}";
            mailBody =
                $"Hello,\n\n" +
                $"Please find attached diagnostics ZIP generated by Monitor.\n" +
                $"Report ID: {reportId}\n\n" +
                $"How to read:\n" +
                $"- support-report.txt: human summary\n" +
                $"- support-report.json: machine-readable fields for quick parsing\n\n" +
                $"ZIP path on sender host: {zipPath}\n\n" +
                $"Regards.";

            string draftPath = Path.Combine(reportDir, "issue-draft.txt");
            File.WriteAllText(draftPath, $"Issue: {SUPPORT_CONTACT_URL}\nSubject: {mailSubject}\n\n{mailBody}", Encoding.UTF8);

            return zipPath;
        }

        private SupportStatsReport CollectSupportStats(string reportId)
        {
            string accessPath = Path.Combine(LOG_DIR, "access.log");
            string blockPath = Path.Combine(LOG_DIR, "block_list.log");
            string whitePath = Path.Combine(LOG_DIR, "whiteList.log");
            string configPath = Path.Combine(LOG_DIR, "config.json");

            int accessTotal = 0;
            int accessLast24h = 0;
            if (File.Exists(accessPath))
            {
                foreach (string raw in File.ReadLines(accessPath, Encoding.UTF8))
                {
                    if (string.IsNullOrWhiteSpace(raw))
                        continue;

                    accessTotal++;
                    if (TryParseBracketTimestamp(raw, out DateTime ts) && ts >= DateTime.Now.AddHours(-24))
                        accessLast24h++;
                }
            }

            var activeTargets = ReadBlockedTargetsFromBlockListLog().ToList();
            int activeDirectIps = activeTargets.Count(x => !x.Contains("/", StringComparison.Ordinal));
            int activeSubnets = activeTargets.Count(x => x.Contains("/", StringComparison.Ordinal));
            int firewallTargetCount = ReadBlockedTargetsFromFirewallRule().Count();

            int whitelistCount = 0;
            if (File.Exists(whitePath))
            {
                foreach (string line in File.ReadLines(whitePath, Encoding.UTF8))
                {
                    string value = line.Trim();
                    if (!string.IsNullOrWhiteSpace(value) && !value.StartsWith("#", StringComparison.Ordinal))
                        whitelistCount++;
                }
            }

            var topTargets = BuildTopBlockedTargets(blockPath, 10);

            string serviceState = "Unknown";
            try
            {
                using var sc = new ServiceController(SERVICE_NAME);
                serviceState = sc.Status.ToString();
            }
            catch (Exception ex)
            {
                serviceState = $"Error: {ex.Message}";
            }

            string appVersion = FileVersionInfo.GetVersionInfo(Application.ExecutablePath).FileVersion ?? "unknown";

            return new SupportStatsReport
            {
                ReportId = reportId,
                GeneratedLocal = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                MachineName = Environment.MachineName,
                UserName = Environment.UserName,
                OsVersion = Environment.OSVersion.ToString(),
                MonitorVersion = appVersion,
                ServiceStatus = serviceState,
                AccessAttemptsTotal = accessTotal,
                AccessAttemptsLast24h = accessLast24h,
                ActiveBlockedTargets = activeTargets.Count,
                ActiveBlockedDirectIps = activeDirectIps,
                ActiveBlockedSubnets = activeSubnets,
                FirewallRemoteTargetCount = firewallTargetCount,
                WhitelistEntries = whitelistCount,
                TopBlockedTargets = topTargets,
                Notes = "Attach this report ZIP to email for support investigation."
            };
        }

        private static List<SupportTopBlockedTarget> BuildTopBlockedTargets(string blockPath, int top)
        {
            var stats = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            if (!File.Exists(blockPath))
                return new List<SupportTopBlockedTarget>();

            foreach (string raw in File.ReadLines(blockPath, Encoding.UTF8))
            {
                string target = ExtractBlockedTarget(raw);
                if (string.IsNullOrWhiteSpace(target))
                    continue;

                if (!stats.ContainsKey(target))
                    stats[target] = 0;
                stats[target]++;
            }

            return stats
                .OrderByDescending(k => k.Value)
                .ThenBy(k => k.Key, StringComparer.OrdinalIgnoreCase)
                .Take(Math.Max(1, top))
                .Select(k => new SupportTopBlockedTarget { Target = k.Key, Hits = k.Value })
                .ToList();
        }

        private static bool TryParseBracketTimestamp(string line, out DateTime timestamp)
        {
            timestamp = default;
            if (string.IsNullOrWhiteSpace(line) || line.Length < 21 || line[0] != '[')
                return false;

            int end = line.IndexOf(']');
            if (end <= 1)
                return false;

            string rawTs = line.Substring(1, end - 1).Trim();
            return DateTime.TryParseExact(
                rawTs,
                "yyyy-MM-dd HH:mm:ss",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeLocal,
                out timestamp);
        }

        private static void TryCopyIfExists(string sourcePath, string destinationDirectory)
        {
            if (!File.Exists(sourcePath))
                return;

            string destinationPath = Path.Combine(destinationDirectory, Path.GetFileName(sourcePath));
            File.Copy(sourcePath, destinationPath, overwrite: true);
        }

        private static void TryRevealFileInExplorer(string filePath)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"/select,\"{filePath}\"",
                    UseShellExecute = true
                });
            }
            catch { }
        }

        private static void TryOpenSupportContactPage()
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = SUPPORT_CONTACT_URL,
                    UseShellExecute = true
                });
            }
            catch { }
        }

        private static string BuildSupportReportText(SupportStatsReport report)
        {
            var sb = new StringBuilder();
            sb.AppendLine("RDP Security Monitor Support Report");
            sb.AppendLine($"Report ID: {report.ReportId}");
            sb.AppendLine($"Generated: {report.GeneratedLocal}");
            sb.AppendLine($"Machine: {report.MachineName}");
            sb.AppendLine($"User: {report.UserName}");
            sb.AppendLine($"OS: {report.OsVersion}");
            sb.AppendLine($"Monitor version: {report.MonitorVersion}");
            sb.AppendLine($"Service status: {report.ServiceStatus}");
            sb.AppendLine();
            sb.AppendLine("Statistics:");
            sb.AppendLine($"- Access attempts total: {report.AccessAttemptsTotal}");
            sb.AppendLine($"- Access attempts last 24h: {report.AccessAttemptsLast24h}");
            sb.AppendLine($"- Active blocked targets: {report.ActiveBlockedTargets}");
            sb.AppendLine($"- Active blocked direct IPs: {report.ActiveBlockedDirectIps}");
            sb.AppendLine($"- Active blocked subnets: {report.ActiveBlockedSubnets}");
            sb.AppendLine($"- Firewall remote target count: {report.FirewallRemoteTargetCount}");
            sb.AppendLine($"- Whitelist entries: {report.WhitelistEntries}");
            sb.AppendLine();
            sb.AppendLine("Top blocked targets:");
            foreach (var item in report.TopBlockedTargets)
                sb.AppendLine($"- {item.Target}: {item.Hits}");

            sb.AppendLine();
            sb.AppendLine("How to read:");
            sb.AppendLine("- support-report.txt: quick human summary");
            sb.AppendLine("- support-report.json: machine-readable structured stats");
            sb.AppendLine("- service.log/access.log/block_list.log: source evidence");
            return sb.ToString();
        }

        private void LoadMessageNotificationSettings()
        {
            try
            {
                string settingsPath = Path.Combine(LOG_DIR, "monitor-notifications.json");
                if (File.Exists(settingsPath))
                {
                    var json = File.ReadAllText(settingsPath, Encoding.UTF8);
                    var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                    var settings = JsonSerializer.Deserialize<MessageNotificationSettings>(json, options);

                    if (settings != null)
                    {
                        chkNotifyMonitorStart.Checked = settings.MonitorStart;
                        chkNotifyMonitorClose.Checked = settings.MonitorClose;
                        chkNotifyServiceStart.Checked = settings.ServiceStart;
                        chkNotifyServiceStop.Checked = settings.ServiceStop;
                        chkNotifyConfigSave.Checked = settings.ConfigSave;
                    }
                }
            }
            catch (Exception ex)
            {
                AppendLog($"[WARN] Failed to load message notification settings: {ex.Message}");
            }
        }

        private MessageNotificationSettings? GetCurrentNotificationSettingsSnapshot()
        {
            try
            {
                if (IsHandleCreated && InvokeRequired)
                    return (MessageNotificationSettings?)Invoke(new Func<MessageNotificationSettings?>(GetCurrentNotificationSettingsSnapshot));

                if (chkNotifyMonitorStart == null ||
                    chkNotifyMonitorClose == null ||
                    chkNotifyServiceStart == null ||
                    chkNotifyServiceStop == null ||
                    chkNotifyConfigSave == null)
                {
                    return null;
                }

                return new MessageNotificationSettings
                {
                    MonitorStart = chkNotifyMonitorStart.Checked,
                    MonitorClose = chkNotifyMonitorClose.Checked,
                    ServiceStart = chkNotifyServiceStart.Checked,
                    ServiceStop = chkNotifyServiceStop.Checked,
                    ConfigSave = chkNotifyConfigSave.Checked
                };
            }
            catch
            {
                return null;
            }
        }

        private bool ShouldNotify(string eventType)
        {
            try
            {
                var currentSettings = GetCurrentNotificationSettingsSnapshot();
                if (currentSettings != null)
                {
                    return eventType switch
                    {
                        "MonitorStart" => currentSettings.MonitorStart,
                        "MonitorClose" => currentSettings.MonitorClose,
                        "ServiceStart" => currentSettings.ServiceStart,
                        "ServiceStop" => currentSettings.ServiceStop,
                        "ConfigSave" => currentSettings.ConfigSave,
                        _ => false
                    };
                }

                string settingsPath = Path.Combine(LOG_DIR, "monitor-notifications.json");
                if (!File.Exists(settingsPath))
                    return false; // Default: don't send

                var json = File.ReadAllText(settingsPath, Encoding.UTF8);
                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                var settings = JsonSerializer.Deserialize<MessageNotificationSettings>(json, options);

                if (settings == null)
                    return false;

                return eventType switch
                {
                    "MonitorStart" => settings.MonitorStart,
                    "MonitorClose" => settings.MonitorClose,
                    "ServiceStart" => settings.ServiceStart,
                    "ServiceStop" => settings.ServiceStop,
                    "ConfigSave" => settings.ConfigSave,
                    _ => false
                };
            }
            catch
            {
                return false;
            }
        }

        private void SetupFileWatcher()
        {
            try
            {
                if (!Directory.Exists(LOG_DIR)) return;
                fileWatcher = new FileSystemWatcher(LOG_DIR)
                {
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size,
                    Filter = "*.log"
                };
                fileWatcher.Changed += (s, e) => this.BeginInvoke(new Action(() => OnLogFileChanged(e.FullPath)));
                fileWatcher.EnableRaisingEvents = true;
            }
            catch { }
        }

        private void OnLogFileChanged(string filePath)
        {
            try
            {
                string fileName = Path.GetFileName(filePath).ToLower();
                if (fileName == "access.log")
                    ReadLogTail(filePath, ref lastAccessLogPosition, "[ACCESS]");
                else if (fileName == "block_list.log")
                {
                    ReadLogTail(filePath, ref lastBlockLogPosition, "[BLOCK]");
                    LoadBannedIPs();
                }
                else if (fileName == "service.log")
                    ReadLogTail(filePath, ref lastServiceLogPosition, "[SERVICE]");
            }
            catch { }
        }

        private void ReadLogTail(string filePath, ref long lastPosition, string prefix)
        {
            try
            {
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    if (lastPosition > fs.Length) lastPosition = 0;
                    fs.Seek(lastPosition, SeekOrigin.Begin);
                    using (var sr = new StreamReader(fs, Encoding.UTF8))
                    {
                        string line;
                        while ((line = sr.ReadLine()) != null)
                        {
                            if (!string.IsNullOrWhiteSpace(line))
                                AppendLog($"{prefix} {line}");
                        }
                    }
                    lastPosition = fs.Position;
                }
            }
            catch { }
        }

        private void LoadInitialData()
        {
            UpdateServiceStatus();
            LoadConfiguration();
            LoadBannedIPs();
            LoadWhiteList();
            LoadRecentLogs();
        }

        private void UpdateServiceStatus()
        {
            try
            {
                var service = ServiceController.GetServices().FirstOrDefault(s => s.ServiceName == SERVICE_NAME);
                if (service == null)
                {
                    if (IsLocalEngineRunning())
                    {
                        lblServiceStatus.Text = "Local mode: RUNNING (service not installed)";
                        lblServiceStatus.ForeColor = Color.FromArgb(255, 152, 0);
                        btnStartService.Enabled = false;
                        btnStopService.Enabled = true;
                    }
                    else
                    {
                        lblServiceStatus.Text = "⚠ Service NOT INSTALLED";
                        lblServiceStatus.ForeColor = Color.FromArgb(244, 67, 54);
                        btnStartService.Enabled = true;
                        btnStopService.Enabled = false;
                    }
                    return;
                }

                service.Refresh();
                lblServiceStatus.Text = $"Status: {service.Status} | Startup: {service.StartType}";
                lblServiceStatus.ForeColor = service.Status == ServiceControllerStatus.Running
                    ? Color.FromArgb(76, 175, 80)
                    : Color.FromArgb(244, 67, 54);
                btnStartService.Enabled = service.Status != ServiceControllerStatus.Running;
                btnStopService.Enabled = service.Status == ServiceControllerStatus.Running;
            }
            catch (Exception ex)
            {
                lblServiceStatus.Text = $"Error: {ex.Message}";
                lblServiceStatus.ForeColor = Color.FromArgb(244, 67, 54);
            }
        }

        private bool IsLocalEngineRunning()
        {
            try
            {
                return Process.GetProcessesByName("WinService").Any();
            }
            catch
            {
                return false;
            }
        }

        private bool TryStartLocalEngine()
        {
            try
            {
                var localServiceExe = ResolveLocalServiceExePath();
                if (string.IsNullOrWhiteSpace(localServiceExe))
                {
                    AppendLog("[ERROR] Local engine not found near monitor executable");
                    return false;
                }

                Process.Start(new ProcessStartInfo
                {
                    FileName = localServiceExe,
                    Arguments = "run",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                });

                AppendLog("[MONITOR] Local engine started (WinService.exe run)");
                return true;
            }
            catch (Exception ex)
            {
                AppendLog($"[ERROR] Failed to start local engine: {ex.Message}");
                return false;
            }
        }

        private string? ResolveLocalServiceExePath()
        {
            try
            {
                var candidates = new[]
                {
                    Path.Combine(AppContext.BaseDirectory, "WinService.exe"),
                    Path.Combine(Application.StartupPath, "WinService.exe"),
                    Path.Combine(Directory.GetCurrentDirectory(), "WinService.exe")
                };

                foreach (var candidate in candidates)
                {
                    if (File.Exists(candidate))
                        return candidate;
                }

                return null;
            }
            catch
            {
                return null;
            }
        }

        private bool TryStopLocalEngine()
        {
            try
            {
                var processes = Process.GetProcessesByName("WinService");
                foreach (var process in processes)
                {
                    process.Kill();
                }

                if (processes.Length > 0)
                    AppendLog($"[MONITOR] Local engine stopped ({processes.Length} proc)");

                return true;
            }
            catch (Exception ex)
            {
                AppendLog($"[ERROR] Failed to stop local engine: {ex.Message}");
                return false;
            }
        }

        private bool IsServiceAccessDenied(Exception exception)
        {
            if (exception is UnauthorizedAccessException)
                return true;

            var details = exception.ToString();
            return details.IndexOf("Access is denied", StringComparison.OrdinalIgnoreCase) >= 0
                || details.IndexOf("Отказано в доступе", StringComparison.OrdinalIgnoreCase) >= 0
                || details.IndexOf("Cannot open", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private bool TryStopServiceElevated()
        {
            try
            {
                var arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"Stop-Service -Name '{SERVICE_NAME}' -Force -ErrorAction Stop\"";
                var processInfo = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = arguments,
                    UseShellExecute = true,
                    Verb = "runas",
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                using var process = Process.Start(processInfo);
                if (process == null)
                    return false;

                process.WaitForExit(15000);

                if (process.ExitCode == 0)
                {
                    AppendLog("[MONITOR] Service stopped with administrator rights");
                    return true;
                }

                AppendLog($"[ERROR] Elevated stop failed with exit code: {process.ExitCode}");
                return false;
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
            {
                AppendLog("[MONITOR] Stop service with administrator rights was canceled");
                return false;
            }
            catch (Exception ex)
            {
                AppendLog($"[ERROR] Elevated stop failed: {ex.Message}");
                return false;
            }
        }

        private bool TryStartServiceElevated()
        {
            try
            {
                var arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"Start-Service -Name '{SERVICE_NAME}' -ErrorAction Stop\"";
                var processInfo = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = arguments,
                    UseShellExecute = true,
                    Verb = "runas",
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                using var process = Process.Start(processInfo);
                if (process == null)
                    return false;

                process.WaitForExit(15000);

                if (process.ExitCode == 0)
                {
                    AppendLog("[MONITOR] Service started with administrator rights");
                    return true;
                }

                AppendLog($"[ERROR] Elevated start failed with exit code: {process.ExitCode}");
                return false;
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
            {
                AppendLog("[MONITOR] Start service with administrator rights was canceled");
                return false;
            }
            catch (Exception ex)
            {
                AppendLog($"[ERROR] Elevated start failed: {ex.Message}");
                return false;
            }
        }

        private void LoadConfiguration()
        {
            try
            {
                string configPath = Path.Combine(LOG_DIR, "config.json");
                if (!File.Exists(configPath))
                {
                    lblConfig.Text = "Config not found";
                    return;
                }
                
                var json = ConfigCrypto.ReadConfigText(configPath);
                var config = JsonSerializer.Deserialize<ServiceConfig>(json);
                
                if (config != null)
                {
                    string desiredLanguage = string.Equals(config.UiLanguage, "EN", StringComparison.OrdinalIgnoreCase)
                        ? "EN"
                        : "UA";
                    if (!string.Equals(Program.CurrentLanguage, desiredLanguage, StringComparison.OrdinalIgnoreCase))
                    {
                        Program.CurrentLanguage = desiredLanguage;
                        SyncLanguageMenuChecks();
                        RefreshAllUITexts();
                    }

                    var levelsText = new System.Text.StringBuilder();
                    var cfgPorts = (config.Ports ?? new List<int>()).Where(p => p > 0).Distinct().OrderBy(p => p).ToList();
                    if (cfgPorts.Count == 0 && config.Port > 0)
                        cfgPorts.Add(config.Port);
                    levelsText.AppendLine($"RDP Ports: {(cfgPorts.Count == 0 ? "3389" : string.Join(",", cfgPorts))}");
                    levelsText.AppendLine($"Refresh: 1 sec (anti-DDoS)");
                    levelsText.AppendLine($"Listen IF: {GetInterfacesShortSummary(config)}");
                    levelsText.AppendLine("Block Levels:");
                    
                    foreach (var level in config.Levels)
                    {
                        levelsText.AppendLine($"  • {level.Attempts} attempts → {level.BlockMinutes} minutes");
                    }
                    
                    lblConfig.Text = levelsText.ToString().TrimEnd();
                }
                else
                {
                    lblConfig.Text = "Config parse error";
                }
            }
            catch (Exception ex)
            {
                lblConfig.Text = $"Error loading config: {ex.Message}";
            }
        }

        private string GetInterfacesShortSummary(ServiceConfig config)
        {
            var enabled = (config.Interfaces ?? new List<InterfaceBindingConfig>())
                .Where(i => i.Enabled && !string.IsNullOrWhiteSpace(i.Address))
                .Select(i => i.Address.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (enabled.Count == 0)
                return "ALL";

            const int maxShown = 3;
            if (enabled.Count <= maxShown)
                return string.Join(", ", enabled);

            return $"{string.Join(", ", enabled.Take(maxShown))} (+{enabled.Count - maxShown})";
        }

        private void LoadBannedIPs()
        {
            try
            {
                var savedIP = txtIPToUnblock.Text; // Preserve user input
                lstBannedIPs.Items.Clear();
                var displayItems = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                bool firewallReadFailed = false;
                string firewallReadError = null;

                foreach (var target in ReadBlockedTargetsFromFirewallRule())
                    displayItems.Add(target);

                if (displayItems.Count == 0)
                    firewallReadFailed = !TryReadBlockedTargetsViaNetsh(displayItems, out firewallReadError);

                bool firewallRuleMissing = IsMissingFirewallRuleMessage(firewallReadError);

                // Fallback/merge: if monitor can't read firewall rule (UAC/permissions/policy),
                // show what service considers blocked from block_list.log.
                foreach (var t in ReadBlockedTargetsFromBlockListLog())
                    displayItems.Add(t);

                if (firewallReadFailed && firewallRuleMissing && displayItems.Count == 0)
                {
                    AppendLog("[INFO] RDP_BLOCK_* firewall rules do not exist yet.");
                    lstBannedIPs.Items.Clear();
                }
                else if (firewallReadFailed && firewallRuleMissing && displayItems.Count > 0)
                {
                    AppendLog("[INFO] RDP_BLOCK_* firewall rules do not exist; showing data from block_list.log.");
                }
                else if (firewallReadFailed && displayItems.Count > 0)
                {
                    AppendLog($"[WARN] Can't read RDP_BLOCK_* firewall rules directly; showing merged data from block_list.log. Details: {firewallReadError}");
                }

                foreach (var item in displayItems.OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
                    lstBannedIPs.Items.Add(item);

                if (lstBannedIPs.Items.Count == 0)
                    lstBannedIPs.Items.Add(Lang.Get("MSG_NO_BLOCKED_IPS"));

                txtIPToUnblock.Text = savedIP; // Restore user input
            }
            catch (Exception ex)
            {
                AppendLog($"[ERROR] LoadBannedIPs: {ex.Message}");
            }
        }

        private IEnumerable<string> ReadBlockedTargetsFromFirewallRule()
        {
            var targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            try
            {
                string namesLiteral = string.Join(",", FirewallBuckets.AllRuleNames().Select(n => $"'{n}'"));
                using (var ps = PowerShell.Create())
                {
                    ps.AddScript($@"
                        $names = @({namesLiteral})
                        Get-NetFirewallRule -Name $names -ErrorAction SilentlyContinue |
                            Get-NetFirewallAddressFilter |
                            Select-Object -ExpandProperty RemoteAddress
                    ");

                    var results = ps.Invoke();
                    foreach (var result in results)
                    {
                        if (result?.BaseObject == null)
                            continue;

                        if (result.BaseObject is Array array)
                        {
                            foreach (var item in array)
                                AddBlockedTarget(targets, item?.ToString());
                        }
                        else
                        {
                            AddBlockedTarget(targets, result.BaseObject.ToString());
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                AppendLog($"[WARN] Failed to read RDP_BLOCK_* firewall rules via PowerShell: {ex.Message}");
            }

            return targets;
        }

        private bool TryReadBlockedTargetsViaNetsh(HashSet<string> targets, out string errorDetails)
        {
            errorDetails = null;
            bool anyRuleFound = false;
            var errors = new List<string>();

            foreach (string ruleName in FirewallBuckets.AllRuleNames())
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = $"advfirewall firewall show rule name=\"{ruleName}\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    };

                    using (var process = Process.Start(psi))
                    {
                        if (process == null)
                        {
                            errors.Add($"{ruleName}: failed to start netsh");
                            continue;
                        }

                        string output = process.StandardOutput.ReadToEnd();
                        string error = process.StandardError.ReadToEnd();
                        process.WaitForExit(3000);

                        if (process.ExitCode != 0)
                        {
                            errors.Add(string.IsNullOrWhiteSpace(error) ? output : error);
                            continue;
                        }

                        anyRuleFound = true;
                        foreach (Match ipMatch in Regex.Matches(output, @"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"))
                            AddBlockedTarget(targets, ipMatch.Groups[1].Value);
                    }
                }
                catch (Exception ex)
                {
                    errors.Add($"{ruleName}: {ex.Message}");
                }
            }

            if (!anyRuleFound)
            {
                errorDetails = errors.Count > 0 ? string.Join(" | ", errors) : "No RDP_BLOCK_* rules found";
                return false;
            }

            return true;
        }

        private static bool IsMissingFirewallRuleMessage(string? details)
        {
            if (string.IsNullOrWhiteSpace(details))
                return false;

            string normalized = details.Trim();
            return normalized.IndexOf("No rules match", StringComparison.OrdinalIgnoreCase) >= 0
                || normalized.IndexOf("No rules match the specified criteria", StringComparison.OrdinalIgnoreCase) >= 0
                || normalized.IndexOf("Ни одно правило не соответствует указанным критериям", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static void AddBlockedTarget(HashSet<string> targets, string rawValue)
        {
            if (string.IsNullOrWhiteSpace(rawValue))
                return;

            foreach (var part in rawValue.Split(','))
            {
                var value = part.Trim();
                if (string.IsNullOrWhiteSpace(value)
                    || string.Equals(value, "Any", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(value, "255.255.255.255", StringComparison.OrdinalIgnoreCase))
                    continue;

                targets.Add(value);
            }
        }

        private static bool IsBlockedTargetLogEntryFor(string line, string target)
        {
            if (string.IsNullOrWhiteSpace(line) || string.IsNullOrWhiteSpace(target))
                return false;

            string trimmed = line.Trim();
            string expectedTarget = target.Trim();

            int ipIdx = trimmed.IndexOf("BLOCKED IP:", StringComparison.OrdinalIgnoreCase);
            if (ipIdx >= 0)
            {
                string value = trimmed.Substring(ipIdx + 11).Split('|')[0].Trim();
                return string.Equals(value, expectedTarget, StringComparison.OrdinalIgnoreCase);
            }

            int netIdx = trimmed.IndexOf("BLOCKED NET:", StringComparison.OrdinalIgnoreCase);
            if (netIdx >= 0)
            {
                string value = trimmed.Substring(netIdx + 12).Split('|')[0].Trim();
                return string.Equals(value, expectedTarget, StringComparison.OrdinalIgnoreCase);
            }

            return false;
        }

        private IEnumerable<string> ReadBlockedTargetsFromBlockListLog()
        {
            var targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                string blockLogPath = Path.Combine(LOG_DIR, "block_list.log");
                if (!File.Exists(blockLogPath))
                    return targets;

                DateTime nowLocal = DateTime.Now;
                foreach (var raw in File.ReadAllLines(blockLogPath, Encoding.UTF8))
                {
                    if (string.IsNullOrWhiteSpace(raw))
                        continue;

                    string line = raw.Trim();
                    if (TryParseUntilFromBlockLogLine(line, out DateTime untilLocal) && nowLocal > untilLocal)
                        continue;

                    int ipIdx = line.IndexOf("BLOCKED IP:", StringComparison.OrdinalIgnoreCase);
                    if (ipIdx >= 0)
                    {
                        string ip = line.Substring(ipIdx + 11).Split('|')[0].Trim();
                        if (System.Net.IPAddress.TryParse(ip, out _))
                            targets.Add(ip);
                        continue;
                    }

                    int netIdx = line.IndexOf("BLOCKED NET:", StringComparison.OrdinalIgnoreCase);
                    if (netIdx >= 0)
                    {
                        string subnet = line.Substring(netIdx + 12).Split('|')[0].Trim();
                        if (!string.IsNullOrWhiteSpace(subnet))
                            targets.Add(subnet);
                        continue;
                    }
                }
            }
            catch (Exception ex)
            {
                AppendLog($"[WARN] Failed to read block_list.log: {ex.Message}");
            }

            return targets;
        }

        private static bool TryParseUntilFromBlockLogLine(string line, out DateTime untilLocal)
        {
            untilLocal = default;
            if (string.IsNullOrWhiteSpace(line))
                return false;

            int idx = line.IndexOf("Until:", StringComparison.OrdinalIgnoreCase);
            if (idx < 0)
                return false;

            string tail = line.Substring(idx + 6).Trim();
            if (tail.Contains("|"))
                tail = tail.Split('|')[0].Trim();

            return DateTime.TryParseExact(
                tail,
                "yyyy-MM-dd HH:mm:ss",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeLocal,
                out untilLocal);
        }

        private void LoadWhiteList()
        {
            try
            {
                EnsureLocalIpsInWhitelistFile();

                lstWhiteList.Items.Clear();
                string whitelistPath = Path.Combine(LOG_DIR, "whiteList.log");
                var whitelistItems = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                if (File.Exists(whitelistPath))
                {
                    foreach (var line in File.ReadAllLines(whitelistPath, Encoding.UTF8))
                    {
                        if (string.IsNullOrWhiteSpace(line)) continue;
                        int idx = line.IndexOf("IP:", StringComparison.OrdinalIgnoreCase);
                        if (idx >= 0)
                        {
                            string ip = line.Substring(idx + 3).Trim();
                            if (System.Net.IPAddress.TryParse(ip, out _))
                                whitelistItems.Add(ip);
                        }
                    }
                }

                foreach (var ip in whitelistItems.OrderBy(x => x))
                    lstWhiteList.Items.Add(ip);

                if (lstWhiteList.Items.Count == 0)
                    lstWhiteList.Items.Add(Lang.Get("MSG_NO_WHITELISTED_IPS"));
            }
            catch { }
        }

        private static bool IsLocalOrPrivateIp(string ipAddress)
        {
            if (!System.Net.IPAddress.TryParse(ipAddress, out var parsedIp))
                return false;

            var ip = parsedIp.IsIPv4MappedToIPv6 ? parsedIp.MapToIPv4() : parsedIp;
            if (System.Net.IPAddress.IsLoopback(ip))
                return true;

            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                var bytes = ip.GetAddressBytes();
                if (bytes.Length != 4)
                    return false;

                return bytes[0] == 10
                    || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                    || (bytes[0] == 192 && bytes[1] == 168)
                    || (bytes[0] == 169 && bytes[1] == 254);
            }

            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal)
                    return true;

                var bytes = ip.GetAddressBytes();
                return bytes.Length > 0 && (bytes[0] & 0xFE) == 0xFC;
            }

            return false;
        }

        private HashSet<string> GetLocalAutoWhitelistIps()
        {
            var localIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "127.0.0.1"
            };

            try
            {
                foreach (var ip in System.Net.Dns.GetHostAddresses(System.Net.Dns.GetHostName()))
                {
                    if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                        continue;

                    string text = ip.ToString();
                    if (IsLocalOrPrivateIp(text))
                        localIps.Add(text);
                }
            }
            catch
            {
            }

            return localIps;
        }

        private void EnsureLocalIpsInWhitelistFile()
        {
            try
            {
                string whitelistPath = Path.Combine(LOG_DIR, "whiteList.log");
                var existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                if (File.Exists(whitelistPath))
                {
                    foreach (var raw in File.ReadAllLines(whitelistPath, Encoding.UTF8))
                    {
                        if (string.IsNullOrWhiteSpace(raw))
                            continue;

                        string line = raw.Trim();
                        int idx = line.IndexOf("IP:", StringComparison.OrdinalIgnoreCase);
                        if (idx >= 0)
                            line = line.Substring(idx + 3).Trim();

                        if (System.Net.IPAddress.TryParse(line, out _))
                            existing.Add(line);
                    }
                }

                var toAdd = GetLocalAutoWhitelistIps().Where(ip => !existing.Contains(ip)).ToList();
                if (toAdd.Count == 0)
                    return;

                Directory.CreateDirectory(LOG_DIR);
                var entries = toAdd.Select(ip => $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] IP: {ip}");
                File.AppendAllLines(whitelistPath, entries, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                AppendLog($"[WARN] Failed to auto-whitelist local IPs: {ex.Message}");
            }
        }

        private void LoadRecentLogs()
        {
            txtLogs.Clear();
            AppendLog("=== RDP Security Monitor Started ===");
            AppendLog($"Log directory: {LOG_DIR}\n");

            LoadLogFile("service.log", "[SERVICE]", 10);
            LoadLogFile("access.log", "[ACCESS]", 10);
            LoadLogFile("block_list.log", "[BLOCK]", 15);
        }

        private void LoadLogFile(string fileName, string prefix, int tailLines)
        {
            try
            {
                string filePath = Path.Combine(LOG_DIR, fileName);
                if (!File.Exists(filePath)) return;

                var lines = File.ReadAllLines(filePath, Encoding.UTF8).Reverse().Take(tailLines).Reverse();
                foreach (var line in lines)
                {
                    if (!string.IsNullOrWhiteSpace(line))
                        AppendLog($"{prefix} {line}");
                }

                var fi = new FileInfo(filePath);
                if (fileName == "access.log") lastAccessLogPosition = fi.Length;
                else if (fileName == "block_list.log") lastBlockLogPosition = fi.Length;
                else if (fileName == "service.log") lastServiceLogPosition = fi.Length;
            }
            catch { }
        }

        private void AppendLog(string message)
        {
            if (txtLogs.InvokeRequired)
            {
                txtLogs.Invoke(new Action(() => AppendLog(message)));
                return;
            }

            if (IsDuplicateFileLogEntry(message))
                return;

            string timestamp = DateTime.Now.ToString("HH:mm:ss");
            txtLogs.AppendText($"[{timestamp}] {message}\r\n");
            txtLogs.SelectionStart = txtLogs.Text.Length;
            txtLogs.ScrollToCaret();
        }

        private bool IsDuplicateFileLogEntry(string message)
        {
            if (string.IsNullOrWhiteSpace(message))
                return false;

            bool isFileLog = message.StartsWith("[SERVICE] ", StringComparison.Ordinal)
                || message.StartsWith("[ACCESS] ", StringComparison.Ordinal)
                || message.StartsWith("[BLOCK] ", StringComparison.Ordinal);

            if (!isFileLog)
                return false;

            if (recentFileLogEntries.ContainsKey(message))
                return true;

            recentFileLogEntries[message] = DateTime.UtcNow;
            return false;
        }

        private void StartAutoRefresh()
        {
            refreshTimer = new System.Windows.Forms.Timer { Interval = 5000 };
            refreshTimer.Tick += (s, e) =>
            {
                UpdateServiceStatus();
                LoadBannedIPs();
                PollLogs();
            };
            refreshTimer.Start();
        }

        private void PollLogs()
        {
            try
            {
                string accessPath = Path.Combine(LOG_DIR, "access.log");
                string blockPath = Path.Combine(LOG_DIR, "block_list.log");
                string servicePath = Path.Combine(LOG_DIR, "service.log");

                if (File.Exists(accessPath))
                    ReadLogTail(accessPath, ref lastAccessLogPosition, "[ACCESS]");

                if (File.Exists(blockPath))
                    ReadLogTail(blockPath, ref lastBlockLogPosition, "[BLOCK]");

                if (File.Exists(servicePath))
                    ReadLogTail(servicePath, ref lastServiceLogPosition, "[SERVICE]");
            }
            catch { }
        }

        private void SetLanguage(string languageCode)
        {
            if (Program.CurrentLanguage == languageCode)
            {
                SyncLanguageMenuChecks();
                return;
            }

            Program.CurrentLanguage = languageCode;
            PersistUiLanguageToConfig();
            SyncLanguageMenuChecks();
            
            RefreshAllUITexts();
            
            LoadInitialData();
        }

        private void PersistUiLanguageToConfig()
        {
            try
            {
                string configPath = Path.Combine(LOG_DIR, "config.json");
                if (!File.Exists(configPath))
                    return;

                var json = ConfigCrypto.ReadConfigText(configPath);
                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                var config = JsonSerializer.Deserialize<ServiceConfig>(json, options);
                if (config == null)
                    return;

                config.UiLanguage = Program.CurrentLanguage;

                var saveOptions = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                };
                ConfigCrypto.WriteConfigText(configPath, JsonSerializer.Serialize(config, saveOptions));
            }
            catch (Exception ex)
            {
                AppendLog($"[WARN] Failed to persist UI language to config: {ex.Message}");
            }
        }

        private void SyncLanguageMenuChecks()
        {
            if (menuLanguageUa == null || menuLanguageEn == null || menuLanguage == null)
                return;

            bool isUa = string.Equals(Program.CurrentLanguage, "UA", StringComparison.OrdinalIgnoreCase);
            menuLanguageUa.Checked = isUa;
            menuLanguageEn.Checked = !isUa;
            menuLanguage.Text = isUa ? "Мова" : "Language";
            menuLanguage.Image = isUa ? menuLanguageUa.Image : menuLanguageEn.Image;
        }

        private Bitmap CreateLanguageFlagImage(string languageCode)
        {
            var bitmap = new Bitmap(24, 16);
            using (var g = Graphics.FromImage(bitmap))
            {
                g.Clear(Color.Transparent);

                if (string.Equals(languageCode, "UA", StringComparison.OrdinalIgnoreCase))
                {
                    using var uaBlueBrush = new SolidBrush(Color.FromArgb(0, 87, 183));
                    using var uaYellowBrush = new SolidBrush(Color.FromArgb(255, 215, 0));
                    g.FillRectangle(uaBlueBrush, 0, 0, 24, 8);
                    g.FillRectangle(uaYellowBrush, 0, 8, 24, 8);
                }
                else
                {
                    using var ukBlueBrush = new SolidBrush(Color.FromArgb(1, 33, 105));
                    using var ukRedBrush = new SolidBrush(Color.FromArgb(200, 16, 46));
                    g.FillRectangle(ukBlueBrush, 0, 0, 24, 16);
                    g.FillRectangle(Brushes.White, 9, 0, 6, 16);
                    g.FillRectangle(Brushes.White, 0, 5, 24, 6);
                    g.FillRectangle(ukRedBrush, 10, 0, 4, 16);
                    g.FillRectangle(ukRedBrush, 0, 6, 24, 4);
                }

                g.DrawRectangle(Pens.Gray, 0, 0, 23, 15);
            }

            return bitmap;
        }

        private void RefreshAllUITexts()
        {
            // Window title
            this.Text = Lang.Get("MAIN_TITLE");
            SyncLanguageMenuChecks();

            if (lblServiceStatusHeader != null)
                lblServiceStatusHeader.Text = Lang.Get("SERVICE_STATUS_HEADER");
            if (lblConfigurationHeader != null)
                lblConfigurationHeader.Text = Lang.Get("CONFIG_HEADER");
            
            // Tab titles
            tabControl.TabPages[0].Text = Lang.Get("TAB_CURRENT_LOGS");
            tabControl.TabPages[1].Text = Lang.Get("TAB_BANNED_IPS");
            tabControl.TabPages[2].Text = Lang.Get("TAB_WHITE_LIST");
            tabControl.TabPages[3].Text = Lang.Get("TAB_MANUAL_BLOCK");
            tabControl.TabPages[4].Text = Lang.Get("TAB_SETTINGS");
            tabControl.TabPages[5].Text = Lang.Get("TAB_INTERFACES");
            tabControl.TabPages[6].Text = Lang.Get("TAB_ALERTS");
            tabControl.TabPages[7].Text = Lang.Get("TAB_MESSAGE_SETTINGS");
            
            // Buttons
            btnStartService.Text = Lang.Get("BTN_START");
            btnStopService.Text = Lang.Get("BTN_STOP");
            btnRefresh.Text = Lang.Get("BTN_REFRESH");
            btnSaveConfig.Text = "💾 " + Lang.Get("BTN_SAVE_CONFIGURATION");
            btnAddLevel.Text = Lang.Get("BTN_ADD_LEVEL_WITH_PLUS");
            btnRemoveLevel.Text = Lang.Get("BTN_REMOVE_WITH_X");
            btnManualBlock.Text = "🔒 " + Lang.Get("BTN_BLOCK_THIS_IP");
            btnUnblockIP.Text = "🔓 " + Lang.Get("BTN_UNBLOCK_IP");
            btnClearAllBlocks.Text = "🧹 " + Lang.Get("BTN_CLEAR_ALL_BLOCKS");
            btnAddWhiteIP.Text = Lang.Get("BTN_ADD_WITH_PLUS");
            btnRemoveWhiteIP.Text = Lang.Get("BTN_REMOVE_WITH_X");

            if (lblBannedTitle != null)
                lblBannedTitle.Text = Lang.Get("SECTION_BLOCKED_IPS_FIREWALL");
            if (lblBannedUnblock != null)
                lblBannedUnblock.Text = Lang.Get("SECTION_IP_TO_UNBLOCK");
            if (lblWhiteTitle != null)
                lblWhiteTitle.Text = Lang.Get("SECTION_WHITE_LIST");
            if (lblWhiteAdd != null)
                lblWhiteAdd.Text = Lang.Get("SECTION_ADD_WHITELIST_IP");
            if (lblManualTitle != null)
                lblManualTitle.Text = Lang.Get("SECTION_MANUAL_BLOCK");
            if (lblManualIp != null)
                lblManualIp.Text = Lang.Get("LABEL_IP_ADDRESS");
            if (lblManualDuration != null)
                lblManualDuration.Text = Lang.Get("LABEL_BLOCK_DURATION_FULL");
            if (lblBlockStatus != null)
                lblBlockStatus.Text = Lang.Get("LABEL_BLOCK_STATUS_PLACEHOLDER");
            
            if (btnSaveMessageSettings != null)
                btnSaveMessageSettings.Text = Lang.Get("MSG_SETTINGS_SAVE_BTN");
            if (btnPrepareSupportReport != null)
                btnPrepareSupportReport.Text = GetSupportReportButtonText();
            if (chkNotifyMonitorStart != null)
                chkNotifyMonitorStart.Text = Lang.Get("MSG_SETTINGS_MONITOR_START");
            if (chkNotifyMonitorClose != null)
                chkNotifyMonitorClose.Text = Lang.Get("MSG_SETTINGS_MONITOR_CLOSE");
            if (chkNotifyServiceStart != null)
                chkNotifyServiceStart.Text = Lang.Get("MSG_SETTINGS_SERVICE_START");
            if (chkNotifyServiceStop != null)
                chkNotifyServiceStop.Text = Lang.Get("MSG_SETTINGS_SERVICE_STOP");
            if (chkNotifyConfigSave != null)
                chkNotifyConfigSave.Text = Lang.Get("MSG_SETTINGS_CONFIG_SAVE");

            if (chkAntiBruteEnabled != null)
                chkAntiBruteEnabled.Text = Lang.Get("ANTI_BRUTE_ENABLED");
            if (lblSettingsServiceConfigTitle != null)
                lblSettingsServiceConfigTitle.Text = Lang.Get("SECTION_SERVICE_CONFIG");
            if (lblSettingsRdpPort != null)
                lblSettingsRdpPort.Text = Lang.Get("LABEL_RDP_PORT");
            if (lblSettingsBlockLevels != null)
                lblSettingsBlockLevels.Text = Lang.Get("LABEL_BLOCK_LEVELS_TABLE") + " (60 / 12h / 7d / 2w)";
            if (lblAntiBruteSectionTitle != null)
                lblAntiBruteSectionTitle.Text = Lang.Get("ANTI_BRUTE_SECTION");
            if (lblSprayTitle != null)
                lblSprayTitle.Text = Lang.Get("ANTI_BRUTE_SPRAY");
            if (lblIpAbuseTitle != null)
                lblIpAbuseTitle.Text = Lang.Get("ANTI_BRUTE_IP_ABUSE");
            if (lblRecurrenceTitle != null)
                lblRecurrenceTitle.Text = Lang.Get("ANTI_BRUTE_RECURRENCE");
            if (lblSubnetTitle != null)
                lblSubnetTitle.Text = Lang.Get("ANTI_BRUTE_SUBNET");
            if (lblAntiBruteSprayWindow != null)
                lblAntiBruteSprayWindow.Text = Lang.Get("ANTI_BRUTE_WINDOW_MIN");
            if (lblAntiBruteSprayThreshold != null)
                lblAntiBruteSprayThreshold.Text = Lang.Get("ANTI_BRUTE_UNIQUE_IPS");
            if (lblAntiBruteSprayBlock != null)
                lblAntiBruteSprayBlock.Text = Lang.Get("ANTI_BRUTE_BLOCK_MIN");
            if (lblAntiBruteIpAbuseWindow != null)
                lblAntiBruteIpAbuseWindow.Text = Lang.Get("ANTI_BRUTE_WINDOW_MIN") + " (NAT: M=10)";
            if (lblAntiBruteIpAbuseUsers != null)
                lblAntiBruteIpAbuseUsers.Text = Lang.Get("ANTI_BRUTE_UNIQUE_USERS") + " (NAT: N=3)";
            if (lblAntiBruteRecurrenceLookback != null)
                lblAntiBruteRecurrenceLookback.Text = Lang.Get("ANTI_BRUTE_LOOKBACK_H");
            if (lblAntiBruteRecurrenceStep != null)
                lblAntiBruteRecurrenceStep.Text = Lang.Get("ANTI_BRUTE_STEP");
            if (lblAntiBruteRecurrenceMax != null)
                lblAntiBruteRecurrenceMax.Text = Lang.Get("ANTI_BRUTE_MAX");
            if (lblAntiBruteSubnetWindow != null)
                lblAntiBruteSubnetWindow.Text = Lang.Get("ANTI_BRUTE_WINDOW_MIN");
            if (lblAntiBruteSubnetThreshold != null)
                lblAntiBruteSubnetThreshold.Text = Lang.Get("ANTI_BRUTE_UNIQUE_IPS");
            if (lblAntiBruteSubnetBlock != null)
                lblAntiBruteSubnetBlock.Text = Lang.Get("ANTI_BRUTE_BLOCK_MIN");
            if (chkSprayEnabled != null)
                chkSprayEnabled.Text = Lang.Get("ANTI_BRUTE_ENABLED_SHORT");
            if (chkRecurrenceEnabled != null)
                chkRecurrenceEnabled.Text = Lang.Get("ANTI_BRUTE_ENABLED_SHORT");
            if (chkSubnetEnabled != null)
                chkSubnetEnabled.Text = Lang.Get("ANTI_BRUTE_ENABLED_SHORT");

            if (lblInterfacesTitle != null)
                lblInterfacesTitle.Text = Lang.Get("IFACE_HEADER");

            if (lblAlertsHeader != null)
                lblAlertsHeader.Text = Lang.Get("TELEGRAM_SECTION_HEADER");
            if (chkTelegramEnabled != null)
                chkTelegramEnabled.Text = Lang.Get("TELEGRAM_ENABLE");
            if (lblAlertsBotToken != null)
                lblAlertsBotToken.Text = Lang.Get("TELEGRAM_BOT_TOKEN");
            if (lblAlertsChatId != null)
                lblAlertsChatId.Text = Lang.Get("TELEGRAM_CHAT_ID");
            if (lblAlertsTemplatesHeader != null)
                lblAlertsTemplatesHeader.Text = Lang.Get("TELEGRAM_MESSAGE_TEMPLATES");
            if (lblAlertsPlaceholders != null)
                lblAlertsPlaceholders.Text = Lang.Get("TELEGRAM_PLACEHOLDERS");
            if (lblAlertsDefaultTemplate != null)
                lblAlertsDefaultTemplate.Text = Lang.Get("TELEGRAM_TEMPLATE_DEFAULT");
            if (lblAlertsHelpTitle != null)
                lblAlertsHelpTitle.Text = Lang.Get("TELEGRAM_HELP_TITLE");
            if (lblAlertsLevelCaptions.Count > 0)
            {
                for (int i = 0; i < lblAlertsLevelCaptions.Count; i++)
                    lblAlertsLevelCaptions[i].Text = $"{Lang.Get("TELEGRAM_TEMPLATE_LEVEL")} {i + 1}:";
            }
            if (lblAlertsHelpSteps.Count > 0)
            {
                for (int i = 0; i < lblAlertsHelpSteps.Count; i++)
                    lblAlertsHelpSteps[i].Text = Lang.Get($"TELEGRAM_HELP_STEP{i + 1}");
            }
            if (btnTestTelegram != null)
                btnTestTelegram.Text = Lang.Get("TELEGRAM_TEST_BUTTON");
            if (btnSaveTelegram != null)
                btnSaveTelegram.Text = Lang.Get("TELEGRAM_SAVE_BUTTON");

            if (lblMessageSettingsHeader != null)
                lblMessageSettingsHeader.Text = Lang.Get("MSG_SETTINGS_HEADER");
            if (lblMessageSettingsMonitorSection != null)
                lblMessageSettingsMonitorSection.Text = Lang.Get("MSG_SETTINGS_MONITOR");
            if (lblMessageSettingsServiceSection != null)
                lblMessageSettingsServiceSection.Text = Lang.Get("MSG_SETTINGS_SERVICE");

            PositionAntiBruteHelpBadges();
            ApplyAntiBruteHelpTooltips();
            
            // DataGridView columns
            dgvBlockLevels.Columns[0].HeaderText = Lang.Get("GRID_ATTEMPTS");
            dgvBlockLevels.Columns[1].HeaderText = Lang.Get("GRID_BLOCK_MINUTES");
            if (dgvInterfaces != null)
            {
                dgvInterfaces.Columns[0].HeaderText = Lang.Get("IFACE_COL_ENABLED");
                dgvInterfaces.Columns[1].HeaderText = Lang.Get("IFACE_COL_IP");
                dgvInterfaces.Columns[2].HeaderText = Lang.Get("IFACE_COL_NAME");
            }
            if (btnReloadInterfaces != null)
                btnReloadInterfaces.Text = Lang.Get("IFACE_BTN_RELOAD");
            if (btnSaveInterfaces != null)
                btnSaveInterfaces.Text = Lang.Get("IFACE_BTN_SAVE");
            if (lblInterfacesHint != null)
                lblInterfacesHint.Text = Lang.Get("IFACE_HINT");

            ApplyMainLayout();
        }

        private void BtnRefresh_Click(object sender, EventArgs e)
        {
            LoadInitialData();
            AppendLog("[MONITOR] Manual refresh triggered");
        }

        private void BtnStartService_Click(object sender, EventArgs e)
        {
            try
            {
                var existingService = ServiceController.GetServices().FirstOrDefault(s => s.ServiceName == SERVICE_NAME);
                if (existingService == null)
                {
                    if (TryStartLocalEngine())
                    {
                        UpdateServiceStatus();
                    }
                    return;
                }

                var serviceController = new ServiceController(SERVICE_NAME);
                serviceController.Refresh();
                if (serviceController.Status == ServiceControllerStatus.Running)
                {
                    UpdateServiceStatus();
                    AppendLog("[MONITOR] Service already running");
                    return;
                }

                serviceController.Start();
                AppendLog("[MONITOR] Starting service...");
                serviceController.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(10));
                UpdateServiceStatus();
                AppendLog("[MONITOR] Service started successfully");
                if (ShouldNotify("ServiceStart"))
                    SendSimpleTelegramMessage("\u2705 \u0421\u0415\u0420\u0412\u0406\u0421 \u0417\u0410\u041F\u0423\u0429\u0415\u041D\u041E");
            }
            catch (Exception ex)
            {
                if (IsServiceAccessDenied(ex))
                {
                    AppendLog("[WARN] Service start requires administrator rights. Requesting UAC...");

                    if (TryStartServiceElevated())
                    {
                        UpdateServiceStatus();
                        AppendLog("[MONITOR] Service started successfully");
                        if (ShouldNotify("ServiceStart"))
                            SendSimpleTelegramMessage("\u2705 \u0421\u0415\u0420\u0412\u0406\u0421 \u0417\u0410\u041F\u0423\u0429\u0415\u041D\u041E");
                        return;
                    }

                    AppendLog("[WARN] Service start canceled or access denied");
                    MessageBox.Show(
                        "Administrator privileges are required to start the service. Confirm the UAC prompt or run Monitor as Administrator.",
                        "Access denied",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning);
                    return;
                }

                if (TryStartLocalEngine())
                {
                    AppendLog("[MONITOR] Local engine started");
                    UpdateServiceStatus();
                    return;
                }

                AppendLog($"[ERROR] Service start failed: {ex.Message}");
                MessageBox.Show($"Failed to start service: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void BtnStopService_Click(object sender, EventArgs e)
        {
            try
            {
                var existingService = ServiceController.GetServices().FirstOrDefault(s => s.ServiceName == SERVICE_NAME);
                if (existingService == null)
                {
                    TryStopLocalEngine();
                    UpdateServiceStatus();
                    return;
                }

                var serviceController = new ServiceController(SERVICE_NAME);
                serviceController.Refresh();
                if (serviceController.Status == ServiceControllerStatus.Stopped)
                {
                    UpdateServiceStatus();
                    AppendLog("[MONITOR] Service already stopped");
                    return;
                }

                serviceController.Stop();
                AppendLog("[MONITOR] Stopping service...");
                serviceController.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(10));
                UpdateServiceStatus();
                AppendLog("[MONITOR] Service stopped successfully");
                if (ShouldNotify("ServiceStop"))
                    SendSimpleTelegramMessage("\uD83D\uDED1 \u0421\u0415\u0420\u0412\u0406\u0421 \u0417\u0423\u041F\u0418\u041D\u0415\u041D\u041E");
            }
            catch (Exception ex)
            {
                if (IsServiceAccessDenied(ex))
                {
                    AppendLog("[WARN] Service stop requires administrator rights. Requesting UAC...");

                    if (TryStopServiceElevated())
                    {
                        UpdateServiceStatus();
                        AppendLog("[MONITOR] Service stopped successfully");
                        if (ShouldNotify("ServiceStop"))
                            SendSimpleTelegramMessage("\uD83D\uDED1 \u0421\u0415\u0420\u0412\u0406\u0421 \u0417\u0423\u041F\u0418\u041D\u0415\u041D\u041E");
                        return;
                    }

                    AppendLog("[WARN] Service stop canceled or access denied");
                    MessageBox.Show(
                        "Administrator privileges are required to stop the service. Confirm the UAC prompt or run Monitor as Administrator.",
                        "Access denied",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning);
                    return;
                }

                if (TryStopLocalEngine())
                {
                    AppendLog("[MONITOR] Local engine stopped");
                    UpdateServiceStatus();
                    return;
                }

                AppendLog($"[ERROR] Service stop failed: {ex.Message}");
                MessageBox.Show($"Failed to stop service: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void LstBannedIPs_DoubleClick(object sender, EventArgs e)
        {
            if (lstBannedIPs.SelectedItem != null)
            {
                var selectedIP = lstBannedIPs.SelectedItem.ToString();
                if (selectedIP != Lang.Get("MSG_NO_BLOCKED_IPS"))
                {
                    txtIPToUnblock.Text = selectedIP;
                    txtIPToUnblock.Focus();
                    txtIPToUnblock.SelectAll();
                }
            }
        }

        private void LstBannedIPs_MouseDown(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right)
            {
                int index = lstBannedIPs.IndexFromPoint(e.Location);
                if (index >= 0 && index < lstBannedIPs.Items.Count)
                {
                    lstBannedIPs.SelectedIndex = index;
                    var selectedIP = lstBannedIPs.Items[index].ToString();
                    if (selectedIP != Lang.Get("MSG_NO_BLOCKED_IPS"))
                    {
                        txtIPToUnblock.Text = selectedIP;
                        txtIPToUnblock.Focus();
                        txtIPToUnblock.SelectAll();
                    }
                }
            }
        }

        private void BtnUnblockIP_Click(object sender, EventArgs e)
        {
            string ip = txtIPToUnblock.Text.Trim();
            if (string.IsNullOrWhiteSpace(ip))
            {
                MessageBox.Show("Enter IP to unlock", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            try
            {
                var removedTargets = RemoveBlockedEntriesForIp(ip);
                ApplyFirewallChangeOrSignalService(() =>
                {
                    foreach (var target in removedTargets)
                    {
                        RemoveBlockedTargetFromFirewallRule(target);
                        if (TryConvertSubnet24ToRange(target, out string subnetRange))
                            RemoveBlockedTargetFromFirewallRule(subnetRange);
                    }

                    // Keep backward compatibility for older firewall entries that may contain only direct IP.
                    RemoveBlockedTargetFromFirewallRule(ip);
                });

                LoadBannedIPs();
                txtIPToUnblock.Clear();
                AppendLog($"[MONITOR] IP {ip} unlocked manually");
                SendSimpleTelegramMessage($"🔓 РОЗБЛОКОВАНО: {ip}");
                MessageBox.Show($"IP {ip} has been unlocked", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                AppendLog($"[ERROR] Unlock failed: {ex.Message}");
            }
        }

        private void BtnClearAllBlocks_Click(object sender, EventArgs e)
        {
            try
            {
                bool isUa = string.Equals(Program.CurrentLanguage, "UA", StringComparison.OrdinalIgnoreCase);
                string requiredPhrase = "ТОЧНО УДАЛИТЬ";

                var preConfirm = MessageBox.Show(
                    isUa
                        ? "Будуть видалені всі блокування з журналу та з правил RDP_BLOCK_0..15. Продовжити?"
                        : "All blocks will be removed from log and from RDP_BLOCK_0..15 firewall rules. Continue?",
                    isUa ? "Підтвердження" : "Confirmation",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning);

                if (preConfirm != DialogResult.Yes)
                    return;

                if (!TryConfirmWithPhrase(requiredPhrase, isUa))
                    return;

                string blockLogPath = Path.Combine(LOG_DIR, "block_list.log");
                if (File.Exists(blockLogPath))
                    File.WriteAllText(blockLogPath, string.Empty, Encoding.UTF8);
                else
                    File.WriteAllText(blockLogPath, string.Empty, Encoding.UTF8);

                ApplyFirewallChangeOrSignalService(RemoveAllBlocksFirewallRule);

                LoadBannedIPs();
                AppendLog("[MONITOR] All blocks have been cleared manually");
                SendSimpleTelegramMessage("🧹 ОЧИЩЕНО ВСЕ БЛОКИРОВКИ");
                MessageBox.Show(
                    isUa ? "Усі блокування очищено." : "All blocks were cleared.",
                    isUa ? "Готово" : "Done",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                AppendLog($"[ERROR] Clear all blocks failed: {ex.Message}");
            }
        }

        private bool TryConfirmWithPhrase(string requiredPhrase, bool isUa)
        {
            using (var prompt = new Form())
            {
                prompt.Text = isUa ? "Фінальне підтвердження" : "Final Confirmation";
                prompt.StartPosition = FormStartPosition.CenterParent;
                prompt.FormBorderStyle = FormBorderStyle.FixedDialog;
                prompt.MinimizeBox = false;
                prompt.MaximizeBox = false;
                prompt.ClientSize = new Size(540, 170);

                var lbl = new Label
                {
                    AutoSize = false,
                    Location = new Point(12, 12),
                    Size = new Size(516, 60),
                    Text = (isUa
                        ? "Щоб підтвердити повне очищення, введіть точну фразу: "
                        : "To confirm full cleanup, enter exact phrase: ") + requiredPhrase,
                    Font = new Font("Segoe UI", 9, FontStyle.Bold)
                };

                var txt = new TextBox
                {
                    Location = new Point(12, 82),
                    Size = new Size(516, 24),
                    Font = new Font("Segoe UI", 9)
                };

                var btnOk = new Button
                {
                    Text = isUa ? "Підтвердити" : "Confirm",
                    Location = new Point(350, 122),
                    Size = new Size(85, 30),
                    DialogResult = DialogResult.OK
                };

                var btnCancel = new Button
                {
                    Text = isUa ? "Скасувати" : "Cancel",
                    Location = new Point(443, 122),
                    Size = new Size(85, 30),
                    DialogResult = DialogResult.Cancel
                };

                prompt.Controls.Add(lbl);
                prompt.Controls.Add(txt);
                prompt.Controls.Add(btnOk);
                prompt.Controls.Add(btnCancel);
                prompt.AcceptButton = btnOk;
                prompt.CancelButton = btnCancel;

                if (prompt.ShowDialog(this) != DialogResult.OK)
                    return false;

                if (!string.Equals((txt.Text ?? string.Empty).Trim(), requiredPhrase, StringComparison.Ordinal))
                {
                    MessageBox.Show(
                        isUa ? "Фраза введена невірно. Операцію скасовано." : "Phrase is incorrect. Operation cancelled.",
                        isUa ? "Скасовано" : "Cancelled",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning);
                    return false;
                }

                return true;
            }
        }

        /// <summary>
        /// After the monitor edits block_list.log/whiteList.log directly, ask the running
        /// service to immediately re-read them and resync RDP_BLOCK_0..15 — instead of
        /// waiting on its FileSystemWatcher debounce, or duplicating its bucket/whitelist/TTL
        /// logic here. Falls back to <paramref name="fallbackDirectFirewallEdit"/> (the old
        /// direct-PowerShell edit of the one affected rule) only when the service isn't
        /// running to signal, so a block/unblock made while the service is stopped still
        /// takes effect immediately.
        /// </summary>
        private void ApplyFirewallChangeOrSignalService(Action fallbackDirectFirewallEdit)
        {
            if (TrySignalServiceResync())
                return;

            try
            {
                fallbackDirectFirewallEdit();
            }
            catch (Exception ex)
            {
                AppendLog($"[WARN] Direct firewall fallback failed: {ex.Message}");
            }
        }

        private bool TrySignalServiceResync()
        {
            try
            {
                using var sc = new ServiceController(SERVICE_NAME);
                if (sc.Status != ServiceControllerStatus.Running)
                    return false;

                sc.ExecuteCommand(ServiceControlResyncFirewall);
                AppendLog("[MONITOR] Signalled RDPSecurityService to resync firewall rules now.");
                return true;
            }
            catch (Exception ex)
            {
                AppendLog($"[WARN] Failed to signal service resync, will edit firewall directly: {ex.Message}");
                return false;
            }
        }

        private void RemoveAllBlocksFirewallRule()
        {
            string namesLiteral = string.Join(",", FirewallBuckets.AllRuleNames().Select(n => $"'{n}'"));
            using (var ps = PowerShell.Create())
            {
                ps.AddScript($@"
                    $names = @({namesLiteral})
                    foreach ($name in $names) {{
                        $rule = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
                        if (-not $rule) {{
                            New-NetFirewallRule -Name $name -DisplayName ('RDP Block ' + $name) -Direction Inbound -Action Block -Protocol Any -RemoteAddress '255.255.255.255' -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
                            continue
                        }}

                        Get-NetFirewallRule -Name $name |
                            Get-NetFirewallAddressFilter |
                            Set-NetFirewallAddressFilter -RemoteAddress '255.255.255.255' -ErrorAction SilentlyContinue | Out-Null
                    }}
                ");
                ps.Invoke();
            }
        }

        private void BtnAddWhiteIP_Click(object sender, EventArgs e)
        {
            string ip = txtNewWhiteIP.Text.Trim();
            if (string.IsNullOrWhiteSpace(ip) || !System.Net.IPAddress.TryParse(ip, out _))
            {
                MessageBox.Show("Enter valid IP address", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            try
            {
                string whitelistPath = Path.Combine(LOG_DIR, "whiteList.log");
                string entry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] IP: {ip}";
                File.AppendAllText(whitelistPath, entry + Environment.NewLine, Encoding.UTF8);

                LoadWhiteList();
                var removedTargets = RemoveBlockedEntriesForIp(ip);
                ApplyFirewallChangeOrSignalService(() =>
                {
                    foreach (var target in removedTargets)
                    {
                        RemoveBlockedTargetFromFirewallRule(target);
                        if (TryConvertSubnet24ToRange(target, out string subnetRange))
                            RemoveBlockedTargetFromFirewallRule(subnetRange);
                    }

                    // Keep backward compatibility for older firewall entries that may contain only direct IP.
                    RemoveBlockedTargetFromFirewallRule(ip);
                });

                LoadBannedIPs();
                txtNewWhiteIP.Clear();
                AppendLog($"[MONITOR] IP {ip} added to whitelist and removed from active blocks");
                SendSimpleTelegramMessage($"➕ БІЛИЙ СПИСОК: {ip}");
                MessageBox.Show($"IP {ip} added to whitelist", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void RemoveBlockedTargetFromBlockLog(string target)
        {
            string blockLogPath = Path.Combine(LOG_DIR, "block_list.log");
            if (!File.Exists(blockLogPath))
                return;

            var lines = File.ReadAllLines(blockLogPath, Encoding.UTF8)
                .Where(l => !IsBlockedTargetLogEntryFor(l, target))
                .ToList();
            File.WriteAllLines(blockLogPath, lines, Encoding.UTF8);
        }

        private List<string> RemoveBlockedEntriesForIp(string ip)
        {
            var removedTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string blockLogPath = Path.Combine(LOG_DIR, "block_list.log");
            if (!File.Exists(blockLogPath) || string.IsNullOrWhiteSpace(ip))
                return removedTargets.ToList();

            var keptLines = new List<string>();
            foreach (var line in File.ReadAllLines(blockLogPath, Encoding.UTF8))
            {
                string target = ExtractBlockedTarget(line);
                if (string.IsNullOrWhiteSpace(target))
                {
                    keptLines.Add(line);
                    continue;
                }

                bool removeDirect = string.Equals(target, ip, StringComparison.OrdinalIgnoreCase);
                if (removeDirect)
                {
                    removedTargets.Add(target);
                    continue;
                }

                keptLines.Add(line);
            }

            File.WriteAllLines(blockLogPath, keptLines, Encoding.UTF8);
            return removedTargets.ToList();
        }

        private static string ExtractBlockedTarget(string line)
        {
            if (string.IsNullOrWhiteSpace(line))
                return string.Empty;

            string trimmed = line.Trim();
            int ipIdx = trimmed.IndexOf("BLOCKED IP:", StringComparison.OrdinalIgnoreCase);
            if (ipIdx >= 0)
                return trimmed.Substring(ipIdx + 11).Split('|')[0].Trim();

            int netIdx = trimmed.IndexOf("BLOCKED NET:", StringComparison.OrdinalIgnoreCase);
            if (netIdx >= 0)
                return trimmed.Substring(netIdx + 12).Split('|')[0].Trim();

            return string.Empty;
        }

        private static bool IsIpv4InSubnet24(string ipAddress, string subnetCidr)
        {
            if (!System.Net.IPAddress.TryParse(ipAddress, out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                return false;

            if (!TryParseSubnet24(subnetCidr, out byte[]? netBytes) || netBytes == null)
                return false;

            byte[] bytes = ip.GetAddressBytes();
            return bytes[0] == netBytes[0] && bytes[1] == netBytes[1] && bytes[2] == netBytes[2];
        }

        private static bool TryParseSubnet24(string subnetCidr, out byte[]? netBytes)
        {
            netBytes = null;
            if (string.IsNullOrWhiteSpace(subnetCidr))
                return false;

            string[] parts = subnetCidr.Trim().Split('/');
            if (parts.Length != 2 || parts[1] != "24")
                return false;

            if (!System.Net.IPAddress.TryParse(parts[0], out var netIp) || netIp.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                return false;

            netBytes = netIp.GetAddressBytes();
            return true;
        }

        private static bool TryConvertSubnet24ToRange(string target, out string range)
        {
            range = string.Empty;
            if (!TryParseSubnet24(target, out byte[]? netBytes) || netBytes == null)
                return false;

            range = $"{netBytes[0]}.{netBytes[1]}.{netBytes[2]}.0-{netBytes[0]}.{netBytes[1]}.{netBytes[2]}.255";
            return true;
        }

        private void RemoveBlockedTargetFromFirewallRule(string target)
        {
            if (string.IsNullOrWhiteSpace(target))
                return;

            string ruleName = FirewallBuckets.RuleName(FirewallBuckets.IndexFor(target));

            using (var ps = PowerShell.Create())
            {
                ps.AddScript($@"
                    $rule = Get-NetFirewallRule -Name '{ruleName}' -ErrorAction SilentlyContinue
                    if (-not $rule) {{ return }}

                    $current = @((Get-NetFirewallRule -Name '{ruleName}' | Get-NetFirewallAddressFilter).RemoteAddress -split ',') |
                        Where-Object {{ $_ -and $_ -ne 'Any' }} |
                        Select-Object -Unique

                    $new = $current | Where-Object {{ $_ -ne '{target}' }}

                    if ($new.Count -eq 0) {{
                        Get-NetFirewallRule -Name '{ruleName}' |
                            Get-NetFirewallAddressFilter |
                            Set-NetFirewallAddressFilter -RemoteAddress '255.255.255.255' -ErrorAction SilentlyContinue | Out-Null
                    }}
                    else {{
                        Get-NetFirewallRule -Name '{ruleName}' |
                            Get-NetFirewallAddressFilter |
                            Set-NetFirewallAddressFilter -RemoteAddress ($new -join ',') -ErrorAction SilentlyContinue | Out-Null
                    }}
                ");
                ps.Invoke();
            }
        }

        private void BtnRemoveWhiteIP_Click(object sender, EventArgs e)
        {
            if (lstWhiteList.SelectedIndex < 0)
            {
                MessageBox.Show("Select IP to remove", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            string ip = lstWhiteList.SelectedItem.ToString();
            if (ip == Lang.Get("MSG_NO_WHITELISTED_IPS")) return;

            if (IsLocalOrPrivateIp(ip))
            {
                bool isUa = string.Equals(Program.CurrentLanguage, "UA", StringComparison.OrdinalIgnoreCase);
                MessageBox.Show(
                    isUa ? "Локальні IP захищені: їх не можна видаляти з білого списку." : "Local IPs are protected and cannot be removed from whitelist.",
                    isUa ? "Захищено" : "Protected",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                return;
            }

            try
            {
                string whitelistPath = Path.Combine(LOG_DIR, "whiteList.log");
                var lines = File.ReadAllLines(whitelistPath, Encoding.UTF8).Where(l => !l.Contains(ip)).ToList();
                File.WriteAllLines(whitelistPath, lines, Encoding.UTF8);

                LoadWhiteList();
                AppendLog($"[MONITOR] IP {ip} removed from whitelist");
                SendSimpleTelegramMessage($"➖ ВИДАЛЕНО З БІЛОГО СПИСКУ: {ip}");
                MessageBox.Show($"IP {ip} removed from whitelist", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void BtnManualBlock_Click(object sender, EventArgs e)
        {
            string ip = txtIPToBlock.Text.Trim();
            if (string.IsNullOrWhiteSpace(ip) || !System.Net.IPAddress.TryParse(ip, out _))
            {
                MessageBox.Show("Enter valid IP address", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            if (IsLocalOrPrivateIp(ip))
            {
                bool isUa = string.Equals(Program.CurrentLanguage, "UA", StringComparison.OrdinalIgnoreCase);
                string message = isUa
                    ? "Локальні IP автоматично у білому списку. Блокування заборонено."
                    : "Local IPs are auto-whitelisted and cannot be blocked.";
                lblBlockStatus.Text = message;
                lblBlockStatus.ForeColor = Color.FromArgb(255, 152, 0);
                MessageBox.Show(message, isUa ? "Захищено" : "Protected", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            if (!TryParseBlockDurationMinutes(txtBlockMinutes.Text.Trim(), out int minutes))
            {
                MessageBox.Show("Enter valid duration: 60, 12h, 7d, 2w", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            try
            {
                string durationText = FormatDurationForDisplay(minutes);

                // Add to block_list.log
                string blockLogPath = Path.Combine(LOG_DIR, "block_list.log");
                DateTime until = DateTime.Now.AddMinutes(minutes);
                string entry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] BLOCKED IP: {ip} | Failed Attempts: MANUAL | BlockMinutes: {minutes} | Until: {until:yyyy-MM-dd HH:mm:ss}";
                Directory.CreateDirectory(LOG_DIR);
                File.AppendAllText(blockLogPath, entry + Environment.NewLine, Encoding.UTF8);

                // Ask the running service to resync from block_list.log now; only touch the
                // firewall rule directly here if the service isn't there to do it properly.
                string blockRuleName = FirewallBuckets.RuleName(FirewallBuckets.IndexFor(ip));
                ApplyFirewallChangeOrSignalService(() =>
                {
                    using (var ps = PowerShell.Create())
                    {
                        ps.AddScript($@"
                            $rule = Get-NetFirewallRule -Name '{blockRuleName}' -ErrorAction SilentlyContinue
                            if (-not $rule) {{
                                New-NetFirewallRule -Name '{blockRuleName}' -DisplayName ('RDP Block ' + '{blockRuleName}') -Direction Inbound -Action Block -Protocol Any -RemoteAddress '{ip}' -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
                            }}
                            else {{
                                (Get-NetFirewallRule -Name '{blockRuleName}' | Get-NetFirewallAddressFilter) | Set-NetFirewallAddressFilter -RemoteAddress (
                                    ((Get-NetFirewallRule -Name '{blockRuleName}' | Get-NetFirewallAddressFilter).RemoteAddress -split ',') + @('{ip}') | Where-Object {{$_ -and $_ -ne 'Any' -and $_ -ne '255.255.255.255'}} | Select-Object -Unique
                                ) -join ',' -ErrorAction SilentlyContinue
                            }}
                        ");
                        ps.Invoke();
                    }
                });

                LoadBannedIPs();
                lblBlockStatus.Text = $"✓ Successfully blocked IP {ip} for {durationText} ({minutes} minutes)\nUntil: {until:yyyy-MM-dd HH:mm:ss}\n\nIP has been added to firewall rule.";
                lblBlockStatus.ForeColor = Color.FromArgb(76, 175, 80);
                AppendLog($"[MONITOR] Manually blocked IP {ip} for {durationText} ({minutes}m)");
                SendSimpleTelegramMessage($"🚫 ЗАБЛОКОВАНО: {ip} на {durationText} (до {until:HH:mm})");
                txtIPToBlock.Clear();
            }
            catch (Exception ex)
            {
                lblBlockStatus.Text = $"✗ Error: {ex.Message}";
                lblBlockStatus.ForeColor = Color.FromArgb(244, 67, 54);
                AppendLog($"[ERROR] Manual block failed: {ex.Message}");
            }
        }

        private bool TryParseBlockDurationMinutes(string rawInput, out int minutes)
        {
            minutes = 0;
            if (string.IsNullOrWhiteSpace(rawInput))
                return false;

            string input = rawInput.Trim().ToLowerInvariant().Replace(" ", string.Empty);
            var match = Regex.Match(input, @"^(?<value>\d+)(?<unit>[a-zа-яіїєґ]*)$");
            if (!match.Success)
                return false;

            if (!long.TryParse(match.Groups["value"].Value, out var value) || value < 1)
                return false;

            string unit = match.Groups["unit"].Value;
            long multiplier = unit switch
            {
                "" or "m" or "min" or "mins" or "minute" or "minutes" or "хв" or "хвилин" or "мин" or "м" => 1,
                "h" or "hr" or "hrs" or "hour" or "hours" or "ч" or "час" or "часа" or "часов" or "год" => 60,
                "d" or "day" or "days" or "д" or "дн" or "день" or "дня" or "дней" => 1440,
                "w" or "wk" or "wks" or "week" or "weeks" or "н" or "нед" or "неделя" or "недель" or "тиж" or "тижд" or "тиждень" => 10080,
                _ => 0
            };

            if (multiplier == 0)
                return false;

            long totalMinutes = value * multiplier;
            if (totalMinutes < 1 || totalMinutes > int.MaxValue)
                return false;

            minutes = (int)totalMinutes;
            return true;
        }

        private string FormatDurationForDisplay(int minutes)
        {
            if (minutes % 10080 == 0)
                return $"{minutes / 10080}w";

            if (minutes % 1440 == 0)
                return $"{minutes / 1440}d";

            if (minutes % 60 == 0)
                return $"{minutes / 60}h";

            return $"{minutes}m";
        }

        private bool EnsureConfigFileExists(string configPath)
        {
            try
            {
                if (File.Exists(configPath))
                    return true;

                Directory.CreateDirectory(LOG_DIR);

                string[] exampleCandidates = new[]
                {
                    Path.Combine(Application.StartupPath, "config.example.json"),
                    Path.GetFullPath(Path.Combine(Application.StartupPath, "..", "config.example.json")),
                    Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config.example.json")
                };

                string? examplePath = exampleCandidates.FirstOrDefault(File.Exists);
                if (!string.IsNullOrWhiteSpace(examplePath))
                {
                    string exampleJson = File.ReadAllText(examplePath, Encoding.UTF8);
                    ConfigCrypto.WriteConfigText(configPath, exampleJson);
                    AppendLog($"[MONITOR] config.json created from {examplePath}");
                    return true;
                }

                var defaultConfig = new ServiceConfig
                {
                    Port = 3389,
                    Ports = new List<int> { 3389 },
                    UiLanguage = Program.CurrentLanguage,
                    Levels = new List<BlockLevel>
                    {
                        new BlockLevel { Attempts = 3, BlockMinutes = 30 },
                        new BlockLevel { Attempts = 5, BlockMinutes = 180 },
                        new BlockLevel { Attempts = 7, BlockMinutes = 2880 }
                    },
                    Telegram = new TelegramConfig { Enabled = false, BotToken = "", ChatId = "" },
                    AntiBrute = AntiBruteConfig.CreateDefault()
                };

                var createOptions = new JsonSerializerOptions { WriteIndented = true };
                ConfigCrypto.WriteConfigText(configPath, JsonSerializer.Serialize(defaultConfig, createOptions));
                AppendLog("[MONITOR] config.json created from built-in defaults");
                return true;
            }
            catch (Exception ex)
            {
                AppendLog($"[ERROR] EnsureConfigFileExists failed: {ex.Message}");
                return false;
            }
        }

        private bool TryRecoverBrokenConfig(string configPath)
        {
            try
            {
                if (File.Exists(configPath))
                {
                    string backupPath = configPath + ".bad-" + DateTime.Now.ToString("yyyyMMdd-HHmmss");
                    File.Copy(configPath, backupPath, true);
                    File.Delete(configPath);
                    AppendLog($"[MONITOR] Broken config backed up to {backupPath}");
                }

                return EnsureConfigFileExists(configPath);
            }
            catch (Exception ex)
            {
                AppendLog($"[ERROR] TryRecoverBrokenConfig failed: {ex.Message}");
                return false;
            }
        }


        private void LoadConfigToSettings(bool allowRecovery = true)
        {
            string configPath = Path.Combine(LOG_DIR, "config.json");
            try
            {
                if (!EnsureConfigFileExists(configPath))
                {
                    MessageBox.Show($"Config not found at: {configPath}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                var json = ConfigCrypto.ReadConfigText(configPath);
                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                var config = JsonSerializer.Deserialize<ServiceConfig>(json, options);

                if (config != null)
                {
                    int port = config.Port > 0 ? config.Port : 3389;
                    txtPort.Text = port.ToString();

                    int windowDays = config.FailedAttemptsWindowDays.HasValue ? Math.Max(1, config.FailedAttemptsWindowDays.Value) : 1;
                    txtFailedAttemptsWindowDays.Text = windowDays.ToString();

                    dgvBlockLevels.Rows.Clear();
                    if (config.Levels != null)
                    {
                        foreach (var level in config.Levels)
                        {
                            dgvBlockLevels.Rows.Add(level.Attempts, level.BlockMinutes);
                        }
                    }

                    var anti = config.AntiBrute ?? AntiBruteConfig.CreateDefault();
                    var spray = anti.Spray ?? SprayConfig.CreateDefault();
                    var ipAbuse = anti.IpAbuse ?? IpAbuseConfig.CreateDefault();
                    var recurrence = anti.Recurrence ?? RecurrenceConfig.CreateDefault();
                    var subnet = anti.Subnet ?? SubnetConfig.CreateDefault();

                    chkAntiBruteEnabled.Checked = anti.Enabled;

                    chkSprayEnabled.Checked = spray.Enabled;
                    txtSprayWindowMinutes.Text = Math.Max(1, spray.WindowMinutes).ToString();
                    txtSprayUniqueIpsThreshold.Text = Math.Max(2, spray.UniqueIpsThreshold).ToString();
                    txtSprayBlockMinutes.Text = Math.Max(1, spray.BlockMinutes).ToString();

                    txtIpAbuseWindowMinutes.Text = Math.Max(1, ipAbuse.WindowMinutes).ToString();
                    txtIpAbuseDistinctUsersThreshold.Text = Math.Max(2, ipAbuse.DistinctUsersThreshold).ToString();

                    chkRecurrenceEnabled.Checked = recurrence.Enabled;
                    txtRecurrenceLookbackHours.Text = Math.Max(1, recurrence.LookbackHours).ToString();
                    txtRecurrenceStepMultiplier.Text = Math.Max(0.0, recurrence.StepMultiplier).ToString("0.##", System.Globalization.CultureInfo.InvariantCulture);
                    txtRecurrenceMaxMultiplier.Text = Math.Max(1.0, recurrence.MaxMultiplier).ToString("0.##", System.Globalization.CultureInfo.InvariantCulture);

                    chkSubnetEnabled.Checked = subnet.Enabled;
                    txtSubnetWindowMinutes.Text = Math.Max(1, subnet.WindowMinutes).ToString();
                    txtSubnetUniqueIpsThreshold.Text = Math.Max(2, subnet.UniqueIpsThreshold).ToString();
                    txtSubnetBlockMinutes.Text = Math.Max(1, subnet.BlockMinutes).ToString();

                    AppendLog("[MONITOR] Config loaded to Settings");
                }
                else
                {
                    AppendLog("[ERROR] Config is null after deserialization");
                }
            }
            catch (Exception ex)
            {
                AppendLog($"[ERROR] LoadConfigToSettings failed: {ex.Message}");

                if (allowRecovery && TryRecoverBrokenConfig(configPath))
                {
                    AppendLog("[MONITOR] Config recovered automatically, retrying load");
                    LoadConfigToSettings(false);
                    return;
                }

                MessageBox.Show($"Error loading config: {ex.Message}\n\nPath: {Path.Combine(LOG_DIR, "config.json")}", "Error");
            }
        }

        private void BtnAddLevel_Click(object sender, EventArgs e)
        {
            dgvBlockLevels.Rows.Add(0, 0);
        }

        private void BtnRemoveLevel_Click(object sender, EventArgs e)
        {
            if (dgvBlockLevels.SelectedRows.Count > 0)
            {
                dgvBlockLevels.Rows.RemoveAt(dgvBlockLevels.SelectedRows[0].Index);
            }
            else
            {
                MessageBox.Show("Select a level to remove", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private bool TryParseIntBox(TextBox textBox, string fieldName, int minValue, out int value)
        {
            value = 0;
            if (!int.TryParse(textBox.Text.Trim(), out int parsed) || parsed < minValue)
            {
                MessageBox.Show($"Invalid value for {fieldName}. Minimum: {minValue}", "Validation Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                textBox.Focus();
                return false;
            }

            value = parsed;
            return true;
        }

        private bool TryParseDoubleBox(TextBox textBox, string fieldName, double minValue, out double value)
        {
            value = 0;
            string raw = (textBox.Text ?? string.Empty).Trim().Replace(',', '.');
            if (!double.TryParse(raw, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out double parsed) || parsed < minValue)
            {
                MessageBox.Show($"Invalid value for {fieldName}. Minimum: {minValue}", "Validation Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                textBox.Focus();
                return false;
            }

            value = parsed;
            return true;
        }

        private bool TryParseDurationBox(TextBox textBox, string fieldName, out int minutes, out string conversionInfo)
        {
            minutes = 0;
            conversionInfo = string.Empty;

            string rawInput = textBox.Text.Trim();
            if (!TryParseBlockDurationMinutes(rawInput, out var parsed) || parsed < 1)
            {
                MessageBox.Show($"Invalid value for {fieldName}. Use: 60, 12h, 7d, 2w", "Validation Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                textBox.Focus();
                return false;
            }

            minutes = parsed;
            textBox.Text = minutes.ToString();

            if (!string.Equals(rawInput, minutes.ToString(), StringComparison.OrdinalIgnoreCase))
                conversionInfo = $"{fieldName}: {rawInput} = {minutes}m";

            return true;
        }

        private void BtnSaveConfig_Click(object sender, EventArgs e)
        {
            try
            {
                // Validate input
                if (!int.TryParse(txtPort.Text, out int port) || port < 1 || port > 65535)
                {
                    MessageBox.Show("Invalid port number (1-65535)", "Validation Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                if (!TryParseIntBox(txtFailedAttemptsWindowDays, "Failed attempt lifetime (days)", 1, out int failedAttemptsWindowDays)) return;

                bool isUa = string.Equals(Program.CurrentLanguage, "UA", StringComparison.OrdinalIgnoreCase);
                var durationConversions = new List<string>();

                var levels = new List<BlockLevel>();
                foreach (DataGridViewRow row in dgvBlockLevels.Rows)
                {
                    if (row.IsNewRow)
                        continue;

                    if (row.Cells[0].Value != null && row.Cells[1].Value != null)
                    {
                        string attemptsRaw = row.Cells[0].Value?.ToString()?.Trim() ?? string.Empty;
                        string minutesRaw = row.Cells[1].Value?.ToString()?.Trim() ?? string.Empty;

                        if (!int.TryParse(attemptsRaw, out int attempts) || attempts < 1)
                        {
                            MessageBox.Show("Invalid attempts value in block levels table", "Validation Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }

                        if (!TryParseBlockDurationMinutes(minutesRaw, out int minutes) || minutes < 1)
                        {
                            MessageBox.Show("Invalid block duration in table. Use: 60, 12h, 7d, 2w", "Validation Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }

                        if (!string.Equals(minutesRaw, minutes.ToString(), StringComparison.OrdinalIgnoreCase))
                        {
                            string levelLabel = isUa
                                ? $"Рівень (спроби {attempts})"
                                : $"Level (attempts {attempts})";
                            durationConversions.Add($"{levelLabel}: {minutesRaw} = {minutes}m");
                        }

                        row.Cells[1].Value = minutes;
                        levels.Add(new BlockLevel { Attempts = attempts, BlockMinutes = minutes });
                    }
                }

                if (levels.Count == 0)
                {
                    MessageBox.Show("Add at least one block level", "Validation Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                if (!TryParseIntBox(txtSprayWindowMinutes, "Spray windowMinutes", 1, out int sprayWindowMinutes)) return;
                if (!TryParseIntBox(txtSprayUniqueIpsThreshold, "Spray uniqueIpsThreshold", 2, out int sprayUniqueIpsThreshold)) return;
                string sprayLabel = isUa ? "Spray блок" : "Spray block";
                if (!TryParseDurationBox(txtSprayBlockMinutes, sprayLabel, out int sprayBlockMinutes, out string sprayConversion)) return;
                if (!string.IsNullOrWhiteSpace(sprayConversion)) durationConversions.Add(sprayConversion);

                if (!TryParseIntBox(txtIpAbuseWindowMinutes, "IP abuse windowMinutes", 1, out int ipAbuseWindowMinutes)) return;
                if (!TryParseIntBox(txtIpAbuseDistinctUsersThreshold, "IP abuse distinctUsersThreshold", 2, out int ipAbuseDistinctUsersThreshold)) return;

                if (!TryParseIntBox(txtRecurrenceLookbackHours, "Recurrence lookbackHours", 1, out int recurrenceLookbackHours)) return;
                if (!TryParseDoubleBox(txtRecurrenceStepMultiplier, "Recurrence stepMultiplier", 0.0, out double recurrenceStepMultiplier)) return;
                if (!TryParseDoubleBox(txtRecurrenceMaxMultiplier, "Recurrence maxMultiplier", 1.0, out double recurrenceMaxMultiplier)) return;

                if (!TryParseIntBox(txtSubnetWindowMinutes, "Subnet windowMinutes", 1, out int subnetWindowMinutes)) return;
                if (!TryParseIntBox(txtSubnetUniqueIpsThreshold, "Subnet uniqueIpsThreshold", 2, out int subnetUniqueIpsThreshold)) return;
                string subnetLabel = isUa ? "Subnet блок" : "Subnet block";
                if (!TryParseDurationBox(txtSubnetBlockMinutes, subnetLabel, out int subnetBlockMinutes, out string subnetConversion)) return;
                if (!string.IsNullOrWhiteSpace(subnetConversion)) durationConversions.Add(subnetConversion);

                string configPath = Path.Combine(LOG_DIR, "config.json");
                ServiceConfig? config;
                if (File.Exists(configPath))
                {
                    var currentJson = ConfigCrypto.ReadConfigText(configPath);
                    var currentOptions = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                    config = JsonSerializer.Deserialize<ServiceConfig>(currentJson, currentOptions) ?? new ServiceConfig();
                }
                else
                {
                    config = new ServiceConfig();
                }

                config.Port = port;
                config.Ports = new List<int> { port };
                config.UiLanguage = Program.CurrentLanguage;
                config.Levels = levels;
                config.FailedAttemptsWindowDays = failedAttemptsWindowDays;
                // Preserve subnetUserSpray as-is: there is no GUI for it yet, so rebuilding
                // AntiBruteConfig from the form fields below must not silently reset it to
                // defaults on every Save Config click.
                var existingSubnetUserSpray = config.AntiBrute?.SubnetUserSpray;
                config.AntiBrute = new AntiBruteConfig
                {
                    SubnetUserSpray = existingSubnetUserSpray ?? SubnetUserSprayConfig.CreateDefault(),
                    Enabled = chkAntiBruteEnabled.Checked,
                    Spray = new SprayConfig
                    {
                        Enabled = chkSprayEnabled.Checked,
                        WindowMinutes = sprayWindowMinutes,
                        UniqueIpsThreshold = sprayUniqueIpsThreshold,
                        BlockMinutes = sprayBlockMinutes
                    },
                    IpAbuse = new IpAbuseConfig
                    {
                        WindowMinutes = ipAbuseWindowMinutes,
                        DistinctUsersThreshold = ipAbuseDistinctUsersThreshold
                    },
                    Recurrence = new RecurrenceConfig
                    {
                        Enabled = chkRecurrenceEnabled.Checked,
                        LookbackHours = recurrenceLookbackHours,
                        StepMultiplier = recurrenceStepMultiplier,
                        MaxMultiplier = recurrenceMaxMultiplier
                    },
                    Subnet = new SubnetConfig
                    {
                        Enabled = chkSubnetEnabled.Checked,
                        WindowMinutes = subnetWindowMinutes,
                        UniqueIpsThreshold = subnetUniqueIpsThreshold,
                        BlockMinutes = subnetBlockMinutes
                    }
                };

                var options = new JsonSerializerOptions 
                { 
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                };
                var json = JsonSerializer.Serialize(config, options);

                ConfigCrypto.WriteConfigText(configPath, json);

                LoadConfiguration();
                AppendLog("[MONITOR] Configuration saved successfully");

                string languageLabel = isUa ? "Українська (UA)" : "English (EN)";
                WriteMonitorEventLog("[MONITOR_UI] ConfigSave event triggered from settings tab");
                string configSavedMessage = isUa
                    ? $"⚙️ Конфігурацію збережено в Monitor\nПорт: {port}\nМова: {languageLabel}"
                    : $"⚙️ Configuration saved in Monitor\nPort: {port}\nLanguage: {languageLabel}";
                NotifyMonitorLifecycle("ConfigSave", configSavedMessage, fireAndForget: true);

                var successMessage = new StringBuilder();

                if (isUa)
                {
                    successMessage.AppendLine("Конфігурацію збережено успішно!");
                    successMessage.AppendLine("Сервіс автоматично перезавантажить налаштування.");
                    successMessage.AppendLine();
                    successMessage.AppendLine($"Поточна мова інтерфейсу: {languageLabel}");
                    if (durationConversions.Count > 0)
                    {
                        successMessage.AppendLine();
                        successMessage.AppendLine("Перерахунок тривалості:");
                        foreach (var conversion in durationConversions)
                            successMessage.AppendLine($"- {conversion}");
                    }

                    MessageBox.Show(successMessage.ToString(), "Успіх", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    successMessage.AppendLine("Configuration saved successfully!");
                    successMessage.AppendLine("Service will reload settings automatically.");
                    successMessage.AppendLine();
                    successMessage.AppendLine($"Current UI language: {languageLabel}");
                    if (durationConversions.Count > 0)
                    {
                        successMessage.AppendLine();
                        successMessage.AppendLine("Duration conversion:");
                        foreach (var conversion in durationConversions)
                            successMessage.AppendLine($"- {conversion}");
                    }

                    MessageBox.Show(successMessage.ToString(), "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error saving config: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                AppendLog($"[ERROR] Config save failed: {ex.Message}");
            }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            NotifyMonitorLifecycle("MonitorClose", "\uD83D\uDDA5\uFE0F RDP Security Monitor \u0437\u0430\u043A\u0440\u0438\u0442\u043E", fireAndForget: false);
            refreshTimer?.Stop();
            fileWatcher?.Dispose();
            base.OnFormClosing(e);
        }
    }

    public class ServiceConfig
    {
        [System.Text.Json.Serialization.JsonPropertyName("port")]
        public int Port { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("uiLanguage")]
        public string UiLanguage { get; set; } = "UA";

        [System.Text.Json.Serialization.JsonPropertyName("ports")]
        public List<int> Ports { get; set; } = new List<int>();
        
        [System.Text.Json.Serialization.JsonPropertyName("levels")]
        public List<BlockLevel> Levels { get; set; } = new List<BlockLevel>();

        [System.Text.Json.Serialization.JsonPropertyName("failedAttemptsWindowDays")]
        public int? FailedAttemptsWindowDays { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("telegram")]
        public TelegramConfig? Telegram { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("antiBrute")]
        public AntiBruteConfig? AntiBrute { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("interfaces")]
        public List<InterfaceBindingConfig> Interfaces { get; set; } = new List<InterfaceBindingConfig>();
    }

    public class InterfaceBindingConfig
    {
        [System.Text.Json.Serialization.JsonPropertyName("address")]
        public string Address { get; set; } = "";

        [System.Text.Json.Serialization.JsonPropertyName("enabled")]
        public bool Enabled { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("name")]
        public string Name { get; set; } = "";
    }

    public class AntiBruteConfig
    {
        [System.Text.Json.Serialization.JsonPropertyName("enabled")]
        public bool Enabled { get; set; } = true;

        [System.Text.Json.Serialization.JsonPropertyName("spray")]
        public SprayConfig? Spray { get; set; } = SprayConfig.CreateDefault();

        [System.Text.Json.Serialization.JsonPropertyName("recurrence")]
        public RecurrenceConfig? Recurrence { get; set; } = RecurrenceConfig.CreateDefault();

        [System.Text.Json.Serialization.JsonPropertyName("subnet")]
        public SubnetConfig? Subnet { get; set; } = SubnetConfig.CreateDefault();

        [System.Text.Json.Serialization.JsonPropertyName("ipAbuse")]
        public IpAbuseConfig? IpAbuse { get; set; } = IpAbuseConfig.CreateDefault();

        [System.Text.Json.Serialization.JsonPropertyName("subnetUserSpray")]
        public SubnetUserSprayConfig? SubnetUserSpray { get; set; } = SubnetUserSprayConfig.CreateDefault();

        public static AntiBruteConfig CreateDefault()
        {
            return new AntiBruteConfig
            {
                Enabled = true,
                Spray = SprayConfig.CreateDefault(),
                Recurrence = RecurrenceConfig.CreateDefault(),
                Subnet = SubnetConfig.CreateDefault(),
                IpAbuse = IpAbuseConfig.CreateDefault(),
                SubnetUserSpray = SubnetUserSprayConfig.CreateDefault()
            };
        }
    }

    // Mirrors WinService's SubnetUserSprayConfig so Monitor's Save Config doesn't drop this
    // section on round-trip. No dedicated GUI controls yet — edit config.json's antiBrute
    // section (via the service, since it's DPAPI-encrypted) or wait for GUI support.
    public class SubnetUserSprayConfig
    {
        [System.Text.Json.Serialization.JsonPropertyName("enabled")]
        public bool Enabled { get; set; } = true;

        [System.Text.Json.Serialization.JsonPropertyName("windowMinutes")]
        public int WindowMinutes { get; set; } = 10;

        [System.Text.Json.Serialization.JsonPropertyName("uniqueIpsInSubnetThreshold")]
        public int UniqueIpsInSubnetThreshold { get; set; } = 2;

        [System.Text.Json.Serialization.JsonPropertyName("blockMinutes")]
        public int BlockMinutes { get; set; } = 120;

        public static SubnetUserSprayConfig CreateDefault()
        {
            return new SubnetUserSprayConfig
            {
                Enabled = true,
                WindowMinutes = 10,
                UniqueIpsInSubnetThreshold = 2,
                BlockMinutes = 120
            };
        }
    }

    public class IpAbuseConfig
    {
        [System.Text.Json.Serialization.JsonPropertyName("windowMinutes")]
        public int WindowMinutes { get; set; } = 10;

        [System.Text.Json.Serialization.JsonPropertyName("distinctUsersThreshold")]
        public int DistinctUsersThreshold { get; set; } = 3;

        public static IpAbuseConfig CreateDefault()
        {
            return new IpAbuseConfig
            {
                WindowMinutes = 10,
                DistinctUsersThreshold = 3
            };
        }
    }

    public class SprayConfig
    {
        [System.Text.Json.Serialization.JsonPropertyName("enabled")]
        public bool Enabled { get; set; } = true;

        [System.Text.Json.Serialization.JsonPropertyName("windowMinutes")]
        public int WindowMinutes { get; set; } = 10;

        [System.Text.Json.Serialization.JsonPropertyName("uniqueIpsThreshold")]
        public int UniqueIpsThreshold { get; set; } = 4;

        [System.Text.Json.Serialization.JsonPropertyName("blockMinutes")]
        public int BlockMinutes { get; set; } = 240;

        public static SprayConfig CreateDefault()
        {
            return new SprayConfig
            {
                Enabled = true,
                WindowMinutes = 10,
                UniqueIpsThreshold = 4,
                BlockMinutes = 240
            };
        }
    }

    public class RecurrenceConfig
    {
        [System.Text.Json.Serialization.JsonPropertyName("enabled")]
        public bool Enabled { get; set; } = true;

        [System.Text.Json.Serialization.JsonPropertyName("lookbackHours")]
        public int LookbackHours { get; set; } = 24;

        [System.Text.Json.Serialization.JsonPropertyName("stepMultiplier")]
        public double StepMultiplier { get; set; } = 0.5;

        [System.Text.Json.Serialization.JsonPropertyName("maxMultiplier")]
        public double MaxMultiplier { get; set; } = 4.0;

        public static RecurrenceConfig CreateDefault()
        {
            return new RecurrenceConfig
            {
                Enabled = true,
                LookbackHours = 24,
                StepMultiplier = 0.5,
                MaxMultiplier = 4.0
            };
        }
    }

    public class SubnetConfig
    {
        [System.Text.Json.Serialization.JsonPropertyName("enabled")]
        public bool Enabled { get; set; } = true;

        [System.Text.Json.Serialization.JsonPropertyName("windowMinutes")]
        public int WindowMinutes { get; set; } = 30;

        [System.Text.Json.Serialization.JsonPropertyName("uniqueIpsThreshold")]
        public int UniqueIpsThreshold { get; set; } = 3;

        [System.Text.Json.Serialization.JsonPropertyName("blockMinutes")]
        public int BlockMinutes { get; set; } = 240;

        public static SubnetConfig CreateDefault()
        {
            return new SubnetConfig
            {
                Enabled = true,
                WindowMinutes = 30,
                UniqueIpsThreshold = 3,
                BlockMinutes = 240
            };
        }
    }

    public class TelegramConfig
    {
        [System.Text.Json.Serialization.JsonPropertyName("enabled")]
        public bool Enabled { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("botToken")]
        public string BotToken { get; set; } = "";

        [System.Text.Json.Serialization.JsonPropertyName("chatId")]
        public string ChatId { get; set; } = "";

        [System.Text.Json.Serialization.JsonPropertyName("messageTemplates")]
        public Dictionary<string, string> MessageTemplates { get; set; } = new Dictionary<string, string>();

        [System.Text.Json.Serialization.JsonPropertyName("limitedPhones")]
        public List<string> LimitedPhones { get; set; } = new List<string>();

        [System.Text.Json.Serialization.JsonPropertyName("selfUnbanIp")]
        public string SelfUnbanIp { get; set; } = "";

        [System.Text.Json.Serialization.JsonPropertyName("hereProbeEnabled")]
        public bool HereProbeEnabled { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("hereProbePublicUrl")]
        public string HereProbePublicUrl { get; set; } = "";

        [System.Text.Json.Serialization.JsonPropertyName("hereProbeListenPrefix")]
        public string HereProbeListenPrefix { get; set; } = "";
    }

    public class BlockLevel
    {
        [System.Text.Json.Serialization.JsonPropertyName("attempts")]
        public int Attempts { get; set; }
        
        [System.Text.Json.Serialization.JsonPropertyName("blockMinutes")]
        public int BlockMinutes { get; set; }
    }

    public class MessageNotificationSettings
    {
        [System.Text.Json.Serialization.JsonPropertyName("monitorStart")]
        public bool MonitorStart { get; set; } = false;

        [System.Text.Json.Serialization.JsonPropertyName("monitorClose")]
        public bool MonitorClose { get; set; } = false;

        [System.Text.Json.Serialization.JsonPropertyName("serviceStart")]
        public bool ServiceStart { get; set; } = true;

        [System.Text.Json.Serialization.JsonPropertyName("serviceStop")]
        public bool ServiceStop { get; set; } = true;

        [System.Text.Json.Serialization.JsonPropertyName("configSave")]
        public bool ConfigSave { get; set; } = false;
    }

    public class SupportStatsReport
    {
        [System.Text.Json.Serialization.JsonPropertyName("reportId")]
        public string ReportId { get; set; } = string.Empty;

        [System.Text.Json.Serialization.JsonPropertyName("generatedLocal")]
        public string GeneratedLocal { get; set; } = string.Empty;

        [System.Text.Json.Serialization.JsonPropertyName("machineName")]
        public string MachineName { get; set; } = string.Empty;

        [System.Text.Json.Serialization.JsonPropertyName("userName")]
        public string UserName { get; set; } = string.Empty;

        [System.Text.Json.Serialization.JsonPropertyName("osVersion")]
        public string OsVersion { get; set; } = string.Empty;

        [System.Text.Json.Serialization.JsonPropertyName("monitorVersion")]
        public string MonitorVersion { get; set; } = string.Empty;

        [System.Text.Json.Serialization.JsonPropertyName("serviceStatus")]
        public string ServiceStatus { get; set; } = string.Empty;

        [System.Text.Json.Serialization.JsonPropertyName("accessAttemptsTotal")]
        public int AccessAttemptsTotal { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("accessAttemptsLast24h")]
        public int AccessAttemptsLast24h { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("activeBlockedTargets")]
        public int ActiveBlockedTargets { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("activeBlockedDirectIps")]
        public int ActiveBlockedDirectIps { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("activeBlockedSubnets")]
        public int ActiveBlockedSubnets { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("firewallRemoteTargetCount")]
        public int FirewallRemoteTargetCount { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("whitelistEntries")]
        public int WhitelistEntries { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("topBlockedTargets")]
        public List<SupportTopBlockedTarget> TopBlockedTargets { get; set; } = new List<SupportTopBlockedTarget>();

        [System.Text.Json.Serialization.JsonPropertyName("notes")]
        public string Notes { get; set; } = string.Empty;
    }

    public class SupportTopBlockedTarget
    {
        [System.Text.Json.Serialization.JsonPropertyName("target")]
        public string Target { get; set; } = string.Empty;

        [System.Text.Json.Serialization.JsonPropertyName("hits")]
        public int Hits { get; set; }
    }

    // Custom transparent PictureBox for background
    public class TransparentPictureBox : PictureBox
    {
        protected override void OnPaint(PaintEventArgs e)
        {
            if (this.Image != null)
            {
                var attributes = new System.Drawing.Imaging.ImageAttributes();
                var matrix = new System.Drawing.Imaging.ColorMatrix
                {
                    Matrix33 = 0.08f // Opacity: 8%
                };
                attributes.SetColorMatrix(matrix, System.Drawing.Imaging.ColorMatrixFlag.Default, System.Drawing.Imaging.ColorAdjustType.Bitmap);
                
                e.Graphics.DrawImage(
                    this.Image,
                    new Rectangle(0, 0, this.Width, this.Height),
                    0, 0, this.Image.Width, this.Image.Height,
                    GraphicsUnit.Pixel,
                    attributes);
            }
        }
    }
}
