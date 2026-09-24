using System;
using System.Drawing;
using System.Windows.Forms;

namespace RDPMonitor
{
    public class LanguageSelector : Form
    {
        public string SelectedLanguage { get; private set; } = "UA";

        public LanguageSelector()
        {
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            this.Text = "Виберіть мову | Select Language | Выберите язык";
            this.Size = new Size(400, 250);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.BackColor = Color.FromArgb(240, 240, 240);

            var lblTitle = new Label
            {
                Text = "Виберіть мову інтерфейсу",
                Location = new Point(20, 20),
                Size = new Size(360, 30),
                Font = new Font("Segoe UI", 14, FontStyle.Bold),
                ForeColor = Color.FromArgb(0, 102, 204)
            };
            this.Controls.Add(lblTitle);

            // Кнопка Українська
            var btnUA = new Button
            {
                Text = "УКРАЇНСЬКА (UA)",
                Location = new Point(20, 70),
                Size = new Size(360, 45),
                BackColor = Color.FromArgb(0, 102, 204),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 12, FontStyle.Bold)
            };
            btnUA.FlatAppearance.BorderSize = 0;
            btnUA.Click += (s, e) => SelectLanguage("UA");
            this.Controls.Add(btnUA);

            // Кнопка English
            var btnEN = new Button
            {
                Text = "ENGLISH (EN)",
                Location = new Point(20, 130),
                Size = new Size(360, 45),
                BackColor = Color.FromArgb(76, 175, 80),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 12, FontStyle.Bold)
            };
            btnEN.FlatAppearance.BorderSize = 0;
            btnEN.Click += (s, e) => SelectLanguage("EN");
            this.Controls.Add(btnEN);
        }

        private void SelectLanguage(string lang)
        {
            SelectedLanguage = lang;
            this.Close();
        }
    }
}
