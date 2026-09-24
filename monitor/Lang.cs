using System.Collections.Generic;

namespace RDPMonitor
{
    public static class Lang
    {
        private static Dictionary<string, Dictionary<string, string>> translations = new Dictionary<string, Dictionary<string, string>>
        {
            ["MAIN_TITLE"] = new Dictionary<string, string> { ["UA"] = "Монітор безпеки RDP", ["EN"] = "RDP Security Monitor" },
            ["SERVICE_STATUS_HEADER"] = new Dictionary<string, string> { ["UA"] = "Статус служби:", ["EN"] = "Service Status:" },
            ["SERVICE_CHECKING"] = new Dictionary<string, string> { ["UA"] = "Перевірка статусу...", ["EN"] = "Checking status..." },
            ["SERVICE_STATUS_RUNNING"] = new Dictionary<string, string> { ["UA"] = "Працює", ["EN"] = "Running" },
            ["SERVICE_STATUS_STOPPED"] = new Dictionary<string, string> { ["UA"] = "Зупинено", ["EN"] = "Stopped" },
            ["SERVICE_STATUS_UNKNOWN"] = new Dictionary<string, string> { ["UA"] = "Невідомо", ["EN"] = "Unknown" },
            
            ["BTN_START"] = new Dictionary<string, string> { ["UA"] = "Запустити службу", ["EN"] = "Start Service" },
            ["BTN_STOP"] = new Dictionary<string, string> { ["UA"] = "Зупинити службу", ["EN"] = "Stop Service" },
            ["BTN_REFRESH"] = new Dictionary<string, string> { ["UA"] = "Оновити", ["EN"] = "Refresh" },
            ["BTN_UNLOCK"] = new Dictionary<string, string> { ["UA"] = "Розблокувати IP", ["EN"] = "Unlock IP" },
            ["BTN_ADD"] = new Dictionary<string, string> { ["UA"] = "Додати", ["EN"] = "Add" },
            ["BTN_REMOVE"] = new Dictionary<string, string> { ["UA"] = "Видалити", ["EN"] = "Remove" },
            ["BTN_BLOCK"] = new Dictionary<string, string> { ["UA"] = "Заблокувати IP", ["EN"] = "Block IP" },
            ["BTN_SAVE"] = new Dictionary<string, string> { ["UA"] = "Зберегти налаштування", ["EN"] = "Save Config" },
            ["BTN_ADD_LEVEL"] = new Dictionary<string, string> { ["UA"] = "Додати рівень", ["EN"] = "Add Level" },
            ["BTN_REMOVE_LEVEL"] = new Dictionary<string, string> { ["UA"] = "Видалити рівень", ["EN"] = "Remove Level" },
            
            ["CONFIG_HEADER"] = new Dictionary<string, string> { ["UA"] = "Конфігурація:", ["EN"] = "Configuration:" },
            ["CONFIG_PORT"] = new Dictionary<string, string> { ["UA"] = "Порт:", ["EN"] = "Port:" },
            ["LOADING"] = new Dictionary<string, string> { ["UA"] = "Завантаження...", ["EN"] = "Loading..." },
            
            ["TAB_CURRENT_LOGS"] = new Dictionary<string, string> { ["UA"] = "Поточні логи", ["EN"] = "Current Logs" },
            ["TAB_BANNED_IPS"] = new Dictionary<string, string> { ["UA"] = "Заблоковані IP", ["EN"] = "Banned IPs" },
            ["TAB_WHITE_LIST"] = new Dictionary<string, string> { ["UA"] = "Білий список", ["EN"] = "White List" },
            ["TAB_MANUAL_BLOCK"] = new Dictionary<string, string> { ["UA"] = "Ручне блокування", ["EN"] = "Manual Block" },
            ["TAB_SETTINGS"] = new Dictionary<string, string> { ["UA"] = "Налаштування", ["EN"] = "Settings" },
            ["TAB_INTERFACES"] = new Dictionary<string, string> { ["UA"] = "Інтерфейси", ["EN"] = "Interfaces" },
            ["TAB_ALERTS"] = new Dictionary<string, string> { ["UA"] = "Налаштування АЛЕРТС", ["EN"] = "ALERTS Settings" },
            ["TAB_MESSAGE_SETTINGS"] = new Dictionary<string, string> { ["UA"] = "Налаштування повідомлень", ["EN"] = "Message Settings" },            
            ["SECTION_BANNED_IPS"] = new Dictionary<string, string> { ["UA"] = "Заблоковані IP-адреси:", ["EN"] = "Blocked IPs:" },
            ["SECTION_WHITE_LIST"] = new Dictionary<string, string> { ["UA"] = "Білий список IP (авторозблокування):", ["EN"] = "IP Whitelist (Auto-unlock):" },
            ["SECTION_MANUAL_BLOCK"] = new Dictionary<string, string> { ["UA"] = "Вручну заблокувати IP:", ["EN"] = "Manually Block IP:" },
            ["SECTION_BLOCK_LEVELS"] = new Dictionary<string, string> { ["UA"] = "Налаштування рівнів блокування:", ["EN"] = "Block Levels Configuration:" },
            ["SECTION_BLOCKED_IPS_FIREWALL"] = new Dictionary<string, string> { ["UA"] = "Поточні заблоковані IP (з правила брандмауера):", ["EN"] = "Currently blocked IPs (from firewall rule):" },
            ["SECTION_IP_TO_UNBLOCK"] = new Dictionary<string, string> { ["UA"] = "IP для розблокування:", ["EN"] = "IP to unlock:" },
            ["SECTION_ADD_WHITELIST_IP"] = new Dictionary<string, string> { ["UA"] = "Додати IP до білого списку:", ["EN"] = "Add IP to whitelist:" },
            ["SECTION_SERVICE_CONFIG"] = new Dictionary<string, string> { ["UA"] = "Конфігурація служби", ["EN"] = "Service Configuration" },
            ["SECTION_BLOCK_LEVELS_ATTEMPTS"] = new Dictionary<string, string> { ["UA"] = "Рівні блокування (Спроби → Хвилини):", ["EN"] = "Block Levels (Attempts → Minutes):" },
            
            ["LABEL_IP_ADDRESS"] = new Dictionary<string, string> { ["UA"] = "IP-адреса:", ["EN"] = "IP Address:" },
            ["LABEL_DURATION"] = new Dictionary<string, string> { ["UA"] = "Тривалість (хвилини):", ["EN"] = "Duration (minutes):" },
            ["LABEL_BLOCK_STATUS_PLACEHOLDER"] = new Dictionary<string, string> { ["UA"] = "Статус з'явиться тут...", ["EN"] = "Status will appear here..." },

            ["BTN_UNBLOCK_IP"] = new Dictionary<string, string> { ["UA"] = "Розблокувати IP", ["EN"] = "Unlock IP" },
            ["BTN_CLEAR_ALL_BLOCKS"] = new Dictionary<string, string> { ["UA"] = "Очистити всі блокування", ["EN"] = "Clear all blocks" },
            ["BTN_ADD_WITH_PLUS"] = new Dictionary<string, string> { ["UA"] = "+ Додати", ["EN"] = "+ Add" },
            ["BTN_REMOVE_WITH_X"] = new Dictionary<string, string> { ["UA"] = "✕ Видалити", ["EN"] = "✕ Remove" },
            ["BTN_BLOCK_THIS_IP"] = new Dictionary<string, string> { ["UA"] = "ЗАБЛОКУВАТИ ЦЕЙ IP", ["EN"] = "BLOCK THIS IP" },
            ["BTN_ADD_LEVEL_WITH_PLUS"] = new Dictionary<string, string> { ["UA"] = "+ Додати рівень", ["EN"] = "+ Add Level" },
            ["BTN_SAVE_CONFIGURATION"] = new Dictionary<string, string> { ["UA"] = "ЗБЕРЕГТИ КОНФІГУРАЦІЮ", ["EN"] = "SAVE CONFIGURATION" },
            
            ["GRID_FAILED_ATTEMPTS"] = new Dictionary<string, string> { ["UA"] = "Невдалих спроб", ["EN"] = "Failed Attempts" },
            ["GRID_BLOCK_DURATION"] = new Dictionary<string, string> { ["UA"] = "Тривалість блокування (хв)", ["EN"] = "Block Duration (min)" },
            ["GRID_ATTEMPTS"] = new Dictionary<string, string> { ["UA"] = "Спроми", ["EN"] = "Attempts" },
            ["GRID_BLOCK_MINUTES"] = new Dictionary<string, string> { ["UA"] = "Хвилини блокування", ["EN"] = "Block Minutes" },
            
            ["MSG_NO_BLOCKED_IPS"] = new Dictionary<string, string> { ["UA"] = "(немає заблокованих IP)", ["EN"] = "(no blocked IPs)" },
            ["MSG_NO_WHITELISTED_IPS"] = new Dictionary<string, string> { ["UA"] = "(немає IP у білому списку)", ["EN"] = "(no whitelisted IPs)" },
            
            ["LABEL_BLOCK_DURATION_FULL"] = new Dictionary<string, string> { ["UA"] = "Тривалість блокування (хвилини):", ["EN"] = "Block Duration (minutes):" },
            ["LABEL_RDP_PORT"] = new Dictionary<string, string> { ["UA"] = "Порт RDP:", ["EN"] = "RDP Port:" },
            ["LABEL_BLOCK_LEVELS_TABLE"] = new Dictionary<string, string> { ["UA"] = "Рівні блокування (Спроби → Хвилини):", ["EN"] = "Block Levels (Attempts – Minutes):" },
            ["LABEL_FAILED_ATTEMPTS_WINDOW_DAYS"] = new Dictionary<string, string> { ["UA"] = "Термін життя невдалої спроби (днів):", ["EN"] = "Failed attempt lifetime (days):" },
            ["COL_ATTEMPTS"] = new Dictionary<string, string> { ["UA"] = "Спроби", ["EN"] = "Attempts" },
            ["COL_BLOCK_MINUTES"] = new Dictionary<string, string> { ["UA"] = "Хвилини блокування", ["EN"] = "Block Minutes" },

            ["ANTI_BRUTE_SECTION"] = new Dictionary<string, string> { ["UA"] = "Anti-Brute (MVP)", ["EN"] = "Anti-Brute (MVP)" },
            ["ANTI_BRUTE_ENABLED"] = new Dictionary<string, string> { ["UA"] = "Увімкнути anti-brute", ["EN"] = "Enable anti-brute" },
            ["ANTI_BRUTE_ENABLED_SHORT"] = new Dictionary<string, string> { ["UA"] = "Увімкнено", ["EN"] = "Enabled" },
            ["ANTI_BRUTE_SPRAY"] = new Dictionary<string, string> { ["UA"] = "Spray-детект (багато IP на одного юзера)", ["EN"] = "Spray detection (many IPs to one user)" },
            ["ANTI_BRUTE_IP_ABUSE"] = new Dictionary<string, string> { ["UA"] = "IP abuse (різні логіни з одного IP)", ["EN"] = "IP abuse (different logins from one IP)" },
            ["ANTI_BRUTE_RECURRENCE"] = new Dictionary<string, string> { ["UA"] = "Рецидив IP (множник часу бану)", ["EN"] = "IP recurrence (ban multiplier)" },
            ["ANTI_BRUTE_SUBNET"] = new Dictionary<string, string> { ["UA"] = "Ескалація до /24 підмережі", ["EN"] = "Escalation to /24 subnet" },
            ["ANTI_BRUTE_WINDOW_MIN"] = new Dictionary<string, string> { ["UA"] = "Вікно (хв):", ["EN"] = "Window (min):" },
            ["ANTI_BRUTE_UNIQUE_IPS"] = new Dictionary<string, string> { ["UA"] = "Поріг унікальних IP:", ["EN"] = "Unique IP threshold:" },
            ["ANTI_BRUTE_UNIQUE_USERS"] = new Dictionary<string, string> { ["UA"] = "Поріг різних логінів:", ["EN"] = "Distinct users threshold:" },
            ["ANTI_BRUTE_BLOCK_MIN"] = new Dictionary<string, string> { ["UA"] = "Блок (хв):", ["EN"] = "Block (min):" },
            ["ANTI_BRUTE_LOOKBACK_H"] = new Dictionary<string, string> { ["UA"] = "Історія (год):", ["EN"] = "Lookback (hours):" },
            ["ANTI_BRUTE_STEP"] = new Dictionary<string, string> { ["UA"] = "Крок множника:", ["EN"] = "Step multiplier:" },
            ["ANTI_BRUTE_MAX"] = new Dictionary<string, string> { ["UA"] = "Макс. множник:", ["EN"] = "Max multiplier:" },
            ["ANTI_BRUTE_HELP_OVERVIEW"] = new Dictionary<string, string>
            {
                ["UA"] = "Anti-Brute аналізує невдалі входи та застосовує додаткові правила блокування поверх базових рівнів.",
                ["EN"] = "Anti-Brute analyzes failed logons and applies additional blocking rules on top of base levels."
            },
            ["ANTI_BRUTE_HELP_SPRAY"] = new Dictionary<string, string>
            {
                ["UA"] = "Spray-детект: якщо за вікно часу один логін атакують з багатьох різних IP, джерела блокуються на вказаний час.",
                ["EN"] = "Spray detection: if one username is attacked from many different IPs within the time window, source IPs are blocked for the configured duration."
            },
            ["ANTI_BRUTE_HELP_IP_ABUSE"] = new Dictionary<string, string>
            {
                ["UA"] = "IP abuse: якщо один IP перебирає багато різних логінів за вікно часу, IP блокується як підозрілий.",
                ["EN"] = "IP abuse: if one IP attempts many different usernames within the time window, that IP is blocked as suspicious."
            },
            ["ANTI_BRUTE_HELP_RECURRENCE"] = new Dictionary<string, string>
            {
                ["UA"] = "Рецидив: для IP з повторними атаками час бану множиться (step), але не перевищує max multiplier.",
                ["EN"] = "Recurrence: for repeating offender IPs, ban duration is multiplied by step but capped by max multiplier."
            },
            ["ANTI_BRUTE_HELP_SUBNET"] = new Dictionary<string, string>
            {
                ["UA"] = "Ескалація /24: якщо в одній /24 підмережі багато різних атакуючих IP, може застосовуватися блокування всієї підмережі.",
                ["EN"] = "Subnet /24 escalation: if many different attacking IPs appear within one /24 subnet, the whole subnet can be blocked."
            },

            ["IFACE_HEADER"] = new Dictionary<string, string> { ["UA"] = "Інтерфейси прослуховування RDP", ["EN"] = "RDP Listening Interfaces" },
            ["IFACE_HINT"] = new Dictionary<string, string> { ["UA"] = "Відмітьте інтерфейси, для яких застосовується моніторинг порту.", ["EN"] = "Select interfaces where port monitoring will be applied." },
            ["IFACE_COL_ENABLED"] = new Dictionary<string, string> { ["UA"] = "Слухати", ["EN"] = "Listen" },
            ["IFACE_COL_IP"] = new Dictionary<string, string> { ["UA"] = "IP-адреса", ["EN"] = "IP Address" },
            ["IFACE_COL_NAME"] = new Dictionary<string, string> { ["UA"] = "Інтерфейс", ["EN"] = "Interface" },
            ["IFACE_BTN_RELOAD"] = new Dictionary<string, string> { ["UA"] = "Оновити список", ["EN"] = "Reload List" },
            ["IFACE_BTN_SAVE"] = new Dictionary<string, string> { ["UA"] = "Зберегти інтерфейси", ["EN"] = "Save Interfaces" },
            
            // Telegram notifications
            ["TELEGRAM_SECTION_HEADER"] = new Dictionary<string, string> { ["UA"] = "Налаштування Telegram сповіщень", ["EN"] = "Telegram Notifications Settings" },
            ["TELEGRAM_ENABLE"] = new Dictionary<string, string> { ["UA"] = "Увімкнути Telegram сповіщення", ["EN"] = "Enable Telegram Notifications" },
            ["TELEGRAM_BOT_TOKEN"] = new Dictionary<string, string> { ["UA"] = "Bot Token:", ["EN"] = "Bot Token:" },
            ["TELEGRAM_CHAT_ID"] = new Dictionary<string, string> { ["UA"] = "Chat ID:", ["EN"] = "Chat ID:" },
            ["TELEGRAM_BOT_TOKEN_PLACEHOLDER"] = new Dictionary<string, string> { ["UA"] = "Вставте токен бота (від @BotFather)", ["EN"] = "Paste bot token (from @BotFather)" },
            ["TELEGRAM_CHAT_ID_PLACEHOLDER"] = new Dictionary<string, string> { ["UA"] = "Вставте Chat ID", ["EN"] = "Paste Chat ID" },
            ["TELEGRAM_TEST_BUTTON"] = new Dictionary<string, string> { ["UA"] = "Тестове повідомлення", ["EN"] = "Test Message" },
            ["TELEGRAM_SAVE_BUTTON"] = new Dictionary<string, string> { ["UA"] = "Зберегти налаштування", ["EN"] = "Save Settings" },
            ["TELEGRAM_HELP_TITLE"] = new Dictionary<string, string> { ["UA"] = "Як налаштувати Telegram бота:", ["EN"] = "How to setup Telegram bot:" },
            ["TELEGRAM_HELP_STEP1"] = new Dictionary<string, string> { ["UA"] = "1. Знайдіть @BotFather в Telegram", ["EN"] = "1. Find @BotFather in Telegram" },
            ["TELEGRAM_HELP_STEP2"] = new Dictionary<string, string> { ["UA"] = "2. Надішліть /newbot і дотримуйтесь інструкцій", ["EN"] = "2. Send /newbot and follow instructions" },
            ["TELEGRAM_HELP_STEP3"] = new Dictionary<string, string> { ["UA"] = "3. Скопіюйте Bot Token і вставте вище", ["EN"] = "3. Copy Bot Token and paste above" },
            ["TELEGRAM_HELP_STEP4"] = new Dictionary<string, string> { ["UA"] = "4. Знайдіть @userinfobot щоб дізнатись свій Chat ID", ["EN"] = "4. Find @userinfobot to get your Chat ID" },
            ["TELEGRAM_HELP_STEP5"] = new Dictionary<string, string> { ["UA"] = "5. Натисніть 'Тестове повідомлення' для перевірки", ["EN"] = "5. Click 'Test Message' to verify" },
            ["TELEGRAM_STATUS_DISABLED"] = new Dictionary<string, string> { ["UA"] = "Вимкнено", ["EN"] = "Disabled" },
            ["TELEGRAM_STATUS_ENABLED"] = new Dictionary<string, string> { ["UA"] = "Увімкнено", ["EN"] = "Enabled" },
            ["TELEGRAM_TEST_SUCCESS"] = new Dictionary<string, string> { ["UA"] = "Тестове повідомлення надіслано!", ["EN"] = "Test message sent!" },
            ["TELEGRAM_TEST_FAIL"] = new Dictionary<string, string> { ["UA"] = "Помилка відправки. Перевірте налаштування.", ["EN"] = "Send failed. Check settings." },
            ["TELEGRAM_SAVE_SUCCESS"] = new Dictionary<string, string> { ["UA"] = "Налаштування збережено!", ["EN"] = "Settings saved!" },
            ["TELEGRAM_SAVE_FAIL"] = new Dictionary<string, string> { ["UA"] = "Помилка збереження!", ["EN"] = "Save failed!" },
            ["TELEGRAM_MESSAGE_TEMPLATES"] = new Dictionary<string, string> { ["UA"] = "Шаблони повідомлень для рівнів блокування:", ["EN"] = "Message Templates for Block Levels:" },
            ["TELEGRAM_TEMPLATE_LEVEL"] = new Dictionary<string, string> { ["UA"] = "Рівень", ["EN"] = "Level" },
            ["TELEGRAM_TEMPLATE_DEFAULT"] = new Dictionary<string, string> { ["UA"] = "Шаблон за замовчуванням:", ["EN"] = "Default Template:" },
            ["TELEGRAM_PLACEHOLDERS"] = new Dictionary<string, string> { ["UA"] = "Доступні змінні: {ip}, {attempts}, {duration}", ["EN"] = "Available variables: {ip}, {attempts}, {duration}" },
            ["MSG_SETTINGS_HEADER"] = new Dictionary<string, string> { ["UA"] = "Налаштування Telegram сповіщень", ["EN"] = "Telegram Notification Settings" },
            ["MSG_SETTINGS_MONITOR"] = new Dictionary<string, string> { ["UA"] = "Монітор", ["EN"] = "Monitor" },
            ["MSG_SETTINGS_MONITOR_START"] = new Dictionary<string, string> { ["UA"] = "Надсилати при запуску монітора", ["EN"] = "Notify on monitor start" },
            ["MSG_SETTINGS_MONITOR_CLOSE"] = new Dictionary<string, string> { ["UA"] = "Надсилати при закритті монітора", ["EN"] = "Notify on monitor close" },
            ["MSG_SETTINGS_SERVICE"] = new Dictionary<string, string> { ["UA"] = "Служба", ["EN"] = "Service" },
            ["MSG_SETTINGS_SERVICE_START"] = new Dictionary<string, string> { ["UA"] = "Надсилати при старті служби", ["EN"] = "Notify on service start" },
            ["MSG_SETTINGS_SERVICE_STOP"] = new Dictionary<string, string> { ["UA"] = "Надсилати при зупинці служби", ["EN"] = "Notify on service stop" },
            ["MSG_SETTINGS_CONFIG_SAVE"] = new Dictionary<string, string> { ["UA"] = "Надсилати при збереженні конфігу", ["EN"] = "Notify on config save" },
            ["MSG_SETTINGS_SAVE_BTN"] = new Dictionary<string, string> { ["UA"] = "Зберегти налаштування", ["EN"] = "Save Settings" },        };

        public static string Get(string key)
        {
            string lang = Program.CurrentLanguage;
            if (translations.ContainsKey(key) && translations[key].ContainsKey(lang))
                return translations[key][lang];
            
            // Fallback to EN
            if (translations.ContainsKey(key) && translations[key].ContainsKey("EN"))
                return translations[key]["EN"];
                
            return key; // Fallback to key itself
        }
    }
}

