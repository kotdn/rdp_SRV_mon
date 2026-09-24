# Готовая сборка

Самодостаточные (self-contained, .NET runtime уже внутри — отдельно ставить не нужно) билды `WinService` и `RDPMonitor` под win-x64, собранные из исходников этого репозитория.

## Установка

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
cd Install
.\install.ps1 -StartMonitor
```

Запускать от администратора. `-StartMonitor` — сразу открыть GUI-монитор после установки службы (можно опустить и запустить его позже вручную/ярлыком).

Перед установкой скрипт определяет страну по IP (через ip-api.com) и продолжает только для Украины; если сервис геолокации недоступен — предупреждает и всё равно продолжает установку. Флаг `-SkipGeoCheck` полностью отключает эту проверку.

Скрипт: останавливает и удаляет предыдущую версию службы (если есть), распаковывает `WinService.zip`/`RDPMonitor.zip` в `C:\Program Files\RDPSecurityService`, регистрирует и запускает службу `RDPSecurityService`, создаёт ярлыки монитора на рабочем столе и в меню Пуск. Конфиг и логи — в `C:\ProgramData\RDPSecurityService` (не трогаются при переустановке).

## Обновление до новой версии

Просто запустите `install.ps1` снова из свежераспакованного пакета — старая служба будет корректно остановлена и заменена, firewall-правила и конфиг сохраняются.

## Собрать самому вместо готового пакета

```powershell
cd WinService
dotnet publish -c Release -r win-x64 --self-contained true -o out
cd ..\monitor
dotnet publish -c Release -r win-x64 --self-contained true -o out
```
