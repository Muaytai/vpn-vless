# vpn-vless

Инструмент для развёртывания и управления личным VPN-сервером на протоколе
**VLESS + REALITY**. Предназначен для команды, которой нужен стабильный доступ
к ИИ-сервисам и инструментам через европейский сервер.

REALITY маскирует VPN-трафик под обычное TLS-соединение с популярным сайтом,
делая его неотличимым от обычного HTTPS. Не требует покупки домена или сертификата.

## Требования

| Компонент | Версия |
|-----------|--------|
| **Сервер** | Linux (Debian/Ubuntu), Go 1.26+, systemd |
| **Клиент** | Любой клиент с поддержкой VLESS + REALITY |

Рекомендуемые клиенты:

- **Windows / macOS**: [v2rayN](https://github.com/2dust/v2rayN), [Hiddify](https://github.com/hiddify/hiddify-app)
- **Linux**: [NekoBox](https://github.com/MatsuriDayo/NekoBoxForAndroid), Xray-core напрямую
- **Android**: [v2rayNG](https://github.com/2dust/v2rayNG), Hiddify
- **iOS**: [Streisand](https://apps.apple.com/app/streisand/id6450534064), [FoXray](https://apps.apple.com/app/foxray/id6448898396)

## Быстрый старт

### Установка на сервере

```sh
git clone https://github.com/Muaytai/vpn-vless.git
cd vpn-vless
sudo ./deploy/install.sh
```

Скрипт устанавливает Xray, `vpnctl`, создаёт системную группу и сервис.
При ошибке все изменения откатываются автоматически.

### Настройка

```sh
# Инициализация (замените IP на адрес вашего европейского сервера)
sudo vpnctl init --endpoint 203.0.113.42 --port 443

# Добавление членов команды
sudo vpnctl user add alice
sudo vpnctl user add bob

# Применение конфигурации и запуск
sudo vpnctl server apply

# Получение ссылки для клиента
sudo vpnctl user link alice

# Или полной конфигурации Xray (с настраиваемым SOCKS-портом)
sudo vpnctl user client alice
sudo vpnctl user client --socks-port 9050 bob
```

### Подключение

Скопируйте VLESS-ссылку из `vpnctl user link` в клиент. Готово.

## Команды

```
vpnctl init --endpoint HOST [--port 443] [--reality-host DOMAIN]
                              инициализация сервера

vpnctl user add NAME          добавить пользователя
vpnctl user list              список пользователей и их статусов
vpnctl user revoke NAME       отозвать доступ пользователя
vpnctl user link NAME         VLESS-ссылка для подключения
vpnctl user client [--socks-port PORT] NAME
                              конфигурация Xray-клиента (SOCKS, по умолчанию 1080)

vpnctl server render          показать конфигурацию сервера
vpnctl server apply           проверить и применить конфигурацию (нужен root)
```

После `user add` или `user revoke` необходимо выполнить `server apply`,
чтобы изменения вступили в силу.

## Архитектура

```
vpn-vless/
├── cmd/vpnctl/          CLI-интерфейс, точка входа
├── internal/
│   ├── model/           типы данных (Server, User)
│   ├── store/           SQLite-хранилище с проверками безопасности
│   ├── configgen/       генерация конфигураций Xray и VLESS-ссылок
│   └── apply/           применение конфигурации через systemd
└── deploy/
    ├── install.sh       установщик с полным откатом при ошибке
    └── vpn-vless.service   systemd unit с песочницей
```

## Безопасность

- Данные хранятся в `/var/lib/vpn-vless` (права `0700`), конфигурация — в
  `/etc/vpn-vless` (доступ только root и группе `vpn-vless`)
- SQLite: права файла `0600`, WAL mode, проверка владельца и прав на Linux
- Xray запускается под выделенным пользователем `vpn-vless` с минимальными
  привилегиями и песочницей systemd (`ProtectSystem=strict`, `NoNewPrivileges`,
  `PrivateTmp`, `SystemCallFilter` и др.)
- Маршрутизация на сервере блокирует доступ к приватным IP-диапазонам
  (127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16, fc00::/7 и др.)
- Файловая блокировка (`flock`) предотвращает одновременные мутации
- Ссылки и конфигурации содержат секреты — не передавайте их по открытым каналам

## Переменные окружения

| Переменная | Описание | По умолчанию |
|-----------|----------|-------------|
| `VPN_DATA_DIR` | Каталог данных | `/var/lib/vpn-vless` (Linux), `./data` (Windows) |

## Разработка

```sh
# Тесты
go test ./... -v

# С race detector
go test -race -count=1 ./...

# Линтер
go vet ./...

# Интеграционные тесты с Xray (опционально)
XRAY_INTEGRATION=1 XRAY_TEST_BINARY=/path/to/xray go test ./cmd/vpnctl -v -run TestXray

# Тесты инсталлятора
python deploy/install_test.py
```

