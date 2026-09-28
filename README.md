# suri-streamer

Сервис-агент на Go (без внешних зависимостей, только стандартная библиотека),
который потоково читает алерты Suricata из `eve.json` и транслирует их
в веб-интерфейс по протоколу SSE (Server-Sent Events).

## Покрытие требований


| Требование                                                                                                             | Реализация                                                                                                                            |
| -------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Чтение лога с конца (как`tail -f`), без перечитывания целиком                          | `Tailer`: при старте seek в EOF, опрос 250 мс, незавершённые строки буферизуются                |
| Учёт ротации логов (logrotate create / copytruncate / удаление)                                          | Детекция по смене inode (`os.SameFile`) и по уменьшению размера; автопереоткрытие файла |
| Обрабатывать только`"event_type": "alert"`                                                                     | `parseLine`: прочие типы событий (dns, http, flow, stats...) игнорируются                                          |
| Компактная исходящая схема                                                                               | `AlertPayload`: `timestamp`, `source_ip`, `dest_port`, `signature`, `severity`; timestamp нормализуется к RFC3339 (`...Z`)        |
| `GET /events`, `Content-Type: text/event-stream`, `Cache-Control: no-cache`                                                      | `HandleEvents`                                                                                                                                  |
| CORS`Access-Control-Allow-Origin: *`                                                                                             | выставляется на`/events` и `/health`                                                                                             |
| Fan-out: один читатель файла — много клиентов                                                     | `Hub`: карта каналов клиентов, `Broadcast` дублирует алерт во все активные SSE                   |
| Корректное закрытие стрима и очистка ресурсов при отключении клиента | `r.Context().Done()` + `defer Unsubscribe`                                                                                                      |
| Устойчивость длинных соединений                                                                     | SSE-комментарий`: heartbeat` каждые 15 с, `retry: 3000` для автопереподключения браузера        |

## Архитектура

eve.json -> Tailer (единственный читатель) -> parseLine (фильтр alert)
-> Hub.Broadcast -> канал клиента 1 -> SSE-кадр "data: {...}\n\n"
-> канал клиента 2 -> ...

## Сборка и запуск

Требуется Go >= 1.22, зависимостей нет.

go build -o agent .
./agent -file /var/log/suricata/eve.json -addr :8080


| Флаг | По умолчанию      | Назначение           |
| -------- | ---------------------------- | ------------------------------ |
| `-file`  | `/var/log/suricata/eve.json` | путь к eve.json           |
| `-addr`  | `:8080`                      | адрес HTTP-сервера |

Эндпоинты: `GET /events` — SSE-поток алертов; `GET /health` — `{"status":"ok","clients":N}`.

Кросс-сборка под Linux с любой машины: `GOOS=linux GOARCH=amd64 go build -o agent-linux-amd64 .`

## Развёртывание

### Linux, нативно

Скопировать бинарник (или собрать на месте), пример systemd-юнита `/etc/systemd/system/suri-streamer.service`:

[Unit]
Description=Suricata alerts SSE agent
After=network.target

[Service]
ExecStart=/usr/local/bin/agent -file /var/log/suricata/eve.json -addr :8080
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
Важно: `/var/log/suricata/eve.json` обычно принадлежит root с правами 640 —
запускайте сервис от root или добавьте пользователя в группу владельца лога.

### Docker

docker compose up --build

# SSE: http://localhost:8080/events

Compose поднимает `suricata-replay` (одноразовый прогон pcap, пишет `logs/eve.json`)
и `agent` (ждёт файл, читает и стримит наружу).
