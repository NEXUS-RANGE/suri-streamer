# suri-streamer

Сервис-агент на Go (без внешних зависимостей, только стандартная библиотека),
который потоково читает алерты Suricata из `eve.json` и транслирует их
в веб-интерфейс по протоколу SSE (Server-Sent Events).

## Покрытие требований

| Требование | Реализация |
|---|---|
| Чтение лога с конца (как `tail -f`), без перечитывания целиком | `Tailer`: при старте seek в EOF, опрос 250 мс, незавершённые строки буферизуются |
| Учёт ротации логов (logrotate create / copytruncate / удаление) | Детекция по смене inode (`os.SameFile`) и по уменьшению размера; автопереоткрытие файла |
| Обрабатывать только `"event_type": "alert"` | `parseLine`: прочие типы событий (dns, http, flow, stats...) игнорируются |
| Компактная исходящая схема | `AlertPayload`: `timestamp`, `source_ip`, `dest_port`, `signature`, `severity`; timestamp нормализуется к RFC3339 (`...Z`) |
| `GET /events`, `Content-Type: text/event-stream`, `Cache-Control: no-cache` | `HandleEvents` |
| CORS `Access-Control-Allow-Origin: *` | выставляется на `/events` и `/health` |
| Fan-out: один читатель файла — много клиентов | `Hub`: карта каналов клиентов, `Broadcast` дублирует алерт во все активные SSE |
| Корректное закрытие стрима и очистка ресурсов при отключении клиента | `r.Context().Done()` + `defer Unsubscribe` |
| Устойчивость длинных соединений | SSE-комментарий `: heartbeat` каждые 15 с, `retry: 3000` для автопереподключения браузера |

## Архитектура
eve.json -> Tailer (единственный читатель) -> parseLine (фильтр alert)
-> Hub.Broadcast -> канал клиента 1 -> SSE-кадр "data: {...}\n\n"
-> канал клиента 2 -> ...


## Сборка и запуск

Требуется Go >= 1.22, зависимостей нет.

    go build -o agent .
    ./agent -file /var/log/suricata/eve.json -addr :8080

| Флаг | По умолчанию | Назначение |
|---|---|---|
| `-file` | `/var/log/suricata/eve.json` | путь к eve.json |
| `-addr` | `:8080` | адрес HTTP-сервера |

Эндпоинты: `GET /events` — SSE-поток алертов; `GET /health` — `{"status":"ok","clients":N}`.

Кросс-сборка под Linux с любой машины: `GOOS=linux GOARCH=amd64 go build -o agent-linux-amd64 .`

## Тестовая среда (Docker, живой Suricata не обязателен)

    testenv/gen-pcap.sh   # записать тестовый трафик (ping + HTTP) в pcaps/test.pcap
    testenv/replay.sh     # прогнать pcap через Suricata в контейнере -> дописать алерты в logs/eve.json

Наглядная веб-страница (EventSource + таблица алертов):

    python3 -m http.server 3000 --directory testenv
    # в браузере: http://localhost:3000/sse-test.html?port=<порт агента>

### Ручной прогон (4 терминала)

1. `./agent -file ./logs/eve.json -addr :8081`
2. `curl -N -i http://localhost:8081/events`
3. генератор: `echo '{"timestamp":"2026-09-24T12:00:02.123456+0000","event_type":"alert","src_ip":"192.168.1.50","dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":1000003,"rev":1,"signature":"ET SCAN Potential SSH Scan","category":"","severity":1}}' >> logs/eve.json`
   (не-алерт для проверки фильтра: `{"timestamp":"...","event_type":"dns","src_ip":"1.2.3.4","dest_port":53}`)
4. `python3 -m http.server 3000 --directory testenv` + открыть страницу в браузере (в двух вкладках — виден fan-out)

Ротация:

    mv logs/eve.json logs/eve.json.1 && touch logs/eve.json && echo '<алерт>' >> logs/eve.json
    : > logs/eve.json && sleep 1 && echo '<алерт>' >> logs/eve.json

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

## Структура репозитория

    .
    ├── main.go               # весь агент: Tailer, Hub, SSE-обработчик
    ├── go.mod
    ├── Dockerfile            # multi-stage сборка агента
    ├── docker-compose.yml    # suricata-replay + agent
    ├── .gitignore
    ├── README.md
    └── testenv/
        ├── Dockerfile        # Ubuntu 24.04 + Suricata (для replay)
        ├── rules/test.rules  # 3 правила для тестового трафика
        ├── gen-pcap.sh       # запись тестового трафика в pcap
        ├── replay.sh         # pcap -> Suricata -> logs/eve.json
        └── sse-test.html     # наглядная страница с EventSource
