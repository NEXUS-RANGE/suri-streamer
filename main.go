// Команда agent — сервис-агент, который читает алерты Suricata из eve.json
// (в режиме tail: только новые строки с конца файла) и транслирует их
// подключённым веб-клиентам по протоколу SSE (Server-Sent Events).
//
// Запуск:
//
//	agent -file /var/log/suricata/eve.json -addr :8080
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ---------------------------------------------------------------------------
// Модель данных
// ---------------------------------------------------------------------------

// eveEvent — та часть структуры события Suricata, которая нам интересна.
// Поля, не описанные здесь, при разборе JSON просто игнорируются.
type eveEvent struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	DestPort  int    `json:"dest_port"`
	Alert     *struct {
		Signature string `json:"signature"`
		Severity  int    `json:"severity"`
	} `json:"alert"`
}

// AlertPayload — компактная схема, которую отправляем браузеру (по ТЗ).
type AlertPayload struct {
	Timestamp string `json:"timestamp"`
	SourceIP  string `json:"source_ip"`
	DestPort  int    `json:"dest_port"`
	Signature string `json:"signature"`
	Severity  int    `json:"severity"`
}

// parseLine разбирает одну строку eve.json. Возвращает (payload, true) только
// если это событие-алерт; прочие типы (dns, http, flow, stats...) — пропускает.
func parseLine(line string) (AlertPayload, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return AlertPayload{}, false
	}
	var ev eveEvent
	if err := json.Unmarshal([]byte(line), &ev); err != nil {
		// Строка могла оказаться обрезанной (например, лог дописывался
		// в момент чтения). Не алерт — просто пропускаем.
		return AlertPayload{}, false
	}
	if ev.EventType != "alert" || ev.Alert == nil {
		return AlertPayload{}, false
	}
	return AlertPayload{
		Timestamp: normalizeTimestamp(ev.Timestamp),
		SourceIP:  ev.SrcIP,
		DestPort:  ev.DestPort,
		Signature: ev.Alert.Signature,
		Severity:  ev.Alert.Severity,
	}, true
}

// normalizeTimestamp приводит timestamp Suricata ("...+0000") к формату
// из ТЗ ("...Z"). Если разобрать не удалось — возвращает строку как есть.
func normalizeTimestamp(s string) string {
	t, err := time.Parse("2006-01-02T15:04:05.999999999-0700", s)
	if err != nil {
		return s
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// ---------------------------------------------------------------------------
// Hub — мультиплексор SSE-клиентов (fan-out)
// ---------------------------------------------------------------------------

// Hub в единственном экземпляре хранит каналы всех подключённых клиентов
// и дублирует каждый новый алерт во все активные SSE-соединения.
type Hub struct {
	mu      sync.Mutex
	clients map[chan []byte]struct{}
}

func NewHub() *Hub {
	return &Hub{clients: make(map[chan []byte]struct{})}
}

// Len возвращает текущее число подключённых клиентов.
func (h *Hub) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

// Subscribe регистрирует нового клиента и возвращает его персональный канал.
func (h *Hub) Subscribe() chan []byte {
	// Буфер на случай кратковременно медленного клиента,
	// чтобы одна медленная вкладка не тормозила остальных.
	ch := make(chan []byte, 256)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	n := len(h.clients)
	h.mu.Unlock()
	log.Printf("клиент подключился, всего клиентов: %d", n)
	return ch
}

// Unsubscribe отписывает клиента и закрывает его канал (освобождает ресурсы).
func (h *Hub) Unsubscribe(ch chan []byte) {
	h.mu.Lock()
	if _, ok := h.clients[ch]; ok {
		delete(h.clients, ch)
		close(ch)
	}
	n := len(h.clients)
	h.mu.Unlock()
	log.Printf("клиент отключился, осталось клиентов: %d", n)
}

// Broadcast сериализует payload и рассылает его всем подключённым клиентам.
func (h *Hub) Broadcast(payload AlertPayload) {
	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("ошибка сериализации payload: %v", err)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.clients {
		select {
		case ch <- data:
		default:
			// Буфер клиента переполнен (очень медленный потребитель) —
			// дропаем сообщение, чтобы не блокировать fan-out для всех.
			log.Printf("предупреждение: клиент не успевает, сообщение сброшено")
		}
	}
}

// HandleEvents обслуживает GET /events — SSE-эндпоинт.
func (h *Hub) HandleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Обязательные заголовки SSE + CORS (по ТЗ).
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch := h.Subscribe()
	// defer сработает при любом выходе из функции (в т.ч. при обрыве
	// соединения клиентом) — гарантированная очистка ресурсов.
	defer h.Unsubscribe(ch)

	// Подсказка браузеру: при обрыве соединения переподключаться через 3 с.
	fmt.Fprint(w, "retry: 3000\n\n")
	flusher.Flush()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	ctx := r.Context() // отменяется, когда клиент отключился (закрыл вкладку)
	for {
		select {
		case data, ok := <-ch:
			if !ok {
				return // канал закрыт — завершаем стрим
			}
			// Формат кадра SSE: "data: <json>\n\n"
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush() // отправляем сразу, не копим в буфере
		case <-heartbeat.C:
			// Комментарий SSE (строка с ':') — поддерживает соединение
			// живым в периоды без алертов.
			fmt.Fprint(w, ": heartbeat\n\n")
			flusher.Flush()
		case <-ctx.Done():
			return // клиент отключился
		}
	}
}

// ---------------------------------------------------------------------------
// Tailer — чтение лога «с конца», как tail -f
// ---------------------------------------------------------------------------

// pollInterval — как часто перечитывать файл, когда новых данных нет.
const pollInterval = 250 * time.Millisecond

type Tailer struct {
	path    string
	onEvent func(AlertPayload)
}

func NewTailer(path string, onEvent func(AlertPayload)) *Tailer {
	return &Tailer{path: path, onEvent: onEvent}
}

// Run — внешний цикл: открывает файл и «следит» за ним; при ротации
// (файл пересоздан, обрезан или удалён) открывает его заново.
// Работает, пока не отменён ctx.
func (t *Tailer) Run(ctx context.Context) {
	// Пропускаем историю только если файл уже существовал на момент старта
	// агента. Файл, созданный позже (Suricata стартовала после нас),
	// читается с самого начала — из него ничего не теряем.
	_, statErr := os.Stat(t.path)
	skipHistory := statErr == nil
	for {
		if ctx.Err() != nil {
			return
		}
		f, err := os.Open(t.path)
		if err != nil {
			// Файла ещё нет (например, Suricata не стартовала) — ждём.
			log.Printf("файл %s недоступен (%v), повторю через %v", t.path, err, pollInterval)
			if !sleepCtx(ctx, pollInterval) {
				return
			}
			continue
		}
		if skipHistory {
			// При первом старте перематываемся в конец: историю не
			// перечитываем (требование ТЗ), ждём только новые строки.
			if st, err := f.Stat(); err == nil && st.Size() > 0 {
				f.Seek(0, io.SeekEnd)
				log.Printf("история файла пропущена (%d байт), читаю только новые строки", st.Size())
			}
			skipHistory = false
		}
		t.follow(ctx, f)
		f.Close()
		if ctx.Err() != nil {
			return
		}
		log.Printf("переоткрываю файл %s", t.path)
	}
}

// follow читает новые строки из открытого файла до отмены ctx или до
// обнаружения ротации. Возвращает true, если файл нужно переоткрыть.
func (t *Tailer) follow(ctx context.Context, f *os.File) bool {
	reader := bufio.NewReader(f)
	offset, _ := f.Seek(0, io.SeekCurrent) // сколько байт уже прочитано
	info, err := f.Stat()
	if err != nil {
		log.Printf("ошибка stat: %v", err)
		return true
	}
	var partial string // начало строки, ещё не завершённой переводом строки

	for {
		chunk, err := reader.ReadString('\n')
		if chunk != "" {
			offset += int64(len(chunk))
			partial += chunk
		}
		if err == nil {
			// Прочитана полная строка — обрабатываем.
			t.handleLine(strings.TrimSuffix(partial, "\n"))
			partial = ""
			continue // в буфере могли остаться ещё строки
		}
		if err != io.EOF {
			log.Printf("ошибка чтения файла: %v", err)
			return true // переоткроем файл
		}
		// Достигли конца файла. Проверяем, не произошла ли ротация.
		if t.rotated(info, offset) {
			return true
		}
		// Новых данных нет — короткий сон (прерывается по ctx).
		if !sleepCtx(ctx, pollInterval) {
			return false
		}
	}
}

// rotated определяет ротацию лога по двум признакам:
//  1. файл пересоздан: по пути лежит другой файл (иной inode), чем наш
//     открытый дескриптор (сценарий logrotate create + reopen у Suricata);
//  2. файл обрезан: размер стал меньше прочитанной позиции (copytruncate).
func (t *Tailer) rotated(oldInfo os.FileInfo, offset int64) bool {
	newInfo, err := os.Stat(t.path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("файл %s исчез (ротация/удаление)", t.path)
		} else {
			log.Printf("ошибка stat %s: %v", t.path, err)
		}
		return true
	}
	if !os.SameFile(oldInfo, newInfo) {
		log.Printf("ротация: файл %s пересоздан", t.path)
		return true
	}
	if newInfo.Size() < offset {
		log.Printf("ротация: файл %s обрезан (было прочитано %d байт, размер стал %d)",
			t.path, offset, newInfo.Size())
		return true
	}
	return false
}

// handleLine фильтрует строку и передаёт алерт в callback.
func (t *Tailer) handleLine(line string) {
	payload, ok := parseLine(line)
	if !ok {
		return // не алерт (или мусор) — игнорируем
	}
	t.onEvent(payload)
}

// sleepCtx — сон, прерываемый отменой контекста.
// Возвращает false, если контекст отменён.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// ---------------------------------------------------------------------------
// main — сборка всего вместе
// ---------------------------------------------------------------------------

func main() {
	log.SetFlags(log.LstdFlags)

	filePath := flag.String("file", "/var/log/suricata/eve.json", "путь к eve.json (лог Suricata)")
	addr := flag.String("addr", ":8080", "адрес HTTP-сервера (SSE)")
	flag.Parse()

	// Контекст отменяется по Ctrl+C / SIGTERM — корректное завершение.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hub := NewHub()

	// ЕДИНСТВЕННЫЙ читатель файла (fan-out делает Hub, а не несколько tailer'ов).
	tailer := NewTailer(*filePath, func(p AlertPayload) {
		log.Printf("алерт: src=%s dport=%d sev=%d sig=%q",
			p.SourceIP, p.DestPort, p.Severity, p.Signature)
		hub.Broadcast(p)
	})
	go tailer.Run(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/events", hub.HandleEvents)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fmt.Fprintf(w, `{"status":"ok","clients":%d}`, hub.Len())
	})

	srv := &http.Server{Addr: *addr, Handler: mux}
	go func() {
		<-ctx.Done()
		log.Printf("получен сигнал завершения, останавливаюсь...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	log.Printf("SSE-агент запущен: http://localhost%s/events, файл: %s", *addr, *filePath)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("ошибка HTTP-сервера: %v", err)
	}
	log.Printf("завершение работы")
}
