// sameday-sms-screener: inbound SMS screening proxy for Patriot Pest Control.
//
// Twilio number webhook -> this service -> classify -> forward to Sameday AI
// (normal) or hold (bizarre). Held messages surface to David for approval.
//
// Modes (SCREENER_MODE): observe = log and forward everything (default),
// hold = drop bizarre inbound instead of forwarding to Sameday.
//
// Stdlib only. JSONL event log at DATA_DIR/screener.log.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Port          string
	Mode          string // observe | hold
	UpstreamURL   string // Sameday AI SMS webhook; empty = no forwarding
	AuthToken     string // Twilio auth token for signature validation; empty = skip
	Blocklist     map[string]bool
	DataDir       string
	PublicBaseURL string // e.g. https://sms-screen.itak.live, used for signature validation
}

type Event struct {
	Time      time.Time `json:"time"`
	Type      string    `json:"type"` // inbound | hold | forward | replay | block
	From      string    `json:"from"`
	To        string    `json:"to"`
	Body      string    `json:"body"`
	Class     string    `json:"class"`
	Reason    string    `json:"reason"`
	Forwarded bool      `json:"forwarded"`
}

var (
	cfg     Config
	logMu   sync.Mutex
	logFile *os.File
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func loadConfig() Config {
	bl := map[string]bool{}
	for _, n := range strings.Split(os.Getenv("BLOCKLIST"), ",") {
		if n = strings.TrimSpace(n); n != "" {
			bl[n] = true
		}
	}
	mode := strings.ToLower(env("SCREENER_MODE", "observe"))
	if mode != "hold" {
		mode = "observe"
	}
	return Config{
		Port:          env("PORT", "8080"),
		Mode:          mode,
		UpstreamURL:   os.Getenv("UPSTREAM_SMS_URL"),
		AuthToken:     os.Getenv("TWILIO_AUTH_TOKEN"),
		Blocklist:     bl,
		DataDir:       env("DATA_DIR", "/data"),
		PublicBaseURL: os.Getenv("PUBLIC_BASE_URL"),
	}
}

// classify returns the pattern class, a human reason, and whether to hold.
func classify(body string) (class, reason string, hold bool) {
	b := strings.ToLower(strings.TrimSpace(body))
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(b, s) {
				return true
			}
		}
		return false
	}

	switch {
	case has("ignore previous instructions", "ignore all previous", "disregard previous",
		"system prompt", "you are now", "jailbreak", "developer mode", "dan mode"):
		return "prompt_injection", "tries to override the AI's instructions", true
	case has("wrong number", "who is this", "stop texting", "do not text", "dont text",
		"not me", "remove me", "take me off"):
		return "wrong_number", "sender says this is not their conversation", true
	case has("verify your account", "account suspended", "account locked", "click here to verify",
		"social security", "arrest warrant", "irs ", "wire transfer", "gift card"):
		return "scam", "phishing or impersonation pattern", true
	case has("you've won", "you won", "claim your prize", "free iphone", "double your",
		"investment opportunity", "crypto giveaway", "congratulations you have been selected"):
		return "spam", "prize/lottery spam pattern", true
	}

	if b == "test" || b == "testing" || b == "testing 123" {
		return "test", "connectivity test", false
	}

	// gibberish: very low letter ratio on longer bodies, or long char runs
	letters := 0
	for _, r := range b {
		if r >= 'a' && r <= 'z' {
			letters++
		}
	}
	if len(b) > 12 && float64(letters)/float64(len(b)) < 0.3 {
		return "gibberish", "mostly non-letter characters", true
	}
	if matched, _ := regexp.MatchString(`(.)\1{5,}`, b); matched && len(b) > 8 {
		return "gibberish", "repeated character run", true
	}

	return "normal", "no bizarre pattern matched", false
}

// validateTwilioSignature checks the X-Twilio-Signature header. Skipped when
// no auth token is configured.
func validateTwilioSignature(r *http.Request, form url.Values) bool {
	if cfg.AuthToken == "" {
		return true
	}
	sig := r.Header.Get("X-Twilio-Signature")
	if sig == "" {
		return false
	}
	scheme := "https"
	if r.TLS == nil {
		if fwd := r.Header.Get("X-Forwarded-Proto"); fwd != "" {
			scheme = fwd
		}
	}
	fullURL := scheme + "://" + r.Host + r.URL.RequestURI()
	if cfg.PublicBaseURL != "" {
		fullURL = strings.TrimRight(cfg.PublicBaseURL, "/") + r.URL.RequestURI()
	}
	var sb strings.Builder
	sb.WriteString(fullURL)
	keys := make([]string, 0, len(form))
	for k := range form {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sb.WriteString(k + form.Get(k))
	}
	mac := hmac.New(sha1.New, []byte(cfg.AuthToken))
	mac.Write([]byte(sb.String()))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(sig))
}

func appendEvent(e Event) {
	logMu.Lock()
	defer logMu.Unlock()
	e.Time = time.Now().UTC()
	b, _ := json.Marshal(e)
	fmt.Fprintln(logFile, string(b))
}

func emptyTwiML() string {
	return `<?xml version="1.0" encoding="UTF-8"?><Response></Response>`
}

func handleInbound(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	from, to, body := r.Form.Get("From"), r.Form.Get("To"), r.Form.Get("Body")

	if !validateTwilioSignature(r, r.Form) {
		log.Printf("WARN inbound from %s rejected: bad signature", from)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if cfg.Blocklist[from] {
		appendEvent(Event{Type: "block", From: from, To: to, Body: body, Class: "blocklisted", Reason: "number on blocklist"})
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprint(w, emptyTwiML())
		return
	}

	class, reason, hold := classify(body)
	ev := Event{Type: "inbound", From: from, To: to, Body: body, Class: class, Reason: reason}

	if hold && cfg.Mode == "hold" {
		ev.Type = "hold"
		appendEvent(ev)
		log.Printf("HOLD %s -> %s class=%s reason=%s", from, to, class, reason)
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprint(w, emptyTwiML())
		return
	}

	// forward to Sameday
	if cfg.UpstreamURL != "" {
		resp, err := http.PostForm(cfg.UpstreamURL, r.Form)
		if err != nil {
			log.Printf("ERROR forwarding to upstream: %v", err)
			ev.Type = "forward_error"
			ev.Reason = err.Error()
			appendEvent(ev)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		upBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		ev.Type = "forward"
		ev.Forwarded = true
		appendEvent(ev)
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(resp.StatusCode)
		w.Write(upBody)
		return
	}

	ev.Type = "forward"
	ev.Forwarded = false
	ev.Reason = "no upstream configured; absorbed"
	appendEvent(ev)
	w.Header().Set("Content-Type", "text/xml")
	fmt.Fprint(w, emptyTwiML())
}

// handleReplay runs classification on a supplied sample without forwarding.
// POST JSON: {"from":"...","to":"...","body":"..."}
func handleReplay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		From string `json:"from"`
		To   string `json:"to"`
		Body string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	class, reason, hold := classify(in.Body)
	verdict := "forward"
	if hold && cfg.Mode == "hold" {
		verdict = "hold"
	}
	if cfg.Blocklist[in.From] {
		class, reason, verdict = "blocklisted", "number on blocklist", "block"
	}
	appendEvent(Event{Type: "replay", From: in.From, To: in.To, Body: in.Body,
		Class: class, Reason: reason, Forwarded: verdict == "forward"})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"class": class, "reason": reason, "verdict": verdict, "mode": cfg.Mode,
	})
}

func tailEvents(n int, filter string) []Event {
	data, err := os.ReadFile(cfg.DataDir + "/screener.log")
	if err != nil {
		return nil
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	var out []Event
	for i := len(lines) - 1; i >= 0 && len(out) < n; i-- {
		var e Event
		if json.Unmarshal(lines[i], &e) != nil {
			continue
		}
		if filter != "" && e.Type != filter {
			continue
		}
		out = append(out, e)
	}
	return out
}

func handleHolds(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tailEvents(50, "hold"))
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	counts := map[string]int{}
	classes := map[string]int{}
	for _, e := range tailEvents(10000, "") {
		counts[e.Type]++
		classes[e.Class]++
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"mode": cfg.Mode, "types": counts, "classes": classes, "time": time.Now().UTC(),
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"ok":true,"service":"sameday-sms-screener","mode":"`+cfg.Mode+`"}`)
}

func main() {
	cfg = loadConfig()
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		log.Fatalf("data dir: %v", err)
	}
	f, err := os.OpenFile(cfg.DataDir+"/screener.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Fatalf("log file: %v", err)
	}
	logFile = f
	defer f.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/sms/inbound", handleInbound)
	mux.HandleFunc("/sms/replay", handleReplay)
	mux.HandleFunc("/api/holds", handleHolds)
	mux.HandleFunc("/api/stats", handleStats)
	mux.HandleFunc("/healthz", handleHealth)

	log.Printf("screener listening on :%s mode=%s upstream=%v", cfg.Port, cfg.Mode,
		cfg.UpstreamURL != "")
	log.Fatal(http.ListenAndServe(":"+cfg.Port, mux))
}
