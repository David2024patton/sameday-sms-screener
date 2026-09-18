// sameday-sms-screener: inbound SMS screening proxy for Patriot Pest Control.
//
// Twilio number webhook -> this service -> classify -> forward to Sameday AI
// (clear pest-control inquiry) or hold (bizarre / uncertain). Held messages
// surface to David for approval via the /api/holds endpoints.
//
// FAIL-CLOSED: anything that is not clearly a legitimate pest-control inquiry
// is held. Unknown input never forwards.
//
// Modes (SCREENER_MODE): observe = log only, forward everything (default),
// hold = hold bizarre/uncertain inbound instead of forwarding to Sameday.
//
// Auth: SCREENER_API_KEY guards /api/* and /sms/replay (bearer token).
// Twilio webhooks on /sms/inbound use Twilio signature validation instead.
//
// PII: phone numbers are SHA-256 hashed (truncated) in the event log. Message
// bodies are stored ONLY for held messages (David must review them to approve
// or drop). Forwarded/normal traffic logs class metadata only, no body.
//
// Stdlib only. JSONL event log at DATA_DIR/screener.log. Holds state at
// DATA_DIR/holds.json (survives restarts).
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
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
	APIKey        string // bearer token for /api/* and /sms/replay; empty = deny
	Blocklist     map[string]bool
	DataDir       string
	PublicBaseURL string
}

type Event struct {
	Time      time.Time `json:"time"`
	Type      string    `json:"type"` // inbound | hold | forward | replay | block | release | drop
	FromHash  string    `json:"from_hash"`
	ToHash    string    `json:"to_hash"`
	Body      string    `json:"body,omitempty"` // ONLY for holds
	BodyLen   int       `json:"body_len"`
	Class     string    `json:"class"`
	Reason    string    `json:"reason"`
	Forwarded bool      `json:"forwarded"`
	HoldID    string    `json:"hold_id,omitempty"`
}

// Hold is a message awaiting David's decision.
type Hold struct {
	ID        string    `json:"id"`
	Created   time.Time `json:"created"`
	FromHash  string    `json:"from_hash"`
	ToHash    string    `json:"to_hash"`
	Body      string    `json:"body"`
	Class     string    `json:"class"`
	Reason    string    `json:"reason"`
	Status    string    `json:"status"` // pending | released | dropped
	DecidedAt time.Time `json:"decided_at,omitempty"`
}

var (
	cfg      Config
	logMu    sync.Mutex
	logFile  *os.File
	holdsMu  sync.Mutex
	holds    = map[string]*Hold{}
	holdSeq  int64
	classCnt = map[string]int{}
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
		APIKey:        os.Getenv("SCREENER_API_KEY"),
		Blocklist:     bl,
		DataDir:       env("DATA_DIR", "/data"),
		PublicBaseURL: os.Getenv("PUBLIC_BASE_URL"),
	}
}

// hashPhone returns a truncated SHA-256 hex of the phone number for
// pattern tracking without retaining PII.
func hashPhone(phone string) string {
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, phone)
	sum := sha256.Sum256([]byte("screener-phone|" + digits))
	return hex.EncodeToString(sum[:])[:16]
}

// classify returns the pattern class, a human reason, and whether to hold.
// FAIL-CLOSED: the default verdict is HOLD. Only messages that are clearly
// legitimate pest-control inquiries forward.
func classify(body string) (class, reason string, hold bool) {
	b := strings.ToLower(strings.TrimSpace(body))
	if b == "" {
		return "empty", "empty body", true
	}
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(b, s) {
				return true
			}
		}
		return false
	}

	// Known-bad patterns: always hold.
	switch {
	case has("ignore previous instructions", "ignore all previous", "disregard previous",
		"system prompt", "you are now", "jailbreak", "developer mode", "dan mode",
		"prompt injection"):
		return "prompt_injection", "tries to override the AI's instructions", true
	case has("wrong number", "who is this", "stop texting", "do not text", "dont text",
		"not me", "remove me", "take me off", "unsubscribe", "stop"):
		return "wrong_number", "sender says this is not their conversation", true
	case has("verify your account", "account suspended", "account locked",
		"click here to verify", "social security", "arrest warrant", "irs ",
		"wire transfer", "gift card", "bank account"):
		return "scam", "phishing or impersonation pattern", true
	case has("you've won", "you won", "claim your prize", "free iphone", "double your",
		"investment opportunity", "crypto giveaway", "congratulations you have been selected"):
		return "spam", "prize/lottery spam pattern", true
	}

	if b == "test" || b == "testing" || b == "testing 123" {
		return "test", "connectivity test", false
	}

	// Gibberish: very low letter ratio on longer bodies, or long char runs.
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

	// Known-good: clearly a pest-control inquiry. Only these forward.
	good := []string{
		"ant", "ants", "roach", "roaches", "cockroach", "spider", "spiders",
		"wasp", "wasps", "hornet", "bee", "bees", "termite", "termites",
		"bed bug", "bedbug", "flea", "fleas", "tick", "ticks", "mosquito",
		"mosquitoes", "rodent", "mice", "mouse", "rat", "rats", "squirrel",
		"cricket", "silverfish", "earwig", "centipede", "millipede",
		"pest", "pests", "infestation", "exterminator", "pest control",
		"quote", "estimate", "how much", "price", "pricing", "cost",
		"schedule", "appointment", "book", "booking", "spray", "treatment",
		"service", "technician", "tech visit", "inspection",
		"yes", "yeah", "yep", "ok", "okay", "sure", "sounds good",
		"morning", "afternoon", "evening", "today", "tomorrow", "monday",
		"tuesday", "wednesday", "thursday", "friday",
		"thank", "thanks",
	}
	if has(good...) {
		return "inquiry", "legitimate pest-control inquiry language", false
	}
	// Address-like or phone-like content suggests a real customer.
	if matched, _ := regexp.MatchString(`\d{3,}\s+[a-z]+\s+(st|ave|avenue|rd|road|dr|drive|ln|lane|ct|court|blvd|way)`, b); matched {
		return "inquiry", "contains street address", false
	}
	if matched, _ := regexp.MatchString(`\d{3}[-.\s]?\d{3}[-.\s]?\d{4}`, b); matched {
		return "inquiry", "contains phone number", false
	}

	// FAIL CLOSED: uncertain input holds.
	return "uncertain", "no clear legitimate-inquiry signal; held per fail-closed policy", true
}

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

// requireAPIKey guards /api/* and /sms/replay. Empty key = deny all.
func requireAPIKey(w http.ResponseWriter, r *http.Request) bool {
	if cfg.APIKey == "" {
		http.Error(w, "api not configured", http.StatusServiceUnavailable)
		return false
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	got := strings.TrimPrefix(auth, "Bearer ")
	if subtle.ConstantTimeCompare([]byte(got), []byte(cfg.APIKey)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func appendEvent(e Event) {
	logMu.Lock()
	defer logMu.Unlock()
	e.Time = time.Now().UTC()
	b, _ := json.Marshal(e)
	fmt.Fprintln(logFile, string(b))
}

func saveHolds() {
	holdsMu.Lock()
	defer holdsMu.Unlock()
	tmp := cfg.DataDir + "/holds.json.tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("ERROR saving holds: %v", err)
		return
	}
	list := make([]*Hold, 0, len(holds))
	for _, h := range holds {
		list = append(list, h)
	}
	json.NewEncoder(f).Encode(map[string]any{"holds": list, "seq": holdSeq, "class_counts": classCnt})
	f.Close()
	os.Rename(tmp, cfg.DataDir+"/holds.json")
}

func loadHolds() {
	data, err := os.ReadFile(cfg.DataDir + "/holds.json")
	if err != nil {
		return
	}
	var st struct {
		Holds       []*Hold       `json:"holds"`
		Seq         int64         `json:"seq"`
		ClassCounts map[string]int `json:"class_counts"`
	}
	if json.Unmarshal(data, &st) != nil {
		return
	}
	holdsMu.Lock()
	defer holdsMu.Unlock()
	for _, h := range st.Holds {
		holds[h.ID] = h
	}
	holdSeq = st.Seq
	for k, v := range st.ClassCounts {
		classCnt[k] = v
	}
}

func newHoldID() string {
	holdsMu.Lock()
	defer holdsMu.Unlock()
	holdSeq++
	return fmt.Sprintf("h-%d-%d", time.Now().Unix(), holdSeq)
}

// recordHold stores the hold, updates per-class counts, and returns true when
// this class has now caused 2+ holds (David must review the pattern).
func recordHold(h *Hold) bool {
	holdsMu.Lock()
	holds[h.ID] = h
	classCnt[h.Class]++
	n := classCnt[h.Class]
	holdsMu.Unlock()
	saveHolds()
	return n >= 2
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
	fromHash, toHash := hashPhone(from), hashPhone(to)

	if !validateTwilioSignature(r, r.Form) {
		log.Printf("WARN inbound rejected: bad signature")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if cfg.Blocklist[from] {
		appendEvent(Event{Type: "block", FromHash: fromHash, ToHash: toHash,
			BodyLen: len(body), Class: "blocklisted", Reason: "number on blocklist"})
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprint(w, emptyTwiML())
		return
	}

	class, reason, hold := classify(body)

	if hold && cfg.Mode == "hold" {
		h := &Hold{
			ID: newHoldID(), Created: time.Now().UTC(),
			FromHash: fromHash, ToHash: toHash,
			Body: body, Class: class, Reason: reason, Status: "pending",
		}
		repeat := recordHold(h)
		appendEvent(Event{Type: "hold", FromHash: fromHash, ToHash: toHash,
			Body: body, BodyLen: len(body), Class: class, Reason: reason, HoldID: h.ID})
		log.Printf("HOLD %s class=%s reason=%s repeat_class=%v", h.ID, class, reason, repeat)
		if repeat {
			log.Printf("ALERT class %q has caused 2+ holds: recommend David review pattern and consider LobbyStack cutover", class)
		}
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprint(w, emptyTwiML())
		return
	}

	if cfg.UpstreamURL != "" {
		resp, err := http.PostForm(cfg.UpstreamURL, r.Form)
		if err != nil {
			log.Printf("ERROR forwarding to upstream: %v", err)
			appendEvent(Event{Type: "forward_error", FromHash: fromHash, ToHash: toHash,
				BodyLen: len(body), Class: class, Reason: err.Error()})
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		upBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		appendEvent(Event{Type: "forward", FromHash: fromHash, ToHash: toHash,
			BodyLen: len(body), Class: class, Reason: reason, Forwarded: true})
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(resp.StatusCode)
		w.Write(upBody)
		return
	}

	appendEvent(Event{Type: "forward", FromHash: fromHash, ToHash: toHash,
		BodyLen: len(body), Class: class, Reason: "no upstream configured; absorbed"})
	w.Header().Set("Content-Type", "text/xml")
	fmt.Fprint(w, emptyTwiML())
}

// handleReplay runs classification on a supplied sample without forwarding.
// POST JSON: {"from":"...","to":"...","body":"..."}. Requires API key.
func handleReplay(w http.ResponseWriter, r *http.Request) {
	if !requireAPIKey(w, r) {
		return
	}
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
	appendEvent(Event{Type: "replay", FromHash: hashPhone(in.From), ToHash: hashPhone(in.To),
		BodyLen: len(in.Body), Class: class, Reason: reason, Forwarded: verdict == "forward"})
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

// handleHolds lists pending holds for David's review. Requires API key.
// Bodies are included: David must read them to approve or drop.
func handleHolds(w http.ResponseWriter, r *http.Request) {
	if !requireAPIKey(w, r) {
		return
	}
	holdsMu.Lock()
	var pending []*Hold
	for _, h := range holds {
		if h.Status == "pending" {
			pending = append(pending, h)
		}
	}
	counts := map[string]int{}
	for k, v := range classCnt {
		counts[k] = v
	}
	holdsMu.Unlock()
	sort.Slice(pending, func(i, j int) bool { return pending[i].Created.After(pending[j].Created) })
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"pending": pending, "class_counts": counts, "mode": cfg.Mode,
	})
}

// handleHoldDecision releases (forwards to Sameday) or drops a held message.
// POST /api/holds/{id}/release or /api/holds/{id}/drop. Requires API key.
// Release forwards the ORIGINAL inbound to the upstream; David's approval is
// this API call.
func handleHoldDecision(w http.ResponseWriter, r *http.Request) {
	if !requireAPIKey(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/holds/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || (parts[1] != "release" && parts[1] != "drop") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	id, action := parts[0], parts[1]

	holdsMu.Lock()
	h, ok := holds[id]
	if !ok || h.Status != "pending" {
		holdsMu.Unlock()
		http.Error(w, "hold not found or already decided", http.StatusNotFound)
		return
	}
	holdsMu.Unlock()

	if action == "release" {
		if cfg.UpstreamURL == "" {
			http.Error(w, "no upstream configured", http.StatusConflict)
			return
		}
		form := url.Values{"Body": {h.Body}}
		resp, err := http.PostForm(cfg.UpstreamURL, form)
		if err != nil {
			http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
			return
		}
		resp.Body.Close()
	}
	holdsMu.Lock()
	h.Status = map[string]string{"release": "released", "drop": "dropped"}[action]
	h.DecidedAt = time.Now().UTC()
	holdsMu.Unlock()
	saveHolds()
	appendEvent(Event{Type: action, FromHash: h.FromHash, ToHash: h.ToHash,
		BodyLen: len(h.Body), Class: h.Class, Reason: "david decision: " + action,
		Forwarded: action == "release", HoldID: h.ID})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"id": id, "status": h.Status})
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	if !requireAPIKey(w, r) {
		return
	}
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
	loadHolds()

	mux := http.NewServeMux()
	mux.HandleFunc("/sms/inbound", handleInbound)
	mux.HandleFunc("/sms/replay", handleReplay)
	mux.HandleFunc("/api/holds", handleHolds)
	mux.HandleFunc("/api/holds/", handleHoldDecision)
	mux.HandleFunc("/api/stats", handleStats)
	mux.HandleFunc("/healthz", handleHealth)

	log.Printf("screener listening on :%s mode=%s upstream=%v api=%v", cfg.Port, cfg.Mode,
		cfg.UpstreamURL != "", cfg.APIKey != "")
	log.Fatal(http.ListenAndServe(":"+cfg.Port, mux))
}
