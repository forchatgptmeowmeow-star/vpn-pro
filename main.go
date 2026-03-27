package main

import (
 "context"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "html"
 "io"
 "log"
 "net"
 "net/http"
 "net/url"
 "os"
 "regexp"
 "sort"
 "strconv"
 "strings"
 "sync"
 "time"
)

var supportedSchemes = map[string]struct{}{
 "vless": {}, "vmess": {}, "trojan": {}, "ss": {}, "hysteria2": {}, "tuic": {}, "wg": {}, "socks": {},
}

var linkRe = regexp.MustCompile((?i)\b(?:vless|vmess|trojan|ss|hysteria2|tuic|wg|socks)://[^\s<'\"<>]+)

type SourceStat struct {
 URL       string json:"url"
 Count     int    json:"count"
 Error     string json:"error,omitempty"
 DurationMS int64 json:"duration_ms"
}

type Config struct {
 Sources         []string
 Host            string
 Port            int
 Title           string
 Refresh         time.Duration
 FetchTimeout    time.Duration
 CheckTimeout    time.Duration
 CheckAlive      bool
 MaxConcurrent   int
 MaxBodyBytes    int64
 MaxCheckWorkers int
 ProfileURL      string
}

type Store struct {
 mu      sync.RWMutex
 links   []string
 raw     string
 etag    string
 updated time.Time
 lastErr string
 stats   []SourceStat
}

func loadConfig() Config {
 cfg := Config{
  Sources: []string{
   "https://raw.githubusercontent.com/freefq/free/master/v2",
   "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub1.txt",
   "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt",
   "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/list.txt",
  },
  Host:            getenv("HOST", "0.0.0.0"),
  Port:            getenvInt("PORT", 8080),
  Title:           getenv("TITLE", "🔥 Hiddify PRO Subscription"),
  Refresh:         getenvDur("REFRESH", 10*time.Minute),
  FetchTimeout:    getenvDur("FETCH_TIMEOUT", 15*time.Second),
  CheckTimeout:    getenvDur("CHECK_TIMEOUT", 2*time.Second),
  CheckAlive:      getenvBool("CHECK_ALIVE", true),
  MaxConcurrent:   getenvInt("MAX_CONCURRENT", 16),
  MaxBodyBytes:    int64(getenvInt("MAX_BODY_MB", 2)) * 1024 * 1024,
  MaxCheckWorkers:  getenvInt("CHECK_WORKERS", 64),
  ProfileURL:      os.Getenv("PROFILE_WEB_PAGE_URL"),
 }

 if s := strings.TrimSpace(os.Getenv("SOURCES")); s != "" {
  if strings.HasPrefix(s, "[") {
   var arr []string
   if err := json.Unmarshal([]byte(s), &arr); err == nil && len(arr) > 0 {
    cfg.Sources = arr
   }
  } else {
   var arr []string
   for _, line := range strings.Split(s, "\n") {
    line = strings.TrimSpace(line)
    if line != "" {
     arr = append(arr, line)
    }
   }
   if len(arr) > 0 {
    cfg.Sources = arr
   }
  }
 }

 return cfg
}

func getenv(k, def string) string {
 if v := strings.TrimSpace(os.Getenv(k)); v != "" {
  return v
 }
 return def
}

func getenvInt(k string, def int) int {
 if v := strings.TrimSpace(os.Getenv(k)); v != "" {
  if n, err := strconv.Atoi(v); err == nil {
   return n
  }
 }
 return def
}

func getenvBool(k string, def bool) bool {
 if v := strings.TrimSpace(os.Getenv(k)); v != "" {
  switch strings.ToLower(v) {
  case "1", "true", "yes", "y", "on":
   return true
  case "0", "false", "no", "n", "off":
   return false
  }
 }
 return def
}

func getenvDur(k string, def time.Duration) time.Duration {
 if v := strings.TrimSpace(os.Getenv(k)); v != "" {
  if d, err := time.ParseDuration(v); err == nil {
   return d
  }
 }
 return def
}

func normalizeText(s string) string {
 s = html.UnescapeString(s)
 s = strings.ReplaceAll(s, "\ufeff", "")
 s = strings.ReplaceAll(s, "\r\n", "\n")
 s = strings.ReplaceAll(s, "\r", "\n")
 return strings.TrimSpace(s)
}

func tryBase64(s string) (string, bool) {
 for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
  if b, err := enc.DecodeString(s); err == nil {
   out := string(b)
   if strings.Contains(out, "://") || strings.Contains(out, "\n") {
    return out, true
   }
  }
 }
 return "", false
}
func maybeDecodeText(s string) (string, bool) {
 compact := strings.Join(strings.Fields(s), "")
 if len(compact) >= 64 {
  if decoded, ok := tryBase64(compact); ok {
   return decoded, true
  }
 }
 if strings.Contains(s, "%3A%2F%2F")  strings.Contains(s, "%40")  strings.Contains(s, "%2F") || strings.Contains(s, "%23") {
  if decoded, err := url.QueryUnescape(s); err == nil && strings.Contains(decoded, "://") {
   return decoded, true
  }
 }
 return s, false
}

func canonicalize(raw string) string {
 s := strings.TrimSpace(raw)
 if s == "" {
  return ""
 }
 s = html.UnescapeString(s)
 s = strings.Trim(s, " \t\r\n\"'`<>[](){}")
 s = strings.TrimRight(s, ",.;")
 if decoded, err := url.QueryUnescape(s); err == nil && strings.Contains(decoded, "://") {
  s = decoded
 }
 idx := strings.Index(s, "://")
 if idx < 0 {
  return ""
 }
 scheme := strings.ToLower(s[:idx])
 if _, ok := supportedSchemes[scheme]; !ok {
  return ""
 }
 return scheme + "://" + s[idx+3:]
}

func extractLinks(text string) []string {
 seen := map[string]struct{}{}
 add := func(raw string) {
  if link := canonicalize(raw); link != "" {
   seen[link] = struct{}{}
  }
 }

 for _, m := range linkRe.FindAllString(text, -1) {
  add(m)
 }
 for _, line := range strings.Split(text, "\n") {
  line = strings.TrimSpace(line)
  if line == "" || strings.HasPrefix(line, "#") {
   continue
  }
  if idx := strings.Index(line, "://"); idx > 0 {
   token := line
   if cut := strings.IndexAny(token, " \t"); cut >= 0 {
    token = token[:cut]
   }
   add(token)
  }
 }

 out := make([]string, 0, len(seen))
 for k := range seen {
  out = append(out, k)
 }
 sort.Strings(out)
 return out
}

func fetchSource(ctx context.Context, client *http.Client, source string, maxBody int64) ([]string, error) {
 req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
 if err != nil {
  return nil, err
 }
 req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; HiddifyCollector/1.0)")
 req.Header.Set("Accept", "*/*")

 resp, err := client.Do(req)
 if err != nil {
  return nil, err
 }
 defer resp.Body.Close()

 if resp.StatusCode != http.StatusOK {
  return nil, fmt.Errorf("http %d", resp.StatusCode)
 }

 body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
 if err != nil {
  return nil, err
 }

 text := normalizeText(string(body))
 if decoded, ok := maybeDecodeText(text); ok {
  text = normalizeText(decoded)
 }

 links := extractLinks(text)
 if len(links) == 0 {
  if decoded, err := url.QueryUnescape(text); err == nil && strings.Contains(decoded, "://") {
   links = extractLinks(decoded)
  }
 }
 return links, nil
}

func parseHostPort(link string) (string, int, error) {
 u, err := url.Parse(link)
 if err == nil {
  host := u.Hostname()
  portStr := u.Port()
  if host != "" && portStr != "" {
   p, perr := strconv.Atoi(portStr)
   if perr == nil {
    return host, p, nil
   }
  }
 }

 idx := strings.LastIndex(link, "@")
 if idx < 0 {
  return "", 0, fmt.Errorf("no host")
 }
 rest := link[idx+1:]
 if cut := strings.IndexAny(rest, "?#"); cut >= 0 {
  rest = rest[:cut]
 }
 host, portStr, err2 := net.SplitHostPort(rest)
 if err2 == nil {
  p, perr := strconv.Atoi(portStr)
  if perr == nil {
   return host, p, nil
  }
 }
 if strings.Count(rest, ":") == 1 {
  parts := strings.SplitN(rest, ":", 2)
  p, perr := strconv.Atoi(parts[1])
  if perr == nil {
   return parts[0], p, nil
  }
 }
 return "", 0, fmt.Errorf("no hostport")
}

func probeAlive(ctx context.Context, link string, timeout time.Duration) bool {
 host, port, err := parseHostPort(link)
 if err != nil  host == ""  port <= 0 {
  return false
 }
 d := net.Dialer{Timeout: timeout}
 conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
 if err != nil {
  return false
 }
 _ = conn.Close()
 return true
}

func filterAlive(ctx context.Context, links []string, workers int, timeout time.Duration) []string {
 if len(links) == 0 {
  return links
 }
 if workers <= 0 {
  workers = 32
 }

 jobs := make(chan string)
 out := make(chan string)
 var wg sync.WaitGroup
 for i := 0; i < workers; i++ {
  wg.Add(1)
  go func() {
   defer wg.Done()
   for link := range jobs {
    if probeAlive(ctx, link, timeout) {
     select {
     case out <- link:
     case <-ctx.Done():
      return
     }
    }
   }
  }()
 }

 go func() {
  defer close(jobs)
  for _, link := range links {
   select {
   case jobs <- link:
   case <-ctx.Done():
    return
   }
  }
 }()

 go func() {
  wg.Wait()
  close(out)
 }()

 seen := map[string]struct{}{}
 alive := make([]string, 0, len(links))
 for link := range out {
  if _, ok := seen[link]; ok {
   continue
  }
  seen[link] = struct{}{}
  alive = append(alive, link)
 }
 sort.Strings(alive)

 if len(alive) == 0 {
  return links
 }
 return alive
}

func refreshOnce(ctx context.Context, cfg Config) ([]string, []SourceStat, error) {
 client := &http.Client{Timeout: cfg.FetchTimeout}

 type item struct {
  links []string
  stat  SourceStat
 }

 sem := make(chan struct{}, cfg.MaxConcurrent)
 out := make(chan item, len(cfg.Sources))
 var wg sync.WaitGroup

 for _, src := range cfg.Sources {
  src := src
  wg.Add(1)
  go func() {
   defer wg.Done()
   sem <- struct{}{}
   defer func() { <-sem }()

   start := time.Now()
   links, err := fetchSource(ctx, client, src, cfg.MaxBodyBytes)
   st := SourceStat{URL: src, Count: len(links), DurationMS: time.Since(start).Milliseconds()}
   if err != nil {
    st.Error = err.Error()
   }
   select {
   case out <- item{links: links, stat: st}:
   case <-ctx.Done():
   }
  }()
 }

 go func() {
  wg.Wait()
  close(out)
 }()

 uniq := map[string]struct{}{}
 stats := make([]SourceStat, 0, len(cfg.Sources))
 for it := range out {
  stats = append(stats, it.stat)
  for _, link := range it.links {
   uniq[link] = struct{}{}
  }
 }

 links := make([]string, 0, len(uniq))
 for link := range uniq {
  links = append(links, link)
 }
 sort.Strings(links)

 if cfg.CheckAlive {
  checked := filterAlive(ctx, links, cfg.MaxCheckWorkers, cfg.CheckTimeout)
  if len(checked) > 0 {
   links = checked
  }
 }
 sort.Strings(links)
 return links, stats, nil
}

func safeFilename(s string) string {
 s = strings.ToLower(s)
 s = strings.ReplaceAll(s, "base64:", "")
 var b strings.Builder
 for _, r := range s {
  switch {
  case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
   b.WriteRune(r)
  case r == ' '  r == '-'  r == '_':
   b.WriteRune('_')
  }
 }
 out := strings.Trim(b.String(), "_")
 if out == "" {
  return "subscription"
 }
 if len(out) > 40 {
  out = out[:40]
 }
 return out
}

func encodeProfileTitle(title string) string {
 return "base64:" + base64.StdEncoding.EncodeToString([]byte(title))
}

func (s *Store) update(links []string, stats []SourceStat, errMsg string) {
 raw := strings.Join(links, "\n")
 sum := sha256.Sum256([]byte(raw))
 etag := " + hex.EncodeToString(sum[:]) + "

 s.mu.Lock()
 defer s.mu.Unlock()
 s.links = append([]string(nil), links...)
 s.raw = raw
 s.etag = etag
 s.updated = time.Now()
 s.lastErr = errMsg
 s.stats = append([]SourceStat(nil), stats...)
}

func (s *Store) snapshot() (links []string, raw, etag string, updated time.Time, lastErr string, stats []SourceStat) {
 s.mu.RLock()
 defer s.mu.RUnlock()
 links = append([]string(nil), s.links...)
 raw = s.raw
 etag = s.etag
 updated = s.updated
 lastErr = s.lastErr
 stats = append([]SourceStat(nil), s.stats...)
 return
}

func (s *Store) serveSub(cfg Config) http.HandlerFunc {
 return func(w http.ResponseWriter, r *http.Request) {
  _, raw, etag, updated, lastErr, _ := s.snapshot()
  if etag != "" && r.Header.Get("If-None-Match") == etag {
   w.WriteHeader(http.StatusNotModified)
   return
  }

  title := cfg.Title
  if title == "" {
   title = "Hiddify PRO Subscription"
  }
  filename := safeFilename(title) + ".txt"
  intervalHours := int(cfg.Refresh.Hours())
  if intervalHours < 1 {
   intervalHours = 1
  }
    h := w.Header()
  h.Set("Content-Type", "text/plain; charset=utf-8")
  h.Set("Cache-Control", "no-cache, no-store, must-revalidate")
  h.Set("Pragma", "no-cache")
  h.Set("Expires", "0")
  h.Set("Profile-Title", encodeProfileTitle(title))
  h.Set("content-disposition", fmt.Sprintf(attachment; filename="%s", filename))
  h.Set("profile-update-interval", strconv.Itoa(intervalHours))
  if cfg.ProfileURL != "" {
   h.Set("profile-web-page-url", cfg.ProfileURL)
  }
  if !updated.IsZero() {
   h.Set("X-Updated-At", updated.UTC().Format(time.RFC3339))
  }
  if lastErr != "" {
   h.Set("X-Last-Error", lastErr)
  }
  if etag != "" {
   h.Set("ETag", etag)
  }

  if r.Method == http.MethodHead {
   return
  }

  encoded := base64.StdEncoding.EncodeToString([]byte(raw))
  _, _ = io.WriteString(w, encoded)
 }
}

func (s *Store) serveRaw(cfg Config) http.HandlerFunc {
 return func(w http.ResponseWriter, r *http.Request) {
  _, raw, etag, updated, lastErr, _ := s.snapshot()
  if etag != "" && r.Header.Get("If-None-Match") == etag {
   w.WriteHeader(http.StatusNotModified)
   return
  }
  h := w.Header()
  h.Set("Content-Type", "text/plain; charset=utf-8")
  h.Set("Cache-Control", "no-cache, no-store, must-revalidate")
  h.Set("Profile-Title", encodeProfileTitle(cfg.Title))
  if etag != "" {
   h.Set("ETag", etag)
  }
  if !updated.IsZero() {
   h.Set("X-Updated-At", updated.UTC().Format(time.RFC3339))
  }
  if lastErr != "" {
   h.Set("X-Last-Error", lastErr)
  }
  if r.Method == http.MethodHead {
   return
  }
  _, _ = io.WriteString(w, raw)
 }
}

func (s *Store) serveStats(w http.ResponseWriter, r *http.Request) {
 links, _, etag, updated, lastErr, stats := s.snapshot()
 payload := map[string]any{
  "count":      len(links),
  "updated_at": func() string { if updated.IsZero() { return "" }; return updated.UTC().Format(time.RFC3339) }(),
  "last_error": lastErr,
  "etag":       etag,
  "sources":    stats,
 }
 w.Header().Set("Content-Type", "application/json; charset=utf-8")
 _ = json.NewEncoder(w).Encode(payload)
}

func main() {
 cfg := loadConfig()
 store := &Store{}

 ctx, cancel := context.WithCancel(context.Background())
 defer cancel()

 refresh := func() {
  links, stats, err := refreshOnce(ctx, cfg)
  if err != nil {
   store.update(nil, stats, err.Error())
   log.Printf("refresh error: %v\n", err)
   return
  }
  store.update(links, stats, "")
  log.Printf("refreshed: %d links\n", len(links))
 }

 refresh()

 go func() {
  ticker := time.NewTicker(cfg.Refresh)
  defer ticker.Stop()
  for {
   select {
   case <-ticker.C:
    refresh()
   case <-ctx.Done():
    return
   }
  }
 }()

 mux := http.NewServeMux()
 mux.HandleFunc("/sub", store.serveSub(cfg))
 mux.HandleFunc("/raw", store.serveRaw(cfg))
 mux.HandleFunc("/stats", store.serveStats)
 mux.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
  if r.Method != http.MethodPost && r.Method != http.MethodGet {
   w.WriteHeader(http.StatusMethodNotAllowed)
   return
  }
  go refresh()
  w.Header().Set("Content-Type", "text/plain; charset=utf-8")
  _, _ = io.WriteString(w, "refresh started\n")
 })
 mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
  w.WriteHeader(http.StatusOK)
  _, _ = io.WriteString(w, "ok\n")
 })

 addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
 srv := &http.Server{
  Addr:              addr,
  Handler:           mux,
  ReadHeaderTimeout: 5 * time.Second,
  IdleTimeout:       60 * time.Second,
 }

 log.Printf("listening on http://%s/sub\n", addr)
 log.Printf("raw:   http://%s/raw\n", addr)
 log.Printf("stats: http://%s/stats\n", addr)

 if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
  log.Fatal(err)
 }
}
