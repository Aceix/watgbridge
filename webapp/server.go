package webapp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"watgbridge/bridge"
	"watgbridge/database"
	"watgbridge/state"
	"watgbridge/utils"

	waTypes "go.mau.fi/whatsmeow/types"
	"go.uber.org/zap"
)

//go:embed static/*
var staticFiles embed.FS

type session struct {
	UserID    int64
	CSRFToken string
	ExpiresAt time.Time
}

type ipRateLimit struct {
	Count   int64
	ResetAt time.Time
}

type server struct {
	mux        *http.ServeMux
	sessions   map[string]session
	rateLimits map[string]ipRateLimit
	mu         sync.RWMutex
}

func StartServer() error {
	cfg := state.State.Config
	logger := state.State.Logger

	if !cfg.MiniApp.Enabled {
		return nil
	}
	if cfg.MiniApp.PublicURL == "" {
		return fmt.Errorf("mini app is enabled but mini_app.public_url is empty")
	}
	if cfg.MiniApp.RequireHTTPS && !strings.HasPrefix(strings.ToLower(cfg.MiniApp.PublicURL), "https://") {
		return fmt.Errorf("mini_app.public_url must use HTTPS when mini_app.require_https is true")
	}
	if cfg.MiniApp.BindAddress == "" {
		return fmt.Errorf("mini app is enabled but mini_app.bind_address is empty")
	}

	s := &server{
		mux:        http.NewServeMux(),
		sessions:   make(map[string]session),
		rateLimits: make(map[string]ipRateLimit),
	}
	s.routes()

	httpServer := &http.Server{
		Addr:              cfg.MiniApp.BindAddress,
		Handler:           s.mux,
		ReadHeaderTimeout: 15 * time.Second,
	}

	go func() {
		logger.Info("starting mini app server",
			zap.String("bind_address", cfg.MiniApp.BindAddress),
			zap.String("public_url", cfg.MiniApp.PublicURL),
		)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("mini app server failed", zap.Error(err))
		}
	}()

	return nil
}

func (s *server) routes() {
	api := s.withRateLimit

	s.mux.HandleFunc("/miniapp/api/auth/login", api(s.handleAuthLogin))
	s.mux.HandleFunc("/miniapp/api/auth/me", api(s.withSession(s.handleAuthMe)))
	s.mux.HandleFunc("/miniapp/api/chats", api(s.withSession(s.handleChatsList)))
	s.mux.HandleFunc("/miniapp/api/messages", api(s.withSession(s.handleMessagesList)))
	s.mux.HandleFunc("/miniapp/api/messages/send", api(s.withSession(s.withCSRF(s.handleMessageSend))))
	s.mux.HandleFunc("/miniapp/api/messages/upload", api(s.withSession(s.withCSRF(s.handleMessageUpload))))
	s.mux.HandleFunc("/miniapp/api/messages/revoke", api(s.withSession(s.withCSRF(s.handleMessageRevoke))))
	s.mux.HandleFunc("/miniapp/api/mappings", api(s.withSession(s.withCSRF(s.handleMappings))))
	s.mux.HandleFunc("/miniapp/api/mappings/", api(s.withSession(s.withCSRF(s.handleMappingDelete))))
	s.mux.HandleFunc("/miniapp/api/lookup/contacts", api(s.withSession(s.handleLookupContacts)))
	s.mux.HandleFunc("/miniapp/api/lookup/groups", api(s.withSession(s.handleLookupGroups)))
	s.mux.HandleFunc("/miniapp/api/updates", api(s.withSession(s.handleUpdates)))

	sub, _ := fs.Sub(staticFiles, "static")
	fileServer := http.FileServer(http.FS(sub))
	s.mux.Handle("/miniapp/", http.StripPrefix("/miniapp/", fileServer))
	s.mux.HandleFunc("/miniapp", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/miniapp/", http.StatusTemporaryRedirect)
	})
}

func (s *server) withRateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := state.State.Config
		maxPerMinute := cfg.MiniApp.RateLimitPerMinute
		if maxPerMinute <= 0 {
			maxPerMinute = 120
		}

		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		now := time.Now().UTC()

		s.mu.Lock()
		current := s.rateLimits[host]
		if current.ResetAt.IsZero() || now.After(current.ResetAt) {
			current = ipRateLimit{Count: 0, ResetAt: now.Add(time.Minute)}
		}
		current.Count++
		s.rateLimits[host] = current
		s.mu.Unlock()

		if current.Count > maxPerMinute {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "rate limit exceeded"})
			return
		}
		next(w, r)
	}
}

func (s *server) withSession(next func(http.ResponseWriter, *http.Request, session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(auth, "Bearer ") {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "missing bearer token"})
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid bearer token"})
			return
		}

		s.mu.RLock()
		sess, ok := s.sessions[token]
		s.mu.RUnlock()
		if !ok || time.Now().UTC().After(sess.ExpiresAt) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "session expired"})
			return
		}

		if !bridge.IsAuthorizedTelegramUser(sess.UserID) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "not authorized"})
			return
		}

		next(w, r, sess)
	}
}

func (s *server) withCSRF(next func(http.ResponseWriter, *http.Request, session)) func(http.ResponseWriter, *http.Request, session) {
	return func(w http.ResponseWriter, r *http.Request, sess session) {
		if r.Method != http.MethodPost && r.Method != http.MethodDelete {
			next(w, r, sess)
			return
		}
		token := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
		if token == "" || token != sess.CSRFToken {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "invalid csrf token"})
			return
		}
		next(w, r, sess)
	}
}

func (s *server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	var body struct {
		InitData string `json:"init_data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
		return
	}
	if body.InitData == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "init_data is required"})
		return
	}

	userID, userName, err := validateTelegramInitData(body.InitData)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
		return
	}
	if !bridge.IsAuthorizedTelegramUser(userID) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "not authorized"})
		return
	}

	token := randomToken(userID, userName)
	csrf := randomToken(userID, "csrf")
	ttl := state.State.Config.MiniApp.SessionTTLSeconds
	if ttl <= 0 {
		ttl = 3600
	}
	sess := session{
		UserID:    userID,
		CSRFToken: csrf,
		ExpiresAt: time.Now().UTC().Add(time.Duration(ttl) * time.Second),
	}

	s.mu.Lock()
	s.sessions[token] = sess
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"csrf_token": csrf,
		"user_id":    userID,
		"user_name":  userName,
		"expires_at": sess.ExpiresAt.Unix(),
	})
}

func (s *server) handleAuthMe(w http.ResponseWriter, r *http.Request, sess session) {
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":    sess.UserID,
		"expires_at": sess.ExpiresAt.Unix(),
	})
}

func (s *server) handleChatsList(w http.ResponseWriter, r *http.Request, _ session) {
	pairs, err := database.ChatThreadGetAllPairs(state.State.Config.Telegram.TargetChatID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	type chatItem struct {
		WaChatID     string `json:"wa_chat_id"`
		Name         string `json:"name"`
		ThreadID     int64  `json:"thread_id"`
		LastMessage  string `json:"last_message"`
		LastMessageID uint64 `json:"last_message_id"`
	}

	result := make([]chatItem, 0, len(pairs))
	for _, pair := range pairs {
		name := pair.ID
		if jid, ok := utils.WaParseJID(pair.ID); ok {
			if jid.Server == waTypes.GroupServer {
				name = utils.WaGetGroupName(jid)
			} else {
				name = utils.WaGetContactName(jid)
			}
		}

		item := chatItem{
			WaChatID: pair.ID,
			Name:     name,
			ThreadID: pair.TgThreadId,
		}
		if last, err := database.MiniAppTimelineLatestByChat(pair.ID); err == nil && last != nil {
			item.LastMessage = last.Text
			item.LastMessageID = last.ID
		}
		result = append(result, item)
	}

	writeJSON(w, http.StatusOK, map[string]any{"chats": result})
}

func (s *server) handleMessagesList(w http.ResponseWriter, r *http.Request, _ session) {
	waChatID := strings.TrimSpace(r.URL.Query().Get("chat_id"))
	if waChatID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "chat_id is required"})
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	beforeID, _ := strconv.ParseUint(r.URL.Query().Get("before"), 10, 64)
	items, err := database.MiniAppTimelineListByChat(waChatID, limit, beforeID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"messages": items})
}

func (s *server) handleMessageSend(w http.ResponseWriter, r *http.Request, sess session) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	var body struct {
		WaChatID  string `json:"wa_chat_id"`
		Text      string `json:"text"`
		ReplyToID string `json:"reply_to_wa_message_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
		return
	}

	if strings.TrimSpace(body.WaChatID) == "" || strings.TrimSpace(body.Text) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "wa_chat_id and text are required"})
		return
	}

	sendRes, err := bridge.SendTextToWhatsApp(body.WaChatID, body.Text, body.ReplyToID)
	status := "sent"
	errMsg := ""
	if err != nil {
		status = "failed"
		errMsg = err.Error()
	} else {
		bridge.RecordTimelineMessage(database.MiniAppTimelineMessage{
			WaChatID:           body.WaChatID,
			WaMessageID:        sendRes.ID,
			ReplyToWaMessageID: body.ReplyToID,
			SenderJID:          state.State.WhatsAppClient.Store.ID.String(),
			SenderName:         fmt.Sprintf("TelegramUser:%d", sess.UserID),
			Direction:          "out",
			Source:             "mini_app",
			Text:               body.Text,
			MediaType:          "text",
			Status:             status,
		})
	}

	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": status,
		"message_id": sendRes.ID,
		"error_message": errMsg,
	})
}

func (s *server) handleMessageUpload(w http.ResponseWriter, r *http.Request, sess session) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	if err := r.ParseMultipartForm(30 << 20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "failed to parse multipart body"})
		return
	}

	waChatID := strings.TrimSpace(r.FormValue("wa_chat_id"))
	caption := strings.TrimSpace(r.FormValue("caption"))
	replyToID := strings.TrimSpace(r.FormValue("reply_to_wa_message_id"))
	if waChatID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "wa_chat_id is required"})
		return
	}

	file, fileHeader, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "file is required"})
		return
	}
	defer file.Close()

	mimeType := fileHeader.Header.Get("Content-Type")
	sendRes, err := bridge.SendMediaToWhatsApp(waChatID, caption, replyToID, file, fileHeader, mimeType)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}

	bridge.RecordTimelineMessage(database.MiniAppTimelineMessage{
		WaChatID:           waChatID,
		WaMessageID:        sendRes.ID,
		ReplyToWaMessageID: replyToID,
		SenderJID:          state.State.WhatsAppClient.Store.ID.String(),
		SenderName:         fmt.Sprintf("TelegramUser:%d", sess.UserID),
		Direction:          "out",
		Source:             "mini_app",
		Text:               caption,
		MediaType:          mimeType,
		MediaName:          fileHeader.Filename,
		Status:             "sent",
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "sent",
		"message_id": sendRes.ID,
	})
}

func (s *server) handleMessageRevoke(w http.ResponseWriter, r *http.Request, _ session) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	var body struct {
		WaChatID    string `json:"wa_chat_id"`
		WaMessageID string `json:"wa_message_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
		return
	}
	if body.WaChatID == "" || body.WaMessageID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "wa_chat_id and wa_message_id are required"})
		return
	}

	if err := bridge.RevokeWhatsAppMessage(body.WaChatID, body.WaMessageID); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	bridge.RecordTimelineMessage(database.MiniAppTimelineMessage{
		WaChatID:    body.WaChatID,
		WaMessageID: body.WaMessageID,
		Direction:   "out",
		Source:      "mini_app",
		Text:        "Message revoked",
		Status:      "revoked",
		MediaType:   "system",
	})

	writeJSON(w, http.StatusOK, map[string]any{"status": "revoked"})
}

func (s *server) handleMappings(w http.ResponseWriter, r *http.Request, _ session) {
	switch r.Method {
	case http.MethodGet:
		pairs, err := database.ChatThreadGetAllPairs(state.State.Config.Telegram.TargetChatID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"mappings": pairs})
		return
	case http.MethodPost:
		var body struct {
			WaChatID string `json:"wa_chat_id"`
			ThreadID int64  `json:"thread_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
			return
		}
		if body.WaChatID == "" || body.ThreadID == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "wa_chat_id and thread_id are required"})
			return
		}
		if err := database.ChatThreadAddNewPair(body.WaChatID, state.State.Config.Telegram.TargetChatID, body.ThreadID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
		return
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}

func (s *server) handleMappingDelete(w http.ResponseWriter, r *http.Request, _ session) {
	if r.Method != http.MethodDelete {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	waChatID := strings.TrimPrefix(r.URL.Path, "/miniapp/api/mappings/")
	waChatID = strings.TrimSpace(waChatID)
	if waChatID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "wa_chat_id is required in path"})
		return
	}

	if err := database.ChatThreadDropPairByWa(waChatID, state.State.Config.Telegram.TargetChatID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
}

func (s *server) handleLookupContacts(w http.ResponseWriter, r *http.Request, _ session) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if query == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "q is required"})
		return
	}

	results, _, err := utils.WaFuzzyFindContacts(query)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"contacts": results})
}

func (s *server) handleLookupGroups(w http.ResponseWriter, r *http.Request, _ session) {
	groups, err := state.State.WhatsAppClient.GetJoinedGroups(context.Background())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": groups})
}

func (s *server) handleUpdates(w http.ResponseWriter, r *http.Request, _ session) {
	sinceID, _ := strconv.ParseUint(strings.TrimSpace(r.URL.Query().Get("since")), 10, 64)
	limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))

	items, err := database.MiniAppTimelineListSince(sinceID, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	latestID := sinceID
	if len(items) > 0 {
		latestID = items[len(items)-1].ID
	} else if last, err := database.MiniAppTimelineLatestID(); err == nil {
		latestID = last
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"latest_id": latestID,
		"messages":  items,
	})
}

func validateTelegramInitData(initData string) (int64, string, error) {
	cfg := state.State.Config
	values, err := url.ParseQuery(initData)
	if err != nil {
		return 0, "", fmt.Errorf("invalid initData")
	}

	hash := values.Get("hash")
	if hash == "" {
		return 0, "", fmt.Errorf("missing hash in initData")
	}

	authDateRaw := values.Get("auth_date")
	authDate, err := strconv.ParseInt(authDateRaw, 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("invalid auth_date in initData")
	}
	maxAge := cfg.MiniApp.InitDataTTLSeconds
	if maxAge <= 0 {
		maxAge = 300
	}
	if time.Now().UTC().Unix()-authDate > maxAge {
		return 0, "", fmt.Errorf("initData has expired")
	}

	dataCheck := make([]string, 0, len(values))
	for key, v := range values {
		if key == "hash" || len(v) == 0 {
			continue
		}
		dataCheck = append(dataCheck, key+"="+v[0])
	}
	sort.Strings(dataCheck)
	dataCheckString := strings.Join(dataCheck, "\n")

	secretDigest := hmac.New(sha256.New, []byte("WebAppData"))
	secretDigest.Write([]byte(cfg.Telegram.BotToken))
	secretKey := secretDigest.Sum(nil)

	h := hmac.New(sha256.New, secretKey)
	h.Write([]byte(dataCheckString))
	expectedHash := hex.EncodeToString(h.Sum(nil))
	if !hmac.Equal([]byte(expectedHash), []byte(hash)) {
		return 0, "", fmt.Errorf("invalid initData hash")
	}

	userRaw := values.Get("user")
	if userRaw == "" {
		return 0, "", fmt.Errorf("missing user in initData")
	}

	var user struct {
		ID        int64  `json:"id"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Username  string `json:"username"`
	}
	if err := json.Unmarshal([]byte(userRaw), &user); err != nil {
		return 0, "", fmt.Errorf("invalid user payload")
	}
	if user.ID == 0 {
		return 0, "", fmt.Errorf("invalid user id")
	}

	name := strings.TrimSpace(strings.Join([]string{user.FirstName, user.LastName}, " "))
	if name == "" {
		name = user.Username
	}
	if name == "" {
		name = strconv.FormatInt(user.ID, 10)
	}

	return user.ID, name, nil
}

func randomToken(userID int64, suffix string) string {
	payload := fmt.Sprintf("%d|%s|%d", userID, suffix, time.Now().UTC().UnixNano())
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
