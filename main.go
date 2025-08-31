
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type Channel struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Type string `json:"type"` // "m3u8" أو "direct"
}

var (
	mu       sync.RWMutex
	channels = map[string]Channel{
		"bein1": {
			Name: "BeIN SPORTS 1",
			URL:  "http://188.241.219.157/ulke.bordo1453.befhjjjj/Orhantelegrammmm30conextionefbn/274122?token=ShJdY2ZmQQNHCmMZCDZXUh9GSHAWGFMD.ZDsGQVN.WGBFNX013GR9YV1QbGBp0QE9SWmpcXlQXXlUHWlcbRxFACmcDY1tXEVkbVAoAAQJUFxUbRFldAxdeUAdaVAFcUwcHAhwWQlpXQQMLTFhUG0FQQU1VQl4HWTsFVBQLVABGCVxEXFgeEVwNZgFcWVlZBxcDGwESHERcFxETWAxCCQgfEFNZQEBSRwYbX1dBVFtPF1pWRV5EFExGWxMmJxVJRlZKRVVaQVpcDRtfG0BLFU8XUEpvQlUVQRYEUA8HRUdeEQITHBZfUks8WgpXWl1UF1xWV0MSCkQERk0TDw1ZDBBcQG5AXVYRCQ1MCVVJ",
			Type: "direct",
		},
		"bein2": {
			Name: "BeIN SPORTS 2",
			URL:  "http://188.241.219.157/yusf4k/yusf4k/274123?token=ShJdY2ZmQQNHCmMZCDZXUh9GSHAWGFMD.ZDsGQVN.WGBFNX013GR9YV1QbGBp0QE9SWmpcXlQXXlUHWlcbRxFACmcDY1tXEVkbVAoAAQJUFxUbRFldAxdeUAdaVAFcUwcHAhwWQlpXQQMLTFhUG0FQQU1VQl4HWTsFVBQLVABGCVxEXFgeEVwNZgFcWVlZBxcDGwESHERcFxETWAxCCQgfEFNZQEBSRwYbX1dBVFtPF1pWRV5EFExGWxMmJxVJRlZKRVVaQVpcDRtfG0BLFU8XUEpvQlUVQRYEUA8HRUdeEQITHBZfUks8WgpXWl1UF1xWV0MSCkQERk0TDw1ZDBBcQG5AXVYRCQ1MCVVJ",
			Type: "direct",
		},
		"bein3": {
			Name: "BeIN SPORTS 3",
			URL:  "http://188.241.219.157/yusf4k/yusf4k/274124?token=ShJdY2ZmQQNHCmMZCDZXUh9GSHAWGFMD.ZDsGQVN.WGBFNX013GR9YV1QbGBp0QE9SWmpcXlQXXlUHWlcbRxFACmcDY1tXEVkbVAoAAQJUFxUbRFldAxdeUAdaVAFcUwcHAhwWQlpXQQMLTFhUG0FQQU1VQl4HWTsFVBQLVABGCVxEXFgeEVwNZgFcWVlZBxcDGwESHERcFxETWAxCCQgfEFNZQEBSRwYbX1dBVFtPF1pWRV5EFExGWxMmJxVJRlZKRVVaQVpcDRtfG0BLFU8XUEpvQlUVQRYEUA8HRUdeEQITHBZfUks8WgpXWl1UF1xWV0MSCkQERk0TDw1ZDBBcQG5AXVYRCQ1MCVVJ",
			Type: "direct",
		},
		"bein4": {
			Name: "BeIN SPORTS 4", 
			URL:  "http://188.241.219.157/yusf4k/yusf4k/274125?token=ShJdY2ZmQQNHCmMZCDZXUh9GSHAWGFMD.ZDsGQVN.WGBFNX013GR9YV1QbGBp0QE9SWmpcXlQXXlUHWlcbRxFACmcDY1tXEVkbVAoAAQJUFxUbRFldAxdeUAdaVAFcUwcHAhwWQlpXQQMLTFhUG0FQQU1VQl4HWTsFVBQLVABGCVxEXFgeEVwNZgFcWVlZBxcDGwESHERcFxETWAxCCQgfEFNZQEBSRwYbX1dBVFtPF1pWRV5EFExGWxMmJxVJRlZKRVVaQVpcDRtfG0BLFU8XUEpvQlUVQRYEUA8HRUdeEQITHBZfUks8WgpXWl1UF1xWV0MSCkQERk0TDw1ZDBBcQG5AXVYRCQ1MCVVJ",
			Type: "direct",
		},
		"thmanyah1": {
			Name: "Thmanyah 1",
			URL:  "http://1789-181.123091763.it.com/live/710135_.m3u8",
			Type: "m3u8",
		},
		"alwan1": {
			Name: "Alwan Sports 1",
			URL:  "https://mo3ad.xyz:443/live/mo3ad100/mo3ad100/669.ts",
			Type: "direct",
		},
	    "alwan2": {
			Name: "Alwan Sports 2",
			URL:  "https://mo3ad.xyz:443/live/mo3ad100/mo3ad100/670.ts",
			Type: "direct",
		},
	    "alwan3": {
			Name: "Alwan Sports 3",
			URL:  "https://mo3ad.xyz:443/live/mo3ad100/mo3ad100/671.ts",
			Type: "direct",
		},
		"alwan4": {
			Name: "Alwan Sports 4",
			URL:  "https://mo3ad.xyz:443/live/mo3ad100/mo3ad100/672.ts",
			Type: "direct",
		},
		"duhoksports": {
			Name: "Duhok Sports",
			URL:  "http://halabja88.jyber.xyz/live/ottplayer/halabja8/804064.ts?token=SxAKVEBaQ14XUwYBBVYCD1VdBQRSB1cABAAEUVoFBw4JC1ADBQZUAVQTHBNGEEFcBQhpWAASCFcBAABTFUQTR0NXEGpaVkNeFwUHBgxVBAxGSRRFDV1XQA8ABlQKUFcFCAdXGRFCCAAXC15EWQgfGwEdQlQWXlMOalVUElAFAxQKXBdZXx5DC1tuVFRYBV1dRl8UAEYcEAtGQRNeVxMKWhwQAFxHQAAQUBMKX0AIXxVGBllECkRAGxcLEy1oREoUVUoWUF1BCAtbEwoTQRcRFUYMRW4WVUEWR1RQCVwURAwSAkAZEV8AHGpSX19bAVBNDQpYQkYKEFMXHRMJVggPQl9APUVaVkNeW0RcXUg",
			Type: "direct",
		},
		"nrtsports": {
			Name: "Nrt Sports",
			URL:  "https://cdn.karwan.tv/nrt-sport/tracks-v1a1/mono.m3u8",
			Type: "m3u8",
		},
	}
	
	// قائمة الروابط التي تحتاج فحص نوع المحتوى
	directStreamSources = []string{
		"hi-world.me",
		"play/live.php",
	}
	
	// إعدادات محسنة للاتصال مع timeout أقصر
	client = &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       60 * time.Second,
			DisableKeepAlives:     false,
			DisableCompression:    true,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("توقف بعد 10 عمليات إعادة توجيه")
			}
			for key, val := range via[0].Header {
				req.Header[key] = val
			}
			return nil
		},
	}
	
	// Cache للمحتوى لكل قناة
	channelCaches = make(map[string]*ChannelCache)
	cachesMutex   sync.RWMutex
	
	// Rate limiting
	rateLimiter = make(map[string]time.Time)
	rateMutex   sync.RWMutex
	
	// نظام المصادقة
	adminUsername = "admin"           // يمكن تغييره
	adminPassword = "stream123"       // يمكن تغييره
	sessions     = make(map[string]time.Time)
	sessionMutex sync.RWMutex
)

type ChannelCache struct {
	sync.RWMutex
	content   string
	timestamp time.Time
	baseURL   string
}

const (
	cacheTimeout     = 5 * time.Second
	rateLimit        = 1 * time.Second
	maxRequestSize   = 50 * 1024 * 1024
	connectionBuffer = 1000
	maxRetries       = 3
	channelsFile     = "saved_channels.json"
	sessionDuration  = 24 * time.Hour  // مدة الجلسة
	cookieName       = "stream_session"
)

// حفظ القنوات في ملف JSON
func saveChannels() error {
	mu.RLock()
	defer mu.RUnlock()
	
	data, err := json.MarshalIndent(channels, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(channelsFile, data, 0644)
}

// تحميل القنوات من ملف JSON
func loadChannels() error {
	if _, err := os.Stat(channelsFile); os.IsNotExist(err) {
		return nil // الملف غير موجود، لا مشكلة
	}
	
	data, err := os.ReadFile(channelsFile)
	if err != nil {
		return err
	}
	
	var savedChannels map[string]Channel
	if err := json.Unmarshal(data, &savedChannels); err != nil {
		return err
	}
	
	mu.Lock()
	// دمج القنوات المحفوظة مع القنوات الافتراضية
	for id, channel := range savedChannels {
		channels[id] = channel
	}
	mu.Unlock()
	
	log.Printf("✅ تم تحميل %d قناة من الملف المحفوظ", len(savedChannels))
	return nil
}

func init() {
	// تحميل القنوات المحفوظة أولاً
	if err := loadChannels(); err != nil {
		log.Printf("خطأ في تحميل القنوات المحفوظة: %v", err)
	}
	
	// إنشاء cache لكل قناة
	for channelID := range channels {
		channelCaches[channelID] = &ChannelCache{}
	}
}

// إنشاء معرف جلسة عشوائي
func generateSessionID() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

// تشفير كلمة المرور
func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return base64.URLEncoding.EncodeToString(hash[:])
}

// التحقق من كلمة المرور
func checkPassword(password, hash string) bool {
	return hashPassword(password) == hash
}

// إنشاء جلسة جديدة
func createSession() string {
	sessionID := generateSessionID()
	sessionMutex.Lock()
	sessions[sessionID] = time.Now().Add(sessionDuration)
	sessionMutex.Unlock()
	return sessionID
}

// التحقق من صحة الجلسة
func isValidSession(sessionID string) bool {
	sessionMutex.RLock()
	defer sessionMutex.RUnlock()
	
	expiry, exists := sessions[sessionID]
	if !exists {
		return false
	}
	
	if time.Now().After(expiry) {
		// انتهت صلاحية الجلسة
		delete(sessions, sessionID)
		return false
	}
	
	return true
}

// الحصول على معرف الجلسة من الطلب
func getSessionFromRequest(r *http.Request) string {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// التحقق من المصادقة
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := getSessionFromRequest(r)
		
		if sessionID == "" || !isValidSession(sessionID) {
			// إعادة توجيه لصفحة تسجيل الدخول
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		
		next(w, r)
	}
}

// تنظيف Cache والجلسات القديمة
func cleanupCache() {
	for {
		time.Sleep(30 * time.Second)
		
		now := time.Now()
		
		// تنظيف rateLimiter
		rateMutex.Lock()
		for ip, lastRequest := range rateLimiter {
			if now.Sub(lastRequest) > 10*time.Minute {
				delete(rateLimiter, ip)
			}
		}
		rateMutex.Unlock()
		
		// تنظيف الجلسات المنتهية الصلاحية
		sessionMutex.Lock()
		for sessionID, expiry := range sessions {
			if now.After(expiry) {
				delete(sessions, sessionID)
			}
		}
		sessionMutex.Unlock()
	}
}

// فحص Rate Limiting
func checkRateLimit(ip string) bool {
	rateMutex.Lock()
	defer rateMutex.Unlock()
	
	lastRequest, exists := rateLimiter[ip]
	now := time.Now()
	
	if exists && now.Sub(lastRequest) < rateLimit {
		return false
	}
	
	rateLimiter[ip] = now
	return true
}

// الحصول على IP العميل
func getClientIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		return strings.Split(forwarded, ",")[0]
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}

// فحص إذا كان الرابط يحتاج فحص نوع المحتوى
func needsContentTypeCheck(url string) bool {
	for _, source := range directStreamSources {
		if strings.Contains(url, source) {
			return true
		}
	}
	return false
}

// فحص نوع المحتوى للرابط
func checkContentType(url string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		log.Printf("خطأ في إنشاء طلب HEAD: %v", err)
		return ""
	}
	
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")
	
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("خطأ في طلب HEAD: %v", err)
		return checkContentTypeWithGet(url)
	}
	defer resp.Body.Close()
	
	contentType := resp.Header.Get("Content-Type")
	log.Printf("Content-Type من HEAD: %s", contentType)
	return contentType
}

func checkContentTypeWithGet(url string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return ""
	}
	
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Range", "bytes=0-1023")
	
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	
	contentType := resp.Header.Get("Content-Type")
	log.Printf("Content-Type من GET محدود: %s", contentType)
	
	if contentType == "" || strings.Contains(contentType, "text") {
		buffer := make([]byte, 512)
		n, _ := resp.Body.Read(buffer)
		content := string(buffer[:n])
		
		if strings.Contains(content, "\x47") || len(content) > 100 {
			return "video/mp2t"
		}
		
		if strings.Contains(content, "#EXTM3U") {
			return "application/vnd.apple.mpegurl"
		}
	}
	
	return contentType
}

func doRequestWithRetry(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error
	
	log.Printf("محاولة الاتصال بـ: %s", req.URL.String())
	
	for i := 0; i < maxRetries; i++ {
		resp, err = client.Do(req)
		
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				log.Printf("نجح الاتصال: %s (المحاولة %d)", req.URL.String(), i+1)
				return resp, nil
			} else if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				log.Printf("إعادة توجيه: %s -> %d", req.URL.String(), resp.StatusCode)
				return resp, nil
			}
		}
		
		if resp != nil {
			log.Printf("فشل الاتصال: %s - Status: %d, Error: %v", req.URL.String(), resp.StatusCode, err)
			resp.Body.Close()
		} else {
			log.Printf("فشل الاتصال: %s - Error: %v", req.URL.String(), err)
		}
		
		if i < maxRetries-1 {
			waitTime := time.Duration(i+1) * 2 * time.Second
			log.Printf("إعادة المحاولة %d بعد %v للرابط: %s", i+2, waitTime, req.URL.String())
			time.Sleep(waitTime)
		}
	}
	
	return resp, err
}

func createDirectM3U8(streamURL, host, channelID string) string {
	encodedURL := url.QueryEscape(streamURL)
	localURL := fmt.Sprintf("http://%s/ts?url=%s&channel=%s", host, encodedURL, channelID)
	
	m3u8Content := fmt.Sprintf(`#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXT-X-MEDIA-SEQUENCE:0
#EXT-X-PLAYLIST-TYPE:EVENT
#EXTINF:3600.0,
%s
#EXT-X-ENDLIST
`, localURL)
	
	return m3u8Content
}

func rewriteM3U8Content(content string, host string, sourceBaseURL string, channelID string) string {
	var result strings.Builder
	result.Grow(len(content) + 1000)
	
	scanner := bufio.NewScanner(strings.NewReader(content))
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		if strings.HasPrefix(line, "#") || line == "" {
			result.WriteString(line + "\n")
		} else if strings.HasSuffix(line, ".ts") {
			var tsURL string
			if strings.HasPrefix(line, "http") {
				tsURL = line
			} else {
				tsURL = sourceBaseURL + line
			}
			
			encodedURL := url.QueryEscape(tsURL)
			localURL := fmt.Sprintf("http://%s/ts?url=%s&channel=%s", host, encodedURL, channelID)
			result.WriteString(localURL + "\n")
		} else if strings.HasSuffix(line, ".m3u8") {
			result.WriteString(fmt.Sprintf("http://%s/%s.m3u8\n", host, channelID))
		} else {
			result.WriteString(line + "\n")
		}
	}
	
	return result.String()
}

func getBaseURL(m3u8URL string) string {
	lastSlash := strings.LastIndex(m3u8URL, "/")
	if lastSlash == -1 {
		return m3u8URL
	}
	return m3u8URL[:lastSlash+1]
}

func tempStreamHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	if !checkRateLimit(clientIP) {
		http.Error(w, "كثرة الطلبات", http.StatusTooManyRequests)
		return
	}
	
	sourceURL := r.URL.Query().Get("url")
	streamType := r.URL.Query().Get("type")
	
	if sourceURL == "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("استخدم: /temp?url=رابط_البث&type=m3u8|direct"))
		return
	}
	
	if streamType == "" {
		if strings.Contains(sourceURL, ".m3u8") {
			streamType = "m3u8"
		} else {
			streamType = "direct"
		}
	}
	
	log.Printf("🔄 طلب بث مؤقت: %s (النوع: %s)", sourceURL, streamType)
	
	if streamType == "direct" {
		m3u8Content := createDirectM3U8(sourceURL, r.Host, "temp")
		
		w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		
		w.Write([]byte(m3u8Content))
		return
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, "GET", sourceURL, nil)
	if err != nil {
		http.Error(w, "خطأ في إنشاء الطلب", http.StatusInternalServerError)
		return
	}
	
	setOptimalHeaders(req, sourceURL)
	
	resp, err := doRequestWithRetry(req)
	if err != nil {
		log.Printf("فشل في جلب M3U8 المؤقت من %s: %v", sourceURL, err)
		http.Error(w, "فشل في جلب ملف M3U8: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		log.Printf("❌ فشل البث المؤقت: URL=%s, Status=%d", sourceURL, resp.StatusCode)
		http.Error(w, fmt.Sprintf("خطأ من المصدر: %d", resp.StatusCode), http.StatusBadGateway)
		return
	}
	
	limitedReader := io.LimitReader(resp.Body, maxRequestSize)
	content, err := io.ReadAll(limitedReader)
	if err != nil {
		log.Printf("فشل في قراءة المحتوى المؤقت: %v", err)
		http.Error(w, "فشل في قراءة المحتوى", http.StatusInternalServerError)
		return
	}
	
	baseURL := getBaseURL(sourceURL)
	rewrittenContent := rewriteM3U8Content(string(content), r.Host, baseURL, "temp")
	
	w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	
	w.Write([]byte(rewrittenContent))
	
	log.Printf("✅ نجح البث المؤقت: %s", sourceURL)
}

func setOptimalHeaders(req *http.Request, sourceURL string) {
	if strings.Contains(sourceURL, "ghosttv.art") {
		req.Header.Set("User-Agent", "VLC/3.0.18 LibVLC/3.0.18")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Cache-Control", "no-cache")
	} else if strings.Contains(sourceURL, "foxtv7.com") {
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "application/vnd.apple.mpegurl, video/*, */*")
		req.Header.Set("Referer", "https://foxtv7.com/")
		req.Header.Set("Origin", "https://foxtv7.com")
		req.Header.Set("X-Forwarded-For", "185.220.101.182")
	} else if strings.Contains(sourceURL, "footballii.ir") {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Referer", "https://footballii.ir/")
		req.Header.Set("X-Forwarded-For", "94.182.229.116")
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		req.Header.Set("Accept", "application/vnd.apple.mpegurl,video/*,*/*")
	}
	
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("DNT", "1")
}

func setSourceHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	if !checkRateLimit(clientIP) {
		http.Error(w, "كثرة الطلبات، حاول لاحقاً", http.StatusTooManyRequests)
		return
	}
	
	channelID := r.URL.Query().Get("channel")
	newURL := r.URL.Query().Get("url")
	channelType := r.URL.Query().Get("type")
	channelName := r.URL.Query().Get("name")
	
	if channelID == "" || newURL == "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("استخدم: /set_source?channel=channel_id&url=رابط_البث_الجديد&type=m3u8|direct&name=اسم_القناة"))
		return
	}
	
	if channelType == "" {
		if strings.Contains(newURL, ".m3u8") {
			channelType = "m3u8"
		} else {
			channelType = "direct"
		}
	}
	
	mu.Lock()
	if channel, exists := channels[channelID]; exists {
		channel.URL = newURL
		channel.Type = channelType
		if channelName != "" {
			channel.Name = channelName
		}
		channels[channelID] = channel
	} else {
		name := channelName
		if name == "" {
			name = channelID
		}
		channels[channelID] = Channel{
			Name: name,
			URL:  newURL,
			Type: channelType,
		}
		channelCaches[channelID] = &ChannelCache{}
	}
	mu.Unlock()
	
	// حفظ التغييرات في الملف
	if err := saveChannels(); err != nil {
		log.Printf("خطأ في حفظ القنوات: %v", err)
	}
	
	log.Printf("✅ تم إضافة/تحديث وحفظ القناة %s", channelID)
	
	// مسح الكاش عند تغيير المصدر
	cachesMutex.RLock()
	if cache, exists := channelCaches[channelID]; exists {
		cache.Lock()
		cache.content = ""
		cache.timestamp = time.Time{}
		cache.Unlock()
	}
	cachesMutex.RUnlock()
	
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(fmt.Sprintf("تم تحديث القناة %s (%s) إلى: %s", channelID, channelType, newURL)))
}

// معالج حذف القناة
func deleteSourceHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	if !checkRateLimit(clientIP) {
		http.Error(w, "كثرة الطلبات، حاول لاحقاً", http.StatusTooManyRequests)
		return
	}
	
	channelID := r.URL.Query().Get("channel")
	
	if channelID == "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("استخدم: /delete_source?channel=channel_id"))
		return
	}
	
	mu.Lock()
	_, exists := channels[channelID]
	if exists {
		delete(channels, channelID)
	}
	mu.Unlock()
	
	if !exists {
		http.Error(w, "القناة غير موجودة", http.StatusNotFound)
		return
	}
	
	// حفظ التغييرات في الملف
	if err := saveChannels(); err != nil {
		log.Printf("خطأ في حفظ القنوات بعد الحذف: %v", err)
	}
	
	// حذف الكاش
	cachesMutex.Lock()
	delete(channelCaches, channelID)
	cachesMutex.Unlock()
	
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(fmt.Sprintf("تم حذف القناة %s بنجاح", channelID)))
	log.Printf("✅ تم حذف وحفظ التغييرات للقناة %s", channelID)
}

func channelHandler(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	channelID := strings.TrimSuffix(path, ".m3u8")
	
	clientIP := getClientIP(r)
	if !checkRateLimit(clientIP) {
		http.Error(w, "كثرة الطلبات", http.StatusTooManyRequests)
		return
	}
	
	mu.RLock()
	channel, exists := channels[channelID]
	mu.RUnlock()
	
	if !exists {
		http.Error(w, "القناة غير موجودة", http.StatusNotFound)
		return
	}
	
	if channel.Type == "direct" {
		m3u8Content := createDirectM3U8(channel.URL, r.Host, channelID)
		
		w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		
		w.Write([]byte(m3u8Content))
		return
	}
	
	if needsContentTypeCheck(channel.URL) {
		contentType := checkContentType(channel.URL)
		log.Printf("🔍 فحص نوع المحتوى للقناة %s: %s", channelID, contentType)
		
		if strings.Contains(contentType, "video/mp2t") || strings.Contains(contentType, "video/ts") {
			log.Printf("📺 تحويل القناة %s إلى نوع مباشر بسبب محتوى TS", channelID)
			m3u8Content := createDirectM3U8(channel.URL, r.Host, channelID)
			
			w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "*")
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			
			w.Write([]byte(m3u8Content))
			return
		}
	}
	
	cachesMutex.RLock()
	cache := channelCaches[channelID]
	cachesMutex.RUnlock()
	
	cache.RLock()
	cached := cache.content
	cacheTime := cache.timestamp
	cachedBaseURL := cache.baseURL
	cache.RUnlock()
	
	if cached != "" && time.Since(cacheTime) < cacheTimeout {
		rewrittenContent := rewriteM3U8Content(cached, r.Host, cachedBaseURL, channelID)
		
		w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		
		w.Write([]byte(rewrittenContent))
		return
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, "GET", channel.URL, nil)
	if err != nil {
		http.Error(w, "خطأ في إنشاء الطلب", http.StatusInternalServerError)
		return
	}
	
	if strings.Contains(channel.URL, "foxtv7.com") {
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "application/vnd.apple.mpegurl, video/*, */*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9,ar;q=0.8")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		req.Header.Set("Referer", "https://foxtv7.com/")
		req.Header.Set("Origin", "https://foxtv7.com")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Ch-Ua", `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`)
		req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
		req.Header.Set("Sec-Ch-Ua-Platform", `"Linux"`)
		req.Header.Set("X-Forwarded-For", "185.220.101.182")
		req.Header.Set("X-Real-IP", "185.220.101.182")
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("Pragma", "no-cache")
	} else if strings.Contains(channel.URL, "footballii.ir") {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		req.Header.Set("Referer", "https://wo.cma.footballii.ir/")
		req.Header.Set("Origin", "https://footballii.ir")
		req.Header.Set("DNT", "1")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.Header.Set("X-Forwarded-For", "94.182.229.116")
		req.Header.Set("X-Real-IP", "94.182.229.116")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
	} else if strings.Contains(channel.URL, "karwan.tv") {
		req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1")
		req.Header.Set("Accept", "application/vnd.apple.mpegurl")
		req.Header.Set("Referer", "https://karwan.tv/")
		req.Header.Set("Origin", "https://karwan.tv")
		req.Header.Set("X-Forwarded-For", "89.187.171.150")
		req.Header.Set("X-Real-IP", "89.187.171.150")
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		req.Header.Set("Accept", "application/vnd.apple.mpegurl,video/*,*/*")
		req.Header.Set("Referer", "https://s3taku.com/")
		req.Header.Set("Origin", "https://s3taku.com")
	}
	
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("DNT", "1")
	
	resp, err := doRequestWithRetry(req)
	if err != nil {
		log.Printf("فشل في جلب M3U8 للقناة %s من %s: %v", channelID, channel.URL, err)
		http.Error(w, "فشل في جلب ملف M3U8: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	
	log.Printf("استجابة للقناة %s: Status=%d, Content-Type=%s, Content-Length=%s", 
		channelID, resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Get("Content-Length"))
	
	if resp.StatusCode != http.StatusOK {
		errorBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		log.Printf("❌ فشل القناة %s: Status=%d, Body=%s, Headers=%v", 
			channelID, resp.StatusCode, string(errorBody), resp.Header)
		
		if strings.Contains(channel.URL, "foxtv7.com") || strings.Contains(channel.URL, "footballii.ir") {
			log.Printf("🔄 محاولات إضافية للقناة %s مع headers متنوعة", channelID)
			
			userAgents := []string{
				"VLC/3.0.18 LibVLC/3.0.18",
				"FFmpeg/4.4.2",
				"Mozilla/5.0 (Smart TV; Tizen 4.0) AppleWebKit/537.36",
				"Mozilla/5.0 (PlayStation 4 9.00) AppleWebKit/605.1.15",
				"curl/7.68.0",
				"wget/1.20.3",
			}
			
			for i, ua := range userAgents {
				log.Printf("🔄 محاولة %d/%d مع UA: %s", i+1, len(userAgents), ua[:30]+"...")
				
				req2, _ := http.NewRequestWithContext(ctx, "GET", channel.URL, nil)
				req2.Header.Set("User-Agent", ua)
				req2.Header.Set("Accept", "*/*")
				req2.Header.Set("Connection", "close")
				
				if strings.Contains(channel.URL, "foxtv7.com") {
					req2.Header.Set("Referer", "https://foxtv7.com/")
				} else if strings.Contains(channel.URL, "footballii.ir") {
					req2.Header.Set("Referer", "https://footballii.ir/")
				}
				
				resp2, err2 := client.Do(req2)
				if err2 == nil && resp2.StatusCode == http.StatusOK {
					resp.Body.Close()
					resp = resp2
					log.Printf("✅ نجحت المحاولة الإضافية %d للقناة %s", i+1, channelID)
					break
				} else if resp2 != nil {
					resp2.Body.Close()
				}
				
				time.Sleep(time.Millisecond * 500)
			}
		}
		
		if resp.StatusCode != http.StatusOK {
			http.Error(w, fmt.Sprintf("خطأ من المصدر: %d", resp.StatusCode), http.StatusBadGateway)
			return
		}
	}
	
	limitedReader := io.LimitReader(resp.Body, maxRequestSize)
	content, err := io.ReadAll(limitedReader)
	if err != nil {
		log.Printf("فشل في قراءة المحتوى للقناة %s: %v", channelID, err)
		http.Error(w, "فشل في قراءة المحتوى", http.StatusInternalServerError)
		return
	}
	
	baseURL := getBaseURL(channel.URL)
	
	cache.Lock()
	cache.content = string(content)
	cache.timestamp = time.Now()
	cache.baseURL = baseURL
	cache.Unlock()
	
	rewrittenContent := rewriteM3U8Content(string(content), r.Host, baseURL, channelID)
	
	w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	
	w.Write([]byte(rewrittenContent))
}

func tsHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	if !checkRateLimit(clientIP) {
		http.Error(w, "كثرة الطلبات", http.StatusTooManyRequests)
		return
	}
	
	tsURL := r.URL.Query().Get("url")
	if tsURL == "" {
		http.Error(w, "رابط TS مطلوب", http.StatusBadRequest)
		return
	}
	
	decodedURL, err := url.QueryUnescape(tsURL)
	if err != nil {
		http.Error(w, "رابط غير صحيح", http.StatusBadRequest)
		return
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, "GET", decodedURL, nil)
	if err != nil {
		http.Error(w, "خطأ في إنشاء الطلب", http.StatusInternalServerError)
		return
	}
	
	if strings.Contains(decodedURL, "ghosttv.art") {
		req.Header.Set("User-Agent", "VLC/3.0.18 LibVLC/3.0.18")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Cache-Control", "no-cache")
	} else if strings.Contains(decodedURL, "foxtv7.com") {
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
		req.Header.Set("Accept", "video/mp2t,video/*,*/*")
		req.Header.Set("Referer", "https://foxtv7.com/")
		req.Header.Set("X-Forwarded-For", "185.220.101.182")
		req.Header.Set("X-Real-IP", "185.220.101.182")
	} else if strings.Contains(decodedURL, "footballii.ir") {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0")
		req.Header.Set("Accept", "video/mp2t,video/*,*/*")
		req.Header.Set("Referer", "https://footballii.ir/")
		req.Header.Set("X-Forwarded-For", "94.182.229.116")
		req.Header.Set("X-Real-IP", "94.182.229.116")
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		req.Header.Set("Accept", "video/mp2t,video/*,*/*")
		req.Header.Set("Referer", "https://s3taku.com/")
		req.Header.Set("Origin", "https://s3taku.com")
	}
	
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("DNT", "1")
	
	if rangeHeader := r.Header.Get("Range"); rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}
	
	resp, err := doRequestWithRetry(req)
	if err != nil {
		log.Printf("فشل في جلب ملف TS: %v", err)
		http.Error(w, "فشل في جلب ملف TS: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		errorBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		log.Printf("❌ فشل ملف TS: URL=%s, Status=%d, Body=%s", decodedURL, resp.StatusCode, string(errorBody))
		http.Error(w, fmt.Sprintf("خطأ من المصدر: %d", resp.StatusCode), http.StatusBadGateway)
		return
	}
	
	log.Printf("✅ نجح تحميل ملف TS: %s (Status: %d)", decodedURL, resp.StatusCode)
	
	w.Header().Set("Content-Type", "video/mp2t")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Accept-Ranges", "bytes")
	
	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		w.Header().Set("Content-Length", contentLength)
	}
	
	if contentRange := resp.Header.Get("Content-Range"); contentRange != "" {
		w.Header().Set("Content-Range", contentRange)
	}
	
	w.WriteHeader(resp.StatusCode)
	
	buffer := make([]byte, 32*1024)
	_, err = io.CopyBuffer(w, resp.Body, buffer)
	if err != nil {
		log.Printf("خطأ في نسخ محتوى TS: %v", err)
	}
}

// صفحة تسجيل الدخول
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		
		if username == adminUsername && password == adminPassword {
			// إنشاء جلسة جديدة
			sessionID := createSession()
			
			// تعيين الكوكيز
			http.SetCookie(w, &http.Cookie{
				Name:     cookieName,
				Value:    sessionID,
				Path:     "/",
				MaxAge:   int(sessionDuration.Seconds()),
				HttpOnly: true,
				Secure:   false, // تعيين إلى true في HTTPS
				SameSite: http.SameSiteLaxMode,
			})
			
			// إعادة توجيه للصفحة الرئيسية
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		} else {
			// بيانات خاطئة
			w.WriteHeader(http.StatusUnauthorized)
			showLoginForm(w, "اسم المستخدم أو كلمة المرور غير صحيحة")
			return
		}
	}
	
	// عرض نموذج تسجيل الدخول
	showLoginForm(w, "")
}

func showLoginForm(w http.ResponseWriter, errorMsg string) {
	errorHTML := ""
	if errorMsg != "" {
		errorHTML = fmt.Sprintf(`<div style="color: red; margin-bottom: 15px; padding: 10px; border: 1px solid red; border-radius: 5px; background: #ffe6e6;">%s</div>`, errorMsg)
	}
	
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>auth</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            width: 100%%;
            max-width: 400px;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            color: #333;
            margin: 0;
            font-size: 24px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #555;
            font-weight: bold;
        }
        input[type="text"], input[type="password"] {
            width: 100%%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
            box-sizing: border-box;
            transition: border-color 0.3s;
        }
        input[type="text"]:focus, input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
        }
        .login-btn {
            width: 100%%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .login-btn:hover {
            transform: translateY(-2px);
        }
        .info {
            margin-top: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
            font-size: 14px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>auth</h1>
            <p style="color: #888; margin: 5px 0 0 0;">لوحة الإدارة</p>
        </div>
        
        %s
        
        <form method="POST">
            <div class="form-group">
                <label for="username">اسم المستخدم:</label>
                <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
                <label for="password">كلمة المرور:</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit" class="login-btn">دخول</button>
        </form>
        
        <div class="info">
            <strong>ملاحظة:</strong> هذه الصفحة لإدارة الموقع فقط. روابط البث المباشر تعمل بدون تسجيل دخول.
        </div>
    </div>
</body>
</html>`, errorHTML)
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// صفحة تسجيل الخروج
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionFromRequest(r)
	
	if sessionID != "" {
		sessionMutex.Lock()
		delete(sessions, sessionID)
		sessionMutex.Unlock()
	}
	
	// حذف الكوكيز
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	
	// إعادة توجيه لصفحة تسجيل الدخول
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>القنوات</title>
    <style>
        body {
            font-family: Arial;
            margin: 20px;
            background: white;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #ccc;
        }
        h1 {
            color: #000;
            margin: 0;
        }
        .logout-btn {
            padding: 8px 15px;
            background: #dc3545;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            font-size: 14px;
        }
        .logout-btn:hover {
            background: #c82333;
        }
        .channel {
            margin: 10px 0;
            padding: 10px;
            border: 1px solid #ccc;
            position: relative;
        }
        .name {
            font-weight: bold;
            margin-bottom: 5px;
        }
        .url {
            font-size: 12px;
            color: #666;
            word-break: break-all;
            margin-bottom: 5px;
        }
        button {
            padding: 5px 10px;
            margin: 2px;
            border: 1px solid #ccc;
            background: #f5f5f5;
            cursor: pointer;
        }
        .delete-btn {
            background: #ff4444;
            color: white;
            border-color: #cc0000;
        }
        .delete-btn:hover {
            background: #cc0000;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>القنوات المتاحة</h1>
        <a href="/logout" class="logout-btn">تسجيل الخروج</a>
    </div>`)
	
	mu.RLock()
	for channelID, channel := range channels {
		streamURL := fmt.Sprintf("http://%s/%s.m3u8", r.Host, channelID)
		
		html += fmt.Sprintf(`
    <div class="channel">
        <div class="name">%s</div>
        <div class="url">%s</div>
        <button onclick="copyToClipboard('%s')">نسخ</button>
        <button onclick="window.open('%s')">فتح</button>
        <button class="delete-btn" onclick="deleteChannel('%s')">حذف</button>
    </div>`, channel.Name, streamURL, streamURL, streamURL, channelID)
	}
	mu.RUnlock()
	
	html += `
    
    <div style="margin-top: 30px; padding: 20px; border: 2px solid #28a745; border-radius: 5px;">
        <h2>بث مؤقت (بدون حفظ)</h2>
        <form onsubmit="tempStream(event)">
            <div style="margin: 10px 0;">
                <label>رابط المصدر:</label><br>
                <input type="url" id="tempUrl" placeholder="https://example.com/stream.m3u8" style="width: 400px; padding: 5px;" required>
            </div>
            <div style="margin: 10px 0;">
                <label>نوع المصدر:</label><br>
                <select id="tempType" style="padding: 5px;">
                    <option value="m3u8">M3U8 Playlist</option>
                    <option value="direct">مباشر (TS/MP4)</option>
                </select>
            </div>
            <button type="submit" style="padding: 10px 20px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer;">
                إنشاء رابط البث
            </button>
        </form>
        <div id="tempResult" style="margin-top: 15px; padding: 10px; background: #f8f9fa; border-radius: 5px; display: none;">
            <strong>رابط البث المؤقت:</strong><br>
            <input type="text" id="tempStreamUrl" readonly style="width: 400px; padding: 5px; margin: 5px 0;">
            <button onclick="copyToClipboard(document.getElementById('tempStreamUrl').value)" style="padding: 5px 10px; margin-left: 5px;">نسخ</button>
            <button onclick="window.open(document.getElementById('tempStreamUrl').value)" style="padding: 5px 10px; margin-left: 5px;">فتح</button>
        </div>
    </div>

    <div style="margin-top: 30px; padding: 20px; border: 2px solid #007bff; border-radius: 5px;">
        <h2>إضافة مصدر جديد (يُحفظ بشكل دائم)</h2>
        <form onsubmit="addNewSource(event)">
            <div style="margin: 10px 0;">
                <label>معرف القناة:</label><br>
                <input type="text" id="channelId" placeholder="مثال: bein2" style="width: 200px; padding: 5px;" required>
            </div>
            <div style="margin: 10px 0;">
                <label>اسم القناة:</label><br>
                <input type="text" id="channelName" placeholder="مثال: Bein Sports 2" style="width: 200px; padding: 5px;" required>
            </div>
            <div style="margin: 10px 0;">
                <label>رابط المصدر:</label><br>
                <input type="url" id="sourceUrl" placeholder="https://example.com/stream.m3u8" style="width: 400px; padding: 5px;" required>
            </div>
            <div style="margin: 10px 0;">
                <label>نوع المصدر:</label><br>
                <select id="sourceType" style="padding: 5px;">
                    <option value="m3u8">M3U8 Playlist</option>
                    <option value="direct">مباشر (TS/MP4)</option>
                </select>
            </div>
            <button type="submit" style="padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer;">
                إضافة المصدر
            </button>
        </form>
    </div>

    <script>
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => alert('تم النسخ'));
        }
        
        function deleteChannel(channelId) {
            if (confirm('هل أنت متأكد من حذف القناة: ' + channelId + '?')) {
                fetch('/delete_source?channel=' + encodeURIComponent(channelId))
                    .then(response => response.text())
                    .then(data => {
                        alert('تم حذف القناة: ' + data);
                        window.location.reload();
                    })
                    .catch(error => {
                        alert('خطأ في حذف القناة: ' + error);
                    });
            }
        }
        
        function tempStream(event) {
            event.preventDefault();
            
            const tempUrl = document.getElementById('tempUrl').value;
            const tempType = document.getElementById('tempType').value;
            
            if (!tempUrl) {
                alert('يرجى إدخال رابط المصدر');
                return;
            }
            
            const streamUrl = '/temp?url=' + encodeURIComponent(tempUrl) + '&type=' + encodeURIComponent(tempType);
            const fullStreamUrl = window.location.protocol + '//' + window.location.host + streamUrl;
            
            document.getElementById('tempStreamUrl').value = fullStreamUrl;
            document.getElementById('tempResult').style.display = 'block';
            
            alert('تم إنشاء رابط البث المؤقت!');
        }
        
        function addNewSource(event) {
            event.preventDefault();
            
            const channelId = document.getElementById('channelId').value;
            const channelName = document.getElementById('channelName').value;
            const sourceUrl = document.getElementById('sourceUrl').value;
            const sourceType = document.getElementById('sourceType').value;
            
            if (!channelId || !sourceUrl) {
                alert('يرجى ملء جميع الحقول المطلوبة');
                return;
            }
            
            const setSourceUrl = '/set_source?channel=' + encodeURIComponent(channelId) + 
                                 '&url=' + encodeURIComponent(sourceUrl) + 
                                 '&type=' + encodeURIComponent(sourceType) +
                                 '&name=' + encodeURIComponent(channelName);
            
            fetch(setSourceUrl)
                .then(response => response.text())
                .then(data => {
                    alert('تم إضافة المصدر بنجاح: ' + data);
                    window.location.reload();
                })
                .catch(error => {
                    alert('خطأ في إضافة المصدر: ' + error);
                });
        }
    </script>
</body>
</html>`
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func dynamicChannelHandler(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if strings.HasSuffix(path, ".m3u8") {
		channelHandler(w, r)
	} else {
		http.NotFound(w, r)
	}
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	
	go cleanupCache()
	
	server := &http.Server{
		Addr:           "0.0.0.0:" + port,
		ReadTimeout:    60 * time.Second,
		WriteTimeout:   60 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			requireAuth(indexHandler)(w, r)
			return
		}
		// روابط البث تعمل بدون مصادقة
		dynamicChannelHandler(w, r)
	})
	
	// روابط البث المباشر - بدون مصادقة
	http.HandleFunc("/ts", tsHandler)
	
	// روابط الإدارة - تتطلب مصادقة
	http.HandleFunc("/set_source", requireAuth(setSourceHandler))
	http.HandleFunc("/delete_source", requireAuth(deleteSourceHandler))
	http.HandleFunc("/temp", requireAuth(tempStreamHandler))
	
	log.Printf("🚀 خادم البث المحسن يعمل على المنفذ %s", port)
	log.Printf("🌐 الصفحة الرئيسية: http://0.0.0.0:%s", port)
	log.Printf("📺 القنوات المتاحة:")
	
	mu.RLock()
	for channelID, channel := range channels {
		log.Printf("   - %s (%s): http://0.0.0.0:%s/%s.m3u8", channel.Name, channel.Type, port, channelID)
	}
	mu.RUnlock()
	
	log.Printf("⚡ التحسينات: Direct Streaming, Retry Logic, Enhanced Headers")
	log.Printf("💾 نظام الحفظ: المصادر الجديدة تُحفظ بشكل دائم في %s", channelsFile)
	
	log.Fatal(server.ListenAndServe())
}
