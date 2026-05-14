package main

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	pathpkg "path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"golang.org/x/net/webdav"
)

const (
	defaultHTTPPort   = ":18090"
	davPrefix         = "/dav/"
	configPath        = "./disk_config.json"
	maxTextPreviewLen = 256 * 1024
	uploadMemoryLimit = 64 << 20
	listCacheTTL      = 3 * time.Second
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AppConfig struct {
	Root   string      `json:"root"`
	Users  []User      `json:"users"`
	Shares []ShareItem `json:"shares"`
}

type FileItem struct {
	Name     string `json:"name"`
	IsDir    bool   `json:"is_dir"`
	Size     int64  `json:"size"`
	Path     string `json:"path"`
	Modified string `json:"modified"`
}

type batchPathRequest struct {
	Paths []string `json:"paths"`
}

type DirectoryItem struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type ShareItem struct {
	Token      string `json:"token"`
	Name       string `json:"name"`
	FullPath   string `json:"full_path"`
	Permission string `json:"permission"`
	IsDir      bool   `json:"is_dir"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
	CreatedBy  string `json:"created_by"`
}

type dynamicWebDAVFS struct{}

type listCacheEntry struct {
	Items      []FileItem
	ExpiresAt  time.Time
	Generation uint64
}

var (
	defaultConfig = AppConfig{
		Root: "./files",
		Users: []User{
			{Username: "admin", Password: "123456"},
		},
	}
	cfgMu         sync.RWMutex
	appConfig     = cloneConfig(defaultConfig)
	davLockSystem = webdav.NewMemLS()
	errBadPath    = errors.New("invalid path")
	listCacheMu   sync.RWMutex
	listCache     = map[string]listCacheEntry{}
	listGen       uint64
)

const (
	sharePermissionDownload = "download"
	sharePermissionView     = "view"
	sharePermissionEdit     = "edit"
)

func main() {
	loadConfig()
	if err := os.MkdirAll(getCurrentRoot(), 0755); err != nil {
		log.Fatal(err)
	}

	httpPort := getHTTPPort()

	http.HandleFunc("/api/disks", basicAuthFunc(apiGetDisks))
	http.HandleFunc("/api/directories", basicAuthFunc(apiGetDirectories))
	http.HandleFunc("/api/mount", basicAuthFunc(apiMountDisk))
	http.HandleFunc("/api/list", basicAuthFunc(apiList))
	http.HandleFunc("/api/shares", basicAuthFunc(apiShares))
	http.HandleFunc("/api/mkdir", basicAuthFunc(apiMkdir))
	http.HandleFunc("/api/upload", basicAuthFunc(apiUpload))
	http.HandleFunc("/api/delete", basicAuthFunc(apiDelete))
	http.HandleFunc("/api/download", basicAuthFunc(apiDownload))
	http.HandleFunc("/api/preview", basicAuthFunc(apiPreview))
	http.HandleFunc("/api/zip", basicAuthFunc(apiZip))
	http.HandleFunc("/api/unzip", basicAuthFunc(apiUnzip))
	http.HandleFunc("/api/account", basicAuthFunc(apiAccount))
	http.HandleFunc("/share/", serveShare)
	http.Handle(davPrefix, basicAuth(http.HandlerFunc(serveWebDAV)))
	http.HandleFunc("/", basicAuthFunc(page))

	log.Println("HTTP: http://127.0.0.1" + httpPort)
	log.Println("WebDAV: http://127.0.0.1" + httpPort + davPrefix)
	log.Fatal(http.ListenAndServe(httpPort, nil))
}

func getHTTPPort() string {
	port := strings.TrimSpace(os.Getenv("GOWEBDAV_PORT"))
	if port == "" {
		return defaultHTTPPort
	}
	if !strings.HasPrefix(port, ":") {
		port = ":" + port
	}
	return port
}

func loadConfig() {
	cfg := cloneConfig(defaultConfig)

	data, err := os.ReadFile(configPath)
	if err == nil {
		var saved AppConfig
		if json.Unmarshal(data, &saved) == nil {
			if strings.TrimSpace(saved.Root) != "" {
				cfg.Root = strings.TrimSpace(saved.Root)
			}
			users := sanitizeUsers(saved.Users)
			if len(users) > 0 {
				cfg.Users = users
			}
			cfg.Shares = sanitizeShares(saved.Shares)
		}
	}

	cfgMu.Lock()
	appConfig = cfg
	cfgMu.Unlock()

	if err := writeConfig(cfg); err != nil {
		log.Printf("save config failed: %v", err)
	}
}

func writeConfig(cfg AppConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, 0644)
}

func cloneConfig(src AppConfig) AppConfig {
	dst := AppConfig{
		Root:   src.Root,
		Users:  make([]User, 0, len(src.Users)),
		Shares: make([]ShareItem, 0, len(src.Shares)),
	}
	dst.Users = append(dst.Users, src.Users...)
	dst.Shares = append(dst.Shares, src.Shares...)
	return dst
}

func sanitizeUsers(users []User) []User {
	valid := make([]User, 0, len(users))
	for _, user := range users {
		username := strings.TrimSpace(user.Username)
		if username == "" || user.Password == "" {
			continue
		}
		valid = append(valid, User{
			Username: username,
			Password: user.Password,
		})
	}
	return valid
}

func sanitizeShares(shares []ShareItem) []ShareItem {
	valid := make([]ShareItem, 0, len(shares))
	for _, share := range shares {
		token := strings.TrimSpace(share.Token)
		fullPath := strings.TrimSpace(share.FullPath)
		permission, ok := normalizeSharePermission(share.Permission)
		if token == "" || fullPath == "" || !ok {
			continue
		}

		name := strings.TrimSpace(share.Name)
		if name == "" {
			name = filepath.Base(fullPath)
		}

		createdAt := share.CreatedAt
		if createdAt == "" {
			createdAt = time.Now().Format("2006-01-02 15:04:05")
		}

		updatedAt := share.UpdatedAt
		if updatedAt == "" {
			updatedAt = createdAt
		}

		valid = append(valid, ShareItem{
			Token:      token,
			Name:       name,
			FullPath:   fullPath,
			Permission: permission,
			IsDir:      share.IsDir,
			CreatedAt:  createdAt,
			UpdatedAt:  updatedAt,
			CreatedBy:  strings.TrimSpace(share.CreatedBy),
		})
	}
	return valid
}

func getCurrentRoot() string {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return appConfig.Root
}

func setCurrentRoot(root string) error {
	cfgMu.Lock()
	appConfig.Root = root
	snapshot := cloneConfig(appConfig)
	cfgMu.Unlock()
	if err := writeConfig(snapshot); err != nil {
		return err
	}
	invalidateListCache()
	return nil
}

func getShares() []ShareItem {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	items := make([]ShareItem, 0, len(appConfig.Shares))
	items = append(items, appConfig.Shares...)
	return items
}

func normalizeSharePermission(permission string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(permission)) {
	case sharePermissionDownload:
		return sharePermissionDownload, true
	case sharePermissionView:
		return sharePermissionView, true
	case sharePermissionEdit:
		return sharePermissionEdit, true
	default:
		return "", false
	}
}

func createShareLink(name, fullPath, permission, createdBy string, isDir bool) (ShareItem, error) {
	now := time.Now().Format("2006-01-02 15:04:05")
	token, err := newShareToken()
	if err != nil {
		return ShareItem{}, err
	}

	share := ShareItem{
		Token:      token,
		Name:       name,
		FullPath:   fullPath,
		Permission: permission,
		IsDir:      isDir,
		CreatedAt:  now,
		UpdatedAt:  now,
		CreatedBy:  createdBy,
	}

	cfgMu.Lock()
	appConfig.Shares = append(appConfig.Shares, share)
	snapshot := cloneConfig(appConfig)
	cfgMu.Unlock()

	if err := writeConfig(snapshot); err != nil {
		return ShareItem{}, err
	}
	return share, nil
}

func updateSharePermission(token, permission string) (ShareItem, error) {
	cfgMu.Lock()
	defer cfgMu.Unlock()

	for i := range appConfig.Shares {
		if appConfig.Shares[i].Token != token {
			continue
		}
		appConfig.Shares[i].Permission = permission
		appConfig.Shares[i].UpdatedAt = time.Now().Format("2006-01-02 15:04:05")
		snapshot := cloneConfig(appConfig)
		if err := writeConfig(snapshot); err != nil {
			return ShareItem{}, err
		}
		return appConfig.Shares[i], nil
	}
	return ShareItem{}, os.ErrNotExist
}

func deleteShare(token string) error {
	cfgMu.Lock()
	defer cfgMu.Unlock()

	for i := range appConfig.Shares {
		if appConfig.Shares[i].Token != token {
			continue
		}
		appConfig.Shares = append(appConfig.Shares[:i], appConfig.Shares[i+1:]...)
		return writeConfig(cloneConfig(appConfig))
	}
	return os.ErrNotExist
}

func findShare(token string) (ShareItem, bool) {
	cfgMu.RLock()
	defer cfgMu.RUnlock()

	for _, share := range appConfig.Shares {
		if share.Token == token {
			return share, true
		}
	}
	return ShareItem{}, false
}

func newShareToken() (string, error) {
	buf := make([]byte, 9)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", buf), nil
}

func findUser(username, password string) (int, User, bool) {
	cfgMu.RLock()
	defer cfgMu.RUnlock()

	for i, user := range appConfig.Users {
		if user.Username == username && user.Password == password {
			return i, user, true
		}
	}
	return -1, User{}, false
}

func authenticateRequest(r *http.Request) (int, User, bool) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return -1, User{}, false
	}
	return findUser(username, password)
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="gowebdav"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func basicAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := authenticateRequest(r); !ok {
			unauthorized(w)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func basicAuthFunc(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := authenticateRequest(r); !ok {
			unauthorized(w)
			return
		}
		fn(w, r)
	}
}

func serveWebDAV(w http.ResponseWriter, r *http.Request) {
	handler := &webdav.Handler{
		Prefix:     davPrefix,
		FileSystem: dynamicWebDAVFS{},
		LockSystem: davLockSystem,
	}
	handler.ServeHTTP(w, r)
}

func (dynamicWebDAVFS) Mkdir(_ context.Context, name string, perm os.FileMode) error {
	full, err := resolvePath(getCurrentRoot(), name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(full, perm); err != nil {
		return err
	}
	invalidateListCache()
	return nil
}

func (dynamicWebDAVFS) OpenFile(_ context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	full, err := resolvePath(getCurrentRoot(), name)
	if err != nil {
		return nil, err
	}
	if flag&(os.O_CREATE|os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_TRUNC) != 0 {
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			return nil, err
		}
	}
	file, err := os.OpenFile(full, flag, perm)
	if err == nil && flag&(os.O_CREATE|os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_TRUNC) != 0 {
		invalidateListCache()
	}
	return file, err
}

func (dynamicWebDAVFS) RemoveAll(_ context.Context, name string) error {
	if cleanVirtualPath(name) == "/" {
		return errors.New("cannot remove root")
	}
	full, err := resolvePath(getCurrentRoot(), name)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(full); err != nil {
		return err
	}
	invalidateListCache()
	return nil
}

func (dynamicWebDAVFS) Rename(_ context.Context, oldName, newName string) error {
	oldFull, err := resolvePath(getCurrentRoot(), oldName)
	if err != nil {
		return err
	}
	newFull, err := resolvePath(getCurrentRoot(), newName)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(newFull), 0755); err != nil {
		return err
	}
	if err := os.Rename(oldFull, newFull); err != nil {
		return err
	}
	invalidateListCache()
	return nil
}

func (dynamicWebDAVFS) Stat(_ context.Context, name string) (os.FileInfo, error) {
	full, err := resolvePath(getCurrentRoot(), name)
	if err != nil {
		return nil, err
	}
	return os.Stat(full)
}

func cleanVirtualPath(input string) string {
	normalized := strings.ReplaceAll(strings.TrimSpace(input), "\\", "/")
	if normalized == "" {
		return "/"
	}
	cleaned := pathpkg.Clean("/" + normalized)
	if cleaned == "." {
		return "/"
	}
	return cleaned
}

func resolvePath(root, virtualPath string) (string, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}

	cleaned := cleanVirtualPath(virtualPath)
	rel := filepath.FromSlash(strings.TrimPrefix(cleaned, "/"))
	fullAbs, err := filepath.Abs(filepath.Join(rootAbs, rel))
	if err != nil {
		return "", err
	}

	relCheck, err := filepath.Rel(rootAbs, fullAbs)
	if err != nil {
		return "", errBadPath
	}
	if relCheck == ".." || strings.HasPrefix(relCheck, ".."+string(os.PathSeparator)) {
		return "", errBadPath
	}
	return fullAbs, nil
}

func writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(data)
}

func cloneFileItems(items []FileItem) []FileItem {
	if len(items) == 0 {
		return []FileItem{}
	}
	cloned := make([]FileItem, len(items))
	copy(cloned, items)
	return cloned
}

func invalidateListCache() {
	atomic.AddUint64(&listGen, 1)
	listCacheMu.Lock()
	clear(listCache)
	listCacheMu.Unlock()
}

func cachedFileItems(fullPath string) ([]FileItem, bool) {
	listCacheMu.RLock()
	entry, ok := listCache[fullPath]
	listCacheMu.RUnlock()
	if !ok {
		return nil, false
	}
	if entry.Generation != atomic.LoadUint64(&listGen) || time.Now().After(entry.ExpiresAt) {
		return nil, false
	}
	return cloneFileItems(entry.Items), true
}

func storeFileItems(fullPath string, items []FileItem) {
	listCacheMu.Lock()
	listCache[fullPath] = listCacheEntry{
		Items:      cloneFileItems(items),
		ExpiresAt:  time.Now().Add(listCacheTTL),
		Generation: atomic.LoadUint64(&listGen),
	}
	listCacheMu.Unlock()
}

func normalizeVirtualPaths(rawPaths []string) []string {
	if len(rawPaths) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(rawPaths))
	paths := make([]string, 0, len(rawPaths))
	for _, raw := range rawPaths {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		cleaned := cleanVirtualPath(trimmed)
		if _, ok := seen[cleaned]; ok {
			continue
		}
		seen[cleaned] = struct{}{}
		paths = append(paths, cleaned)
	}
	return paths
}

func readBatchPaths(r *http.Request) ([]string, error) {
	if strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		var req batchPathRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, err
		}
		paths := normalizeVirtualPaths(req.Paths)
		if len(paths) == 0 {
			return nil, errors.New("paths are required")
		}
		return paths, nil
	}

	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	rawPaths := append([]string{}, r.Form["paths"]...)
	rawPaths = append(rawPaths, r.Form["path"]...)
	paths := normalizeVirtualPaths(rawPaths)
	if len(paths) == 0 {
		return nil, errors.New("paths are required")
	}
	return paths, nil
}

func collectUploadFiles(form *multipart.Form) []*multipart.FileHeader {
	if form == nil || len(form.File) == 0 {
		return nil
	}
	files := make([]*multipart.FileHeader, 0)
	if named := form.File["files"]; len(named) > 0 {
		files = append(files, named...)
	}
	if named := form.File["file"]; len(named) > 0 {
		files = append(files, named...)
	}
	if len(files) > 0 {
		return files
	}
	for _, headers := range form.File {
		files = append(files, headers...)
	}
	return files
}

func sanitizeUploadName(name string) string {
	normalized := strings.ReplaceAll(strings.TrimSpace(name), "\\", "/")
	return pathpkg.Base(normalized)
}

func saveUploadedFile(targetDir string, header *multipart.FileHeader) error {
	filename := sanitizeUploadName(header.Filename)
	if filename == "." || filename == "/" || filename == "" {
		return errors.New("invalid file name")
	}

	src, err := header.Open()
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(filepath.Join(targetDir, filename))
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	return err
}

func previewKindFromName(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg":
		return "image"
	case ".mp4", ".webm", ".ogg", ".mov", ".m4v":
		return "video"
	case ".mp3", ".wav", ".m4a", ".flac", ".aac", ".oga":
		return "audio"
	case ".pdf":
		return "pdf"
	case ".txt", ".md", ".markdown", ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".log", ".csv",
		".xml", ".html", ".htm", ".css", ".js", ".jsx", ".ts", ".tsx", ".vue", ".go", ".py", ".java",
		".rb", ".rs", ".php", ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".sh", ".bash", ".ps1", ".sql":
		return "text"
	default:
		return ""
	}
}

func looksLikeText(sample []byte) bool {
	if len(sample) == 0 {
		return true
	}
	if !utf8.Valid(sample) {
		return false
	}
	for _, b := range sample {
		if b == 0 {
			return false
		}
	}
	return true
}

func previewKindForFile(name string, sample []byte) string {
	if kind := previewKindFromName(name); kind != "" {
		return kind
	}

	contentType := strings.ToLower(http.DetectContentType(sample))
	switch {
	case strings.HasPrefix(contentType, "image/"):
		return "image"
	case strings.HasPrefix(contentType, "video/"):
		return "video"
	case strings.HasPrefix(contentType, "audio/"):
		return "audio"
	case contentType == "application/pdf":
		return "pdf"
	case strings.HasPrefix(contentType, "text/"),
		strings.Contains(contentType, "json"),
		strings.Contains(contentType, "xml"),
		strings.Contains(contentType, "javascript"):
		return "text"
	case looksLikeText(sample):
		return "text"
	default:
		return ""
	}
}

func buildFileItems(fullDir, virtualPath string) ([]FileItem, error) {
	entries, err := os.ReadDir(fullDir)
	if err != nil {
		return nil, err
	}

	if len(entries) == 0 {
		return []FileItem{}, nil
	}

	results := make([]FileItem, len(entries))
	valid := make([]bool, len(entries))

	workerCount := runtime.NumCPU() * 2
	if workerCount < 4 {
		workerCount = 4
	}
	if workerCount > len(entries) {
		workerCount = len(entries)
	}
	if workerCount > 16 {
		workerCount = 16
	}

	jobs := make(chan int)
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				entry := entries[idx]
				info, infoErr := entry.Info()
				if infoErr != nil {
					continue
				}
				results[idx] = FileItem{
					Name:     entry.Name(),
					IsDir:    entry.IsDir(),
					Size:     info.Size(),
					Path:     pathpkg.Join(virtualPath, entry.Name()),
					Modified: info.ModTime().Format("2006-01-02 15:04"),
				}
				valid[idx] = true
			}
		}()
	}

	for idx := range entries {
		jobs <- idx
	}
	close(jobs)
	wg.Wait()

	items := make([]FileItem, 0, len(entries))
	for idx, ok := range valid {
		if ok {
			items = append(items, results[idx])
		}
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].IsDir != items[j].IsDir {
			return items[i].IsDir
		}
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})
	return items, nil
}

func apiGetDisks(w http.ResponseWriter, r *http.Request) {
	items := make([]string, 0, 8)
	if runtime.GOOS == "windows" {
		for disk := 'A'; disk <= 'Z'; disk++ {
			path := string(disk) + ":\\"
			info, err := os.Stat(path)
			if err == nil && info.IsDir() {
				items = append(items, path)
			}
		}
	} else {
		for _, path := range []string{"/", "/mnt", "/home", "/www/wwwroot"} {
			info, err := os.Stat(path)
			if err == nil && info.IsDir() {
				items = append(items, path)
			}
		}
	}

	writeJSON(w, map[string]any{
		"items":   items,
		"current": getCurrentRoot(),
	})
}

func apiGetDirectories(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(r.URL.Query().Get("path"))
	if target == "" {
		http.Error(w, "path is required", http.StatusBadRequest)
		return
	}

	full, err := filepath.Abs(target)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	info, err := os.Stat(full)
	if err != nil || !info.IsDir() {
		http.Error(w, "directory is not accessible", http.StatusBadRequest)
		return
	}

	entries, err := os.ReadDir(full)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	items := make([]DirectoryItem, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		items = append(items, DirectoryItem{
			Name: entry.Name(),
			Path: filepath.Join(full, entry.Name()),
		})
	}

	sort.Slice(items, func(i, j int) bool {
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})

	parent := filepath.Dir(full)
	if parent == "." {
		parent = full
	}

	writeJSON(w, map[string]any{
		"path":   full,
		"parent": parent,
		"items":  items,
	})
}

func apiMountDisk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	target := strings.TrimSpace(r.PostFormValue("path"))
	if target == "" {
		http.Error(w, "path is required", http.StatusBadRequest)
		return
	}

	full, err := filepath.Abs(target)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	info, err := os.Stat(full)
	if err != nil || !info.IsDir() {
		http.Error(w, "directory is not accessible", http.StatusBadRequest)
		return
	}

	if err := setCurrentRoot(full); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]any{
		"ok":   true,
		"root": full,
	})
}

func apiList(w http.ResponseWriter, r *http.Request) {
	virtualPath := cleanVirtualPath(r.URL.Query().Get("path"))
	full, err := resolvePath(getCurrentRoot(), virtualPath)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	items, ok := cachedFileItems(full)
	if !ok {
		items, err = buildFileItems(full, virtualPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		storeFileItems(full, items)
	}

	writeJSON(w, map[string]any{
		"path":  virtualPath,
		"items": items,
	})
}

type sharePathsRequest struct {
	Paths      []string `json:"paths"`
	Permission string   `json:"permission"`
}

type shareTokensRequest struct {
	Tokens     []string `json:"tokens"`
	Permission string   `json:"permission"`
}

func apiShares(w http.ResponseWriter, r *http.Request) {
	_, user, ok := authenticateRequest(r)
	if !ok {
		unauthorized(w)
		return
	}

	switch r.Method {
	case http.MethodGet:
		items := getShares()
		sort.Slice(items, func(i, j int) bool {
			return items[i].UpdatedAt > items[j].UpdatedAt
		})

		resp := make([]map[string]any, 0, len(items))
		for _, share := range items {
			resp = append(resp, shareResponse(r, share))
		}
		writeJSON(w, map[string]any{"items": resp})
	case http.MethodPost:
		var req sharePathsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		permission, valid := normalizeSharePermission(req.Permission)
		if !valid {
			http.Error(w, "invalid permission", http.StatusBadRequest)
			return
		}
		if len(req.Paths) == 0 {
			http.Error(w, "paths are required", http.StatusBadRequest)
			return
		}

		created := make([]map[string]any, 0, len(req.Paths))
		for _, virtualPath := range req.Paths {
			fullPath, err := resolvePath(getCurrentRoot(), virtualPath)
			if err != nil {
				http.Error(w, "invalid path", http.StatusBadRequest)
				return
			}

			info, err := os.Stat(fullPath)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}

			name := info.Name()
			if name == "" {
				name = filepath.Base(fullPath)
			}

			share, err := createShareLink(name, fullPath, permission, user.Username, info.IsDir())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			created = append(created, shareResponse(r, share))
		}

		writeJSON(w, map[string]any{
			"ok":    true,
			"items": created,
		})
	case http.MethodPut:
		var req shareTokensRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		permission, valid := normalizeSharePermission(req.Permission)
		if !valid {
			http.Error(w, "invalid permission", http.StatusBadRequest)
			return
		}
		if len(req.Tokens) == 0 {
			http.Error(w, "tokens are required", http.StatusBadRequest)
			return
		}

		updated := make([]map[string]any, 0, len(req.Tokens))
		for _, token := range req.Tokens {
			share, err := updateSharePermission(strings.TrimSpace(token), permission)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					http.Error(w, "share not found", http.StatusNotFound)
					return
				}
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			updated = append(updated, shareResponse(r, share))
		}

		writeJSON(w, map[string]any{
			"ok":    true,
			"items": updated,
		})
	case http.MethodDelete:
		var req shareTokensRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if len(req.Tokens) == 0 {
			http.Error(w, "tokens are required", http.StatusBadRequest)
			return
		}

		for _, token := range req.Tokens {
			if err := deleteShare(strings.TrimSpace(token)); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					http.Error(w, "share not found", http.StatusNotFound)
					return
				}
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		writeJSON(w, map[string]bool{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func shareResponse(r *http.Request, share ShareItem) map[string]any {
	return map[string]any{
		"token":      share.Token,
		"name":       share.Name,
		"full_path":  share.FullPath,
		"permission": share.Permission,
		"is_dir":     share.IsDir,
		"created_at": share.CreatedAt,
		"updated_at": share.UpdatedAt,
		"created_by": share.CreatedBy,
		"url":        buildShareURL(r, share.Token),
	}
}

func buildShareURL(r *http.Request, token string) string {
	return requestBaseURL(r) + "/share/" + token
}

func permissionLabel(permission string) string {
	switch permission {
	case sharePermissionDownload:
		return "只下载"
	case sharePermissionView:
		return "可预览"
	case sharePermissionEdit:
		return "可编辑"
	default:
		return permission
	}
}

func requestBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 && strings.TrimSpace(parts[0]) != "" {
			scheme = strings.TrimSpace(parts[0])
		}
	}
	return scheme + "://" + r.Host
}

func serveShare(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/share/"))
	if token == "" {
		http.NotFound(w, r)
		return
	}

	share, ok := findShare(token)
	if !ok {
		http.NotFound(w, r)
		return
	}

	info, err := os.Stat(share.FullPath)
	if err != nil {
		http.Error(w, "shared item not found", http.StatusNotFound)
		return
	}

	switch share.Permission {
	case sharePermissionDownload:
		if info.IsDir() {
			serveShareDownloadDirectory(w, r, share)
			return
		}
		http.ServeFile(w, r, share.FullPath)
	case sharePermissionView, sharePermissionEdit:
		if !info.IsDir() && share.Permission == sharePermissionEdit {
			serveEditableSharedFile(w, r, share)
			return
		}
		if !info.IsDir() {
			http.ServeFile(w, r, share.FullPath)
			return
		}
		serveShareDirectory(w, r, share)
	default:
		http.Error(w, "invalid share permission", http.StatusForbidden)
	}
}

func serveShareDownloadDirectory(w http.ResponseWriter, r *http.Request, share ShareItem) {
	if r.URL.Query().Get("download") == "1" {
		filename := share.Name
		if filename == "" {
			filename = "shared-folder"
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.zip"`, strings.ReplaceAll(filename, `"`, "")))

		zw := zip.NewWriter(w)
		if err := writeZipContents(zw, share.FullPath, filepath.Dir(share.FullPath)); err != nil {
			_ = zw.Close()
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = zw.Close()
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>目录分享</title><style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;background:#f4f6fb;color:#1f2937}.wrap{max-width:760px;margin:0 auto;padding:24px 16px}.panel{background:#fff;border:1px solid #dbe3ef;border-radius:8px;padding:24px}a.button{display:inline-flex;align-items:center;justify-content:center;height:40px;padding:0 16px;border-radius:8px;background:#2563eb;color:#fff;text-decoration:none}p{color:#6b7280;line-height:1.7}</style></head><body><div class="wrap"><div class="panel"><h2 style="margin-top:0">` + htmlEscape(share.Name) + `</h2><p>这个分享链接被设置为只下载。点击下面的按钮即可下载当前目录的 ZIP 压缩包。</p><a class="button" href="?download=1">下载 ZIP</a></div></div></body></html>`))
}

func serveEditableSharedFile(w http.ResponseWriter, r *http.Request, share ShareItem) {
	if r.Method == http.MethodGet && r.URL.Query().Get("download") == "1" {
		http.ServeFile(w, r, share.FullPath)
		return
	}

	if r.Method == http.MethodPost {
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer file.Close()

		filename := filepath.Base(header.Filename)
		if filename == "" || filename == "." {
			http.Error(w, "invalid file name", http.StatusBadRequest)
			return
		}

		dst, err := os.Create(share.FullPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer dst.Close()

		if _, err := io.Copy(dst, file); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		invalidateListCache()

		http.Redirect(w, r, r.URL.Path+"?updated=1", http.StatusSeeOther)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	message := ""
	if r.URL.Query().Get("updated") == "1" {
		message = `<p style="color:#047857">文件已经替换成功。</p>`
	}
	_, _ = w.Write([]byte(`<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>编辑分享文件</title><style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;background:#f4f6fb;color:#1f2937}.wrap{max-width:760px;margin:0 auto;padding:24px 16px}.panel{background:#fff;border:1px solid #dbe3ef;border-radius:8px;padding:24px}a.button,button{display:inline-flex;align-items:center;justify-content:center;height:40px;padding:0 16px;border-radius:8px;background:#2563eb;color:#fff;text-decoration:none;border:none;cursor:pointer}input[type=file]{margin:12px 0}.muted{color:#6b7280;line-height:1.7}</style></head><body><div class="wrap"><div class="panel"><h2 style="margin-top:0">` + htmlEscape(share.Name) + `</h2><p class="muted">这个文件分享允许编辑。你可以直接下载原文件，或者上传新文件覆盖它。</p>` + message + `<p><a class="button" href="` + htmlEscape(r.URL.Path) + `?download=1">下载当前文件</a></p><form method="post" enctype="multipart/form-data"><input type="file" name="file" required><br><button type="submit">上传并替换</button></form></div></div></body></html>`))
}

func writeZipContents(writer *zip.Writer, sourcePath, baseDir string) error {
	return filepath.Walk(sourcePath, func(current string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		rel, err := filepath.Rel(baseDir, current)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		if info.IsDir() {
			if rel == "." {
				return nil
			}
			_, err := writer.Create(rel + "/")
			return err
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = rel
		header.Method = zip.Deflate

		dst, err := writer.CreateHeader(header)
		if err != nil {
			return err
		}

		src, err := os.Open(current)
		if err != nil {
			return err
		}

		_, copyErr := io.Copy(dst, src)
		closeErr := src.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
}

func serveShareDirectory(w http.ResponseWriter, r *http.Request, share ShareItem) {
	rel := cleanVirtualPath(r.URL.Query().Get("path"))
	if rel == "/" {
		rel = "/"
	}

	target, err := resolvePath(share.FullPath, rel)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	info, err := os.Stat(target)
	if err != nil {
		http.Error(w, "path not found", http.StatusNotFound)
		return
	}

	if !info.IsDir() {
		if share.Permission == sharePermissionDownload || share.Permission == sharePermissionView || share.Permission == sharePermissionEdit {
			http.ServeFile(w, r, target)
			return
		}
	}

	if r.Method == http.MethodPost {
		if share.Permission != sharePermissionEdit {
			http.Error(w, "share is read-only", http.StatusForbidden)
			return
		}
		action := strings.TrimSpace(r.FormValue("action"))
		switch action {
		case "mkdir":
			name := strings.TrimSpace(r.FormValue("name"))
			if name == "" || strings.ContainsAny(name, `/\`) {
				http.Error(w, "invalid folder name", http.StatusBadRequest)
				return
			}
			if err := os.MkdirAll(filepath.Join(target, name), 0755); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			invalidateListCache()
		case "delete":
			targetRel := cleanVirtualPath(r.FormValue("target"))
			if targetRel == "/" {
				http.Error(w, "root cannot be deleted", http.StatusBadRequest)
				return
			}
			deleteTarget, err := resolvePath(share.FullPath, targetRel)
			if err != nil {
				http.Error(w, "invalid delete path", http.StatusBadRequest)
				return
			}
			if err := os.RemoveAll(deleteTarget); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			invalidateListCache()
		case "upload":
			file, header, err := r.FormFile("file")
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			defer file.Close()

			filename := filepath.Base(header.Filename)
			if filename == "" || filename == "." {
				http.Error(w, "invalid file name", http.StatusBadRequest)
				return
			}
			dst, err := os.Create(filepath.Join(target, filename))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer dst.Close()
			if _, err := io.Copy(dst, file); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			invalidateListCache()
		default:
			http.Error(w, "unsupported action", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, r.URL.Path+"?path="+urlQueryEscape(rel), http.StatusSeeOther)
		return
	}

	items, err := buildFileItems(target, rel)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(renderSharePage(r, share, rel, items)))
}

func urlQueryEscape(value string) string {
	replacer := strings.NewReplacer("%", "%25", " ", "%20", "#", "%23", "&", "%26", "+", "%2B", "?", "%3F")
	return replacer.Replace(value)
}

func renderSharePage(r *http.Request, share ShareItem, currentPath string, items []FileItem) string {
	var builder strings.Builder
	builder.WriteString(`<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>分享 - `)
	builder.WriteString(htmlEscape(share.Name))
	builder.WriteString(`</title><style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;background:#f4f6fb;color:#1f2937}
.wrap{max-width:1100px;margin:0 auto;padding:24px 16px}
.panel{background:#fff;border:1px solid #dbe3ef;border-radius:8px;padding:18px}
.head{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;flex-wrap:wrap;margin-bottom:16px}
.meta{color:#6b7280;font-size:14px;display:grid;gap:6px}
.bar{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}
button,input[type="text"]{height:38px;border-radius:8px}
button{padding:0 14px;border:none;background:#2563eb;color:#fff;cursor:pointer}
button.secondary{background:#fff;color:#1f2937;border:1px solid #cfd8e3}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:12px;border-bottom:1px solid #edf1f7;font-size:14px}
a{text-decoration:none;color:#1d4ed8}
form.inline{display:inline-flex;gap:8px;flex-wrap:wrap}
.muted{color:#6b7280}
</style></head><body><div class="wrap"><div class="panel">`)
	builder.WriteString(`<div class="head"><div><h2 style="margin:0 0 8px 0">`)
	builder.WriteString(htmlEscape(share.Name))
	builder.WriteString(`</h2><div class="meta"><div>权限: `)
	builder.WriteString(htmlEscape(permissionLabel(share.Permission)))
	builder.WriteString(`</div><div>创建者: `)
	builder.WriteString(htmlEscape(share.CreatedBy))
	builder.WriteString(`</div><div>路径: `)
	builder.WriteString(htmlEscape(currentPath))
	builder.WriteString(`</div></div></div>`)

	if share.Permission == sharePermissionEdit {
		builder.WriteString(`<div class="bar"><form method="post" class="inline"><input type="hidden" name="action" value="mkdir"><input type="text" name="name" placeholder="新建文件夹名称"><button type="submit">新建文件夹</button></form><form method="post" enctype="multipart/form-data" class="inline"><input type="hidden" name="action" value="upload"><input type="file" name="file"><button type="submit">上传文件</button></form></div>`)
	}

	builder.WriteString(`</div><table><thead><tr><th>名称</th><th>类型</th><th>大小</th><th>修改时间</th><th>操作</th></tr></thead><tbody>`)
	if currentPath != "/" {
		parent := pathpkg.Dir(currentPath)
		if parent == "." {
			parent = "/"
		}
		builder.WriteString(`<tr><td><a href="?path=` + htmlEscape(urlQueryEscape(parent)) + `">..</a></td><td class="muted">上级目录</td><td>-</td><td>-</td><td></td></tr>`)
	}

	for _, item := range items {
		builder.WriteString(`<tr><td>`)
		if item.IsDir {
			builder.WriteString(`<a href="?path=` + htmlEscape(urlQueryEscape(item.Path)) + `">` + htmlEscape(item.Name) + `</a>`)
		} else {
			builder.WriteString(`<a href="?path=` + htmlEscape(urlQueryEscape(item.Path)) + `">` + htmlEscape(item.Name) + `</a>`)
		}
		builder.WriteString(`</td><td>`)
		if item.IsDir {
			builder.WriteString(`目录`)
		} else {
			builder.WriteString(`文件`)
		}
		builder.WriteString(`</td><td>`)
		if item.IsDir {
			builder.WriteString(`-`)
		} else {
			builder.WriteString(htmlEscape(formatSizeJS(item.Size)))
		}
		builder.WriteString(`</td><td>` + htmlEscape(item.Modified) + `</td><td>`)
		if !item.IsDir {
			builder.WriteString(`<a href="?path=` + htmlEscape(urlQueryEscape(item.Path)) + `">打开</a>`)
		} else {
			builder.WriteString(`<a href="?path=` + htmlEscape(urlQueryEscape(item.Path)) + `">进入</a>`)
		}
		if share.Permission == sharePermissionEdit && currentPath != "/" {
			builder.WriteString(``)
		}
		if share.Permission == sharePermissionEdit {
			builder.WriteString(` <form method="post" class="inline" onsubmit="return confirm('确定删除这个项目吗？')"><input type="hidden" name="action" value="delete"><input type="hidden" name="target" value="` + htmlEscape(item.Path) + `"><button type="submit" class="secondary">删除</button></form>`)
		}
		builder.WriteString(`</td></tr>`)
	}

	builder.WriteString(`</tbody></table></div></div></body></html>`)
	return builder.String()
}

func htmlEscape(value string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(value)
}

func formatSizeJS(size int64) string {
	if size <= 0 {
		return "-"
	}
	units := []string{"B", "KB", "MB", "GB", "TB"}
	value := float64(size)
	index := 0
	for value >= 1024 && index < len(units)-1 {
		value = value / 1024
		index++
	}
	if index == 0 {
		return fmt.Sprintf("%.0f %s", value, units[index])
	}
	return fmt.Sprintf("%.1f %s", value, units[index])
}

func apiMkdir(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	basePath := cleanVirtualPath(r.PostFormValue("path"))
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		http.Error(w, "folder name is required", http.StatusBadRequest)
		return
	}
	if strings.ContainsAny(name, `/\`) {
		http.Error(w, "folder name is invalid", http.StatusBadRequest)
		return
	}

	full, err := resolvePath(getCurrentRoot(), pathpkg.Join(basePath, name))
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	if err := os.MkdirAll(full, 0755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	invalidateListCache()
	writeJSON(w, map[string]bool{"ok": true})
}

func apiUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(uploadMemoryLimit); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}

	basePath := cleanVirtualPath(r.FormValue("path"))
	targetDir, err := resolvePath(getCurrentRoot(), basePath)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	headers := collectUploadFiles(r.MultipartForm)
	if len(headers) == 0 {
		http.Error(w, "no files uploaded", http.StatusBadRequest)
		return
	}

	saved := 0
	for _, header := range headers {
		if err := saveUploadedFile(targetDir, header); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		saved++
	}
	invalidateListCache()
	writeJSON(w, map[string]any{
		"ok":    true,
		"count": saved,
	})
}

func apiDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	paths, err := readBatchPaths(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	deleted := 0
	for _, virtualPath := range paths {
		if virtualPath == "/" {
			http.Error(w, "root cannot be deleted", http.StatusBadRequest)
			return
		}

		full, err := resolvePath(getCurrentRoot(), virtualPath)
		if err != nil {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}

		if err := os.RemoveAll(full); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		deleted++
	}
	invalidateListCache()
	writeJSON(w, map[string]any{
		"ok":    true,
		"count": deleted,
	})
}

func apiDownload(w http.ResponseWriter, r *http.Request) {
	virtualPath := cleanVirtualPath(r.URL.Query().Get("path"))
	full, err := resolvePath(getCurrentRoot(), virtualPath)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	info, err := os.Stat(full)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if info.IsDir() {
		http.Error(w, "directory download is not supported", http.StatusBadRequest)
		return
	}

	http.ServeFile(w, r, full)
}

func apiPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	virtualPath := cleanVirtualPath(r.URL.Query().Get("path"))
	full, err := resolvePath(getCurrentRoot(), virtualPath)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	info, err := os.Stat(full)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if info.IsDir() {
		http.Error(w, "directory preview is not supported", http.StatusBadRequest)
		return
	}

	file, err := os.Open(full)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	sample := make([]byte, 1024)
	n, readErr := file.Read(sample)
	if readErr != nil && readErr != io.EOF {
		http.Error(w, readErr.Error(), http.StatusInternalServerError)
		return
	}
	sample = sample[:n]

	kind := previewKindForFile(info.Name(), sample)
	contentType := mime.TypeByExtension(strings.ToLower(filepath.Ext(info.Name())))
	if contentType == "" && len(sample) > 0 {
		contentType = http.DetectContentType(sample)
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	if kind != "text" {
		writeJSON(w, map[string]any{
			"kind":         kind,
			"name":         info.Name(),
			"size":         info.Size(),
			"content_type": contentType,
		})
		return
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data, err := io.ReadAll(io.LimitReader(file, maxTextPreviewLen+1))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	truncated := len(data) > maxTextPreviewLen
	if truncated {
		data = data[:maxTextPreviewLen]
	}

	writeJSON(w, map[string]any{
		"kind":         "text",
		"name":         info.Name(),
		"size":         info.Size(),
		"text":         string(data),
		"truncated":    truncated,
		"content_type": contentType,
	})
}

func apiZip(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	paths, err := readBatchPaths(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	zipped := 0
	for _, virtualPath := range paths {
		if virtualPath == "/" {
			http.Error(w, "root cannot be zipped", http.StatusBadRequest)
			return
		}

		full, err := resolvePath(getCurrentRoot(), virtualPath)
		if err != nil {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}

		if _, err := os.Stat(full); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		if err := createZipArchive(full, full+".zip"); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		zipped++
	}
	invalidateListCache()
	writeJSON(w, map[string]any{
		"ok":    true,
		"count": zipped,
	})
}

func createZipArchive(sourcePath, zipPath string) error {
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	writer := zip.NewWriter(zipFile)
	defer writer.Close()

	baseDir := filepath.Dir(sourcePath)
	return filepath.Walk(sourcePath, func(current string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		rel, err := filepath.Rel(baseDir, current)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		if info.IsDir() {
			if rel == "." {
				return nil
			}
			_, err := writer.Create(rel + "/")
			return err
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = rel
		header.Method = zip.Deflate

		w, err := writer.CreateHeader(header)
		if err != nil {
			return err
		}

		file, err := os.Open(current)
		if err != nil {
			return err
		}

		_, copyErr := io.Copy(w, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
}

func unzipArchive(full string) error {
	if !strings.EqualFold(filepath.Ext(full), ".zip") {
		return errors.New("please select a zip file")
	}

	rc, err := zip.OpenReader(full)
	if err != nil {
		return err
	}
	defer rc.Close()

	zipExt := filepath.Ext(full)
	destDir := full[:len(full)-len(zipExt)]
	destAbs, err := filepath.Abs(destDir)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(destAbs, 0755); err != nil {
		return err
	}

	for _, file := range rc.File {
		targetPath := filepath.Join(destAbs, filepath.FromSlash(file.Name))
		targetAbs, err := filepath.Abs(targetPath)
		if err != nil {
			return err
		}

		relCheck, err := filepath.Rel(destAbs, targetAbs)
		if err != nil || relCheck == ".." || strings.HasPrefix(relCheck, ".."+string(os.PathSeparator)) {
			return errors.New("zip contains invalid path")
		}

		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(targetAbs, 0755); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(targetAbs), 0755); err != nil {
			return err
		}

		src, err := file.Open()
		if err != nil {
			return err
		}

		dst, err := os.OpenFile(targetAbs, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			src.Close()
			return err
		}

		_, copyErr := io.Copy(dst, src)
		closeErr := dst.Close()
		srcErr := src.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if srcErr != nil {
			return srcErr
		}
	}

	return nil
}

func apiUnzip(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	paths, err := readBatchPaths(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	unzipped := 0
	for _, virtualPath := range paths {
		full, err := resolvePath(getCurrentRoot(), virtualPath)
		if err != nil {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
		if err := unzipArchive(full); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		unzipped++
	}

	invalidateListCache()
	writeJSON(w, map[string]any{
		"ok":    true,
		"count": unzipped,
	})
}

func apiAccount(w http.ResponseWriter, r *http.Request) {
	index, user, ok := authenticateRequest(r)
	if !ok {
		unauthorized(w)
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]string{
			"username": user.Username,
		})
	case http.MethodPost:
		newUsername := strings.TrimSpace(r.PostFormValue("username"))
		currentPassword := r.PostFormValue("current_password")
		newPassword := r.PostFormValue("new_password")

		if newUsername == "" {
			http.Error(w, "username is required", http.StatusBadRequest)
			return
		}
		if strings.Contains(newUsername, ":") {
			http.Error(w, "username cannot contain ':'", http.StatusBadRequest)
			return
		}
		if currentPassword == "" {
			http.Error(w, "current password is required", http.StatusBadRequest)
			return
		}
		if currentPassword != user.Password {
			http.Error(w, "current password is incorrect", http.StatusUnauthorized)
			return
		}
		if newPassword != "" && len(newPassword) < 4 {
			http.Error(w, "new password must be at least 4 characters", http.StatusBadRequest)
			return
		}

		finalPassword := user.Password
		if newPassword != "" {
			finalPassword = newPassword
		}

		cfgMu.Lock()
		for i, existing := range appConfig.Users {
			if i != index && existing.Username == newUsername {
				cfgMu.Unlock()
				http.Error(w, "username already exists", http.StatusBadRequest)
				return
			}
		}
		appConfig.Users[index] = User{
			Username: newUsername,
			Password: finalPassword,
		}
		snapshot := cloneConfig(appConfig)
		cfgMu.Unlock()

		if err := writeConfig(snapshot); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		writeJSON(w, map[string]any{
			"ok":       true,
			"username": newUsername,
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func page(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(pageHTML))
}

const pageHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>GoWebDAV 文件管理</title>
    <style>
        *{box-sizing:border-box}
        body{
            margin:0;
            font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
            color:#1f2937;
            background:#f3f5f8;
        }
        .app{
            max-width:1360px;
            margin:0 auto;
            padding:24px 20px 32px;
        }
        .topbar{
            display:flex;
            justify-content:space-between;
            align-items:flex-start;
            gap:16px;
            margin-bottom:20px;
        }
        .topbar h1{
            margin:0;
            font-size:28px;
            font-weight:700;
        }
        .topbar p{
            margin:6px 0 0;
            color:#6b7280;
            font-size:14px;
        }
        .topbar-actions{
            display:flex;
            align-items:center;
            gap:12px;
            flex-wrap:wrap;
        }
        .account-chip{
            padding:8px 12px;
            background:#ffffff;
            border:1px solid #dbe3ef;
            border-radius:8px;
            color:#4b5563;
            font-size:14px;
        }
        .toolbar{
            background:#ffffff;
            border:1px solid #dbe3ef;
            border-radius:8px;
            padding:16px;
        }
        .toolbar-row{
            display:flex;
            flex-wrap:wrap;
            align-items:flex-end;
            justify-content:space-between;
            gap:16px;
        }
        .toolbar-row + .toolbar-row{
            margin-top:14px;
            padding-top:14px;
            border-top:1px solid #edf1f7;
        }
        .field-group,.path-wrap{
            display:flex;
            flex-direction:column;
            gap:8px;
            min-width:240px;
        }
        .field-inline{
            display:flex;
            gap:10px;
            align-items:center;
            flex-wrap:wrap;
        }
        label,.label{
            font-size:13px;
            color:#6b7280;
        }
        input[type="text"],input[type="password"],select{
            height:38px;
            padding:0 12px;
            border:1px solid #cfd8e3;
            border-radius:8px;
            background:#fff;
            color:#111827;
            min-width:180px;
        }
        input[type="text"]:focus,input[type="password"]:focus,select:focus{
            outline:none;
            border-color:#2563eb;
            box-shadow:0 0 0 3px rgba(37,99,235,0.12);
        }
        button{
            height:38px;
            padding:0 14px;
            border:none;
            border-radius:8px;
            background:#2563eb;
            color:#fff;
            cursor:pointer;
            font-size:14px;
            white-space:nowrap;
        }
        button:hover{background:#1d4ed8}
        button.secondary{
            background:#ffffff;
            color:#1f2937;
            border:1px solid #cfd8e3;
        }
        button.secondary:hover{background:#f8fafc}
        button.accent{
            background:#d97706;
        }
        button.accent:hover{background:#b45309}
        button.danger{
            background:#dc2626;
        }
        button.danger:hover{background:#b91c1c}
        button.tiny{
            height:30px;
            padding:0 10px;
            border-radius:6px;
            font-size:13px;
        }
        .view-switch{
            display:flex;
            gap:0;
            border:1px solid #cfd8e3;
            border-radius:8px;
            overflow:hidden;
        }
        .view-switch button{
            border-radius:0;
            background:#fff;
            color:#4b5563;
            border-right:1px solid #cfd8e3;
        }
        .view-switch button:last-child{
            border-right:none;
        }
        .view-switch button.active{
            background:#2563eb;
            color:#fff;
        }
        .path-bar{
            display:flex;
            flex-wrap:wrap;
            align-items:center;
            gap:6px;
            min-height:38px;
        }
        .crumb{
            background:#eef4ff;
            color:#1d4ed8;
            border:none;
            height:30px;
            padding:0 10px;
            border-radius:6px;
            cursor:pointer;
        }
        .crumb:hover{
            background:#dbeafe;
        }
        .crumb-sep{
            color:#9ca3af;
        }
        .button-group{
            display:flex;
            gap:10px;
            flex-wrap:wrap;
        }
        .toolbar-actions{
            display:flex;
            gap:10px;
            flex-wrap:wrap;
            align-items:center;
        }
        .summary{
            display:flex;
            align-items:center;
            color:#6b7280;
            font-size:14px;
        }
        .share-panel{
            margin-top:18px;
            background:#ffffff;
            border:1px solid #dbe3ef;
            border-radius:8px;
            padding:16px;
        }
        .share-panel h3{
            margin:0 0 14px 0;
            font-size:18px;
        }
        .share-list{
            display:grid;
            gap:10px;
        }
        .share-item{
            display:grid;
            gap:10px;
            padding:12px;
            border:1px solid #e5ebf4;
            border-radius:8px;
        }
        .share-top{
            display:flex;
            justify-content:space-between;
            gap:12px;
            align-items:flex-start;
            flex-wrap:wrap;
        }
        .share-title{
            font-weight:600;
            word-break:break-word;
        }
        .share-meta{
            color:#6b7280;
            font-size:13px;
            display:grid;
            gap:4px;
        }
        .share-link{
            width:100%;
            height:38px;
            padding:0 12px;
            border:1px solid #cfd8e3;
            border-radius:8px;
            background:#f8fafc;
            color:#111827;
        }
        .permission-badge{
            display:inline-flex;
            align-items:center;
            justify-content:center;
            min-width:68px;
            height:28px;
            padding:0 10px;
            border-radius:999px;
            background:#eff6ff;
            color:#1d4ed8;
            font-size:12px;
            font-weight:600;
        }
        .share-empty{
            color:#6b7280;
            padding:10px 0 2px;
        }
        .status{
            margin-top:12px;
            min-height:22px;
            font-size:14px;
        }
        .status[data-kind="success"]{color:#047857}
        .status[data-kind="error"]{color:#b91c1c}
        .status[data-kind="loading"]{color:#1d4ed8}
        .file-surface{
            margin-top:18px;
            background:#ffffff;
            border:1px solid #dbe3ef;
            border-radius:8px;
            min-height:360px;
            overflow:hidden;
        }
        .empty{
            padding:48px 20px;
            text-align:center;
            color:#6b7280;
        }
        .table{
            width:100%;
        }
        .table-head,.table-row{
            display:grid;
            grid-template-columns:52px minmax(280px,1.8fr) 120px 160px 240px;
            gap:12px;
            align-items:center;
            padding:12px 16px;
        }
        .table-head{
            background:#f8fafc;
            color:#6b7280;
            font-size:13px;
            border-bottom:1px solid #edf1f7;
        }
        .table-row{
            border-bottom:1px solid #edf1f7;
        }
        .table-row.selected{
            background:#f8fbff;
        }
        .table-row:last-child{
            border-bottom:none;
        }
        .table-head input[type="checkbox"],
        .table-row input[type="checkbox"],
        .card-top input[type="checkbox"]{
            width:16px;
            height:16px;
        }
        .name-cell{
            display:flex;
            align-items:center;
            gap:10px;
            min-width:0;
        }
        .item-type{
            display:inline-flex;
            align-items:center;
            justify-content:center;
            min-width:52px;
            height:26px;
            padding:0 8px;
            border-radius:6px;
            background:#eef2ff;
            color:#4338ca;
            font-size:12px;
            font-weight:600;
        }
        .item-type.file{
            background:#eff6ff;
            color:#1d4ed8;
        }
        .item-name{
            overflow:hidden;
            text-overflow:ellipsis;
            white-space:nowrap;
            cursor:pointer;
        }
        .item-name:hover{
            color:#2563eb;
        }
        .actions{
            display:flex;
            gap:8px;
            flex-wrap:wrap;
            justify-content:flex-start;
        }
        .cards{
            display:grid;
            grid-template-columns:repeat(auto-fill,minmax(240px,1fr));
            gap:14px;
            padding:16px;
        }
        .file-card{
            border:1px solid #dbe3ef;
            border-radius:8px;
            padding:14px;
            display:flex;
            flex-direction:column;
            gap:12px;
            min-height:190px;
        }
        .file-card.selected{
            border-color:#93c5fd;
            background:#f8fbff;
        }
        .card-top{
            display:flex;
            justify-content:space-between;
            align-items:flex-start;
            gap:10px;
        }
        .card-name{
            font-size:15px;
            font-weight:600;
            line-height:1.4;
            word-break:break-word;
            cursor:pointer;
        }
        .card-name:hover{
            color:#2563eb;
        }
        .meta{
            display:grid;
            gap:6px;
            color:#6b7280;
            font-size:13px;
        }
        .meta-row{
            display:flex;
            justify-content:space-between;
            gap:12px;
        }
        .modal{
            position:fixed;
            inset:0;
            display:none;
            align-items:center;
            justify-content:center;
            background:rgba(15,23,42,0.56);
            padding:20px;
            z-index:1000;
        }
        .modal.open{
            display:flex;
        }
        .dialog{
            width:min(480px,100%);
            background:#fff;
            border-radius:8px;
            border:1px solid #dbe3ef;
            padding:20px;
        }
        .dialog.large{
            width:min(960px,100%);
            padding:14px;
        }
        .dialog-head{
            display:flex;
            justify-content:space-between;
            align-items:center;
            gap:12px;
            margin-bottom:16px;
        }
        .dialog-head h3{
            margin:0;
            font-size:20px;
        }
        .close-btn{
            background:#fff;
            color:#6b7280;
            border:1px solid #cfd8e3;
        }
        .form-grid{
            display:grid;
            gap:14px;
        }
        .form-grid p{
            margin:0;
            font-size:13px;
            color:#6b7280;
            line-height:1.6;
        }
        .preview-body{
            min-height:280px;
            max-height:78vh;
            overflow:auto;
            display:flex;
            align-items:center;
            justify-content:center;
            background:#0f172a;
            border-radius:6px;
        }
        .preview-body img,.preview-body video,.preview-body audio{
            max-width:100%;
            max-height:76vh;
        }
        .preview-frame{
            width:100%;
            height:76vh;
            border:none;
            border-radius:6px;
            background:#ffffff;
        }
        .preview-text{
            width:100%;
            margin:0;
            padding:18px;
            color:#e5e7eb;
            font-family:Consolas,"SFMono-Regular",monospace;
            font-size:13px;
            line-height:1.6;
            white-space:pre-wrap;
            word-break:break-word;
        }
        .preview-note{
            padding:14px 18px 0;
            color:#fbbf24;
            font-size:13px;
        }
        #uploadInput{
            display:none;
        }
        @media (max-width:960px){
            .table-head,.table-row{
                grid-template-columns:52px minmax(200px,1fr) 96px 130px;
            }
            .table-head .modified-col,.table-row .modified-col{
                display:none;
            }
        }
        @media (max-width:720px){
            .app{
                padding:16px 14px 24px;
            }
            .topbar{
                flex-direction:column;
                align-items:stretch;
            }
            .toolbar-actions{
                flex-direction:column;
                align-items:stretch;
            }
            .table-head{
                display:none;
            }
            .table-row{
                grid-template-columns:44px 1fr;
                align-items:flex-start;
            }
            .table-row > .size-col,
            .table-row > .modified-col{
                display:none;
            }
            .actions{
                grid-column:2;
            }
        }
    </style>
</head>
<body>
<div class="app">
    <div class="topbar">
        <div>
            <h1>GoWebDAV 文件管理</h1>
            <p>文件浏览、上传、压缩和 WebDAV 共用同一挂载目录。</p>
        </div>
        <div class="topbar-actions">
            <div id="accountSummary" class="account-chip">账号: --</div>
            <button class="secondary" onclick="openAccountModal()">账号设置</button>
        </div>
    </div>

    <div class="toolbar">
        <div class="toolbar-row">
            <div class="field-group">
                <span class="label">挂载路径</span>
                <div class="field-inline">
                    <input id="rootPath" type="text" placeholder="输入磁盘或目录路径">
                    <button onclick="mountDisk()">切换</button>
                </div>
            </div>
            <div class="field-group">
                <label for="diskList">常用磁盘</label>
                <select id="diskList" onchange="syncDiskSelection()"></select>
            </div>
            <div class="path-wrap">
                <span class="label">当前路径</span>
                <div id="pathBar" class="path-bar"></div>
            </div>
            <div class="field-group" style="min-width:0">
                <span class="label">显示方式</span>
                <div class="view-switch">
                    <button id="listViewBtn" type="button" onclick="setViewMode('list')">列表</button>
                    <button id="cardViewBtn" type="button" onclick="setViewMode('card')">卡片</button>
                </div>
            </div>
        </div>

        <div class="toolbar-row">
            <div class="toolbar-actions">
                <div class="button-group">
                    <button class="secondary" onclick="goBack()">返回上级</button>
                    <button onclick="createFolder()">新建文件夹</button>
                    <button onclick="triggerUpload()">上传文件</button>
                    <button class="accent" onclick="zipSelected()">压缩</button>
                    <button class="accent" onclick="unzipSelected()">解压</button>
                    <button class="danger" onclick="deleteSelected()">删除</button>
                </div>
                <div class="button-group">
                    <button class="secondary" type="button" onclick="selectAllCurrent()">全选</button>
                    <button class="secondary" type="button" onclick="invertSelection()">反选</button>
                    <button class="secondary" type="button" onclick="clearSelection()">清空选择</button>
                </div>
            </div>
            <div class="summary" id="selectionSummary">当前目录暂无项目</div>
        </div>

        <input id="uploadInput" type="file" multiple>
        <div id="status" class="status" data-kind="idle"></div>
    </div>

    <div id="fileList" class="file-surface"></div>
</div>

<div id="accountModal" class="modal">
    <div class="dialog">
        <div class="dialog-head">
            <h3>账号设置</h3>
            <button class="close-btn tiny" onclick="closeAccountModal()">关闭</button>
        </div>
        <div class="form-grid">
            <div>
                <label for="accountUsername">账号</label>
                <input id="accountUsername" type="text" placeholder="请输入账号">
            </div>
            <div>
                <label for="accountCurrentPassword">当前密码</label>
                <input id="accountCurrentPassword" type="password" placeholder="用于验证本次修改">
            </div>
            <div>
                <label for="accountNewPassword">新密码</label>
                <input id="accountNewPassword" type="password" placeholder="留空表示不修改密码">
            </div>
            <div>
                <label for="accountConfirmPassword">确认新密码</label>
                <input id="accountConfirmPassword" type="password" placeholder="再次输入新密码">
            </div>
            <p>保存后，当前网页会继续使用新凭据。其他 WebDAV 客户端需要改成新的账号密码。</p>
            <div class="button-group">
                <button onclick="saveAccount()">保存修改</button>
                <button class="secondary" onclick="closeAccountModal()">取消</button>
            </div>
        </div>
    </div>
</div>

<div id="previewModal" class="modal" onclick="closePreview(event)">
    <div class="dialog large" onclick="event.stopPropagation()">
        <div class="dialog-head">
            <h3 id="previewTitle">文件预览</h3>
            <button class="close-btn tiny" onclick="closePreview()">关闭</button>
        </div>
        <div id="previewBody" class="preview-body"></div>
    </div>
</div>

<script>
let currentPath = "/";
let currentUsername = "";
let authHeader = "";
let viewMode = localStorage.getItem("gowebdav-view") || "list";
let fileItems = [];
let selected = new Set();
let shareItems = [];
let selectedShares = new Set();
let currentListController = null;
let currentListToken = 0;

const IMAGE_EXTS = new Set(["jpg", "jpeg", "png", "gif", "webp", "bmp", "svg"]);
const VIDEO_EXTS = new Set(["mp4", "webm", "ogg", "mov", "m4v"]);
const AUDIO_EXTS = new Set(["mp3", "wav", "ogg", "m4a", "flac", "aac", "oga"]);
const TEXT_EXTS = new Set(["txt", "md", "markdown", "json", "yaml", "yml", "toml", "ini", "conf", "log", "csv", "xml", "html", "htm", "css", "js", "jsx", "ts", "tsx", "vue", "go", "py", "java", "rb", "rs", "php", "c", "cc", "cpp", "h", "hpp", "cs", "sh", "bash", "ps1", "sql"]);

function byId(id) {
    return document.getElementById(id);
}

function setStatus(text, kind) {
    const el = byId("status");
    el.textContent = text || "";
    el.dataset.kind = kind || "idle";
}

function makeRequestOptions(options) {
    const result = Object.assign({}, options || {});
    result.headers = Object.assign({}, options && options.headers ? options.headers : {});
    if (authHeader) {
        result.headers.Authorization = authHeader;
    }
    return result;
}

async function apiFetch(url, options) {
    const response = await fetch(url, makeRequestOptions(options));
    if (!response.ok) {
        let message = "请求失败";
        try {
            message = await response.text();
        } catch (_) {}
        if (response.status === 401) {
            message = "登录状态已失效，请重新打开页面并登录。";
        }
        throw new Error(message || "请求失败");
    }
    return response;
}

async function apiJSON(url, options) {
    const response = await apiFetch(url, options);
    return response.json();
}

function formBody(data) {
    const params = new URLSearchParams();
    Object.keys(data).forEach(function(key) {
        params.set(key, data[key] == null ? "" : data[key]);
    });
    return params.toString();
}

function formatSize(size) {
    if (!size) {
        return "-";
    }
    const units = ["B", "KB", "MB", "GB", "TB"];
    let value = size;
    let index = 0;
    while (value >= 1024 && index < units.length - 1) {
        value = value / 1024;
        index += 1;
    }
    return (index === 0 ? value.toFixed(0) : value.toFixed(1)) + " " + units[index];
}

function extOf(name) {
    const idx = name.lastIndexOf(".");
    return idx >= 0 ? name.slice(idx + 1).toLowerCase() : "";
}

function previewKind(item) {
    const name = typeof item === "string" ? item : item && item.name ? item.name : "";
    const ext = extOf(name);
    if (IMAGE_EXTS.has(ext)) return "image";
    if (VIDEO_EXTS.has(ext)) return "video";
    if (AUDIO_EXTS.has(ext)) return "audio";
    if (ext === "pdf") return "pdf";
    if (TEXT_EXTS.has(ext)) return "text";
    return "";
}

function canPreview(item) {
    return !!item && !item.is_dir && previewKind(item) !== "";
}

function downloadURL(path) {
    return "/api/download?path=" + encodeURIComponent(path);
}

function kindText(item) {
    if (item.is_dir) {
        return "目录";
    }
    const ext = extOf(item.name);
    return ext ? ext.toUpperCase() : "文件";
}

function selectedVisibleCount() {
    let count = 0;
    fileItems.forEach(function(item) {
        if (selected.has(item.path)) {
            count += 1;
        }
    });
    return count;
}

function selectedVisibleSize() {
    let total = 0;
    fileItems.forEach(function(item) {
        if (!item.is_dir && selected.has(item.path)) {
            total += Number(item.size || 0);
        }
    });
    return total;
}

function updateSelectAllState(selectedCount, totalCount) {
    document.querySelectorAll(".select-all-toggle").forEach(function(checkbox) {
        checkbox.disabled = totalCount === 0;
        checkbox.checked = totalCount > 0 && selectedCount === totalCount;
        checkbox.indeterminate = selectedCount > 0 && selectedCount < totalCount;
    });
}

function updateSelectionSummary() {
    const summary = byId("selectionSummary");
    if (!summary) {
        return;
    }

    const totalCount = fileItems.length;
    const selectedCount = selectedVisibleCount();
    let text = totalCount === 0 ? "当前目录暂无项目" : "共 " + totalCount + " 项";
    if (selectedCount > 0) {
        text += "，已选中 " + selectedCount + " 项";
        const selectedSize = selectedVisibleSize();
        if (selectedSize > 0) {
            text += "（" + formatSize(selectedSize) + "）";
        }
    } else if (totalCount > 0) {
        text += "，未选中项目";
    }
    summary.textContent = text;
    updateSelectAllState(selectedCount, totalCount);
}

function syncDiskSelection() {
    const value = byId("diskList").value;
    if (value) {
        byId("rootPath").value = value;
    }
}

function setViewMode(mode) {
    viewMode = mode === "card" ? "card" : "list";
    localStorage.setItem("gowebdav-view", viewMode);
    byId("listViewBtn").classList.toggle("active", viewMode === "list");
    byId("cardViewBtn").classList.toggle("active", viewMode === "card");
    renderFiles();
}

function renderPathBar() {
    const bar = byId("pathBar");
    bar.innerHTML = "";

    const rootBtn = document.createElement("button");
    rootBtn.className = "crumb";
    rootBtn.textContent = "根目录";
    rootBtn.onclick = function() {
        openPath("/");
    };
    bar.appendChild(rootBtn);

    if (currentPath === "/") {
        return;
    }

    const parts = currentPath.split("/").filter(Boolean);
    let acc = "";
    parts.forEach(function(part) {
        const sep = document.createElement("span");
        sep.className = "crumb-sep";
        sep.textContent = "/";
        bar.appendChild(sep);

        acc += "/" + part;
        const btn = document.createElement("button");
        btn.className = "crumb";
        btn.textContent = part;
        btn.onclick = function() {
            openPath(acc);
        };
        bar.appendChild(btn);
    });
}

function makeActionButton(text, className, handler) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "tiny " + (className || "secondary");
    button.textContent = text;
    button.onclick = function(event) {
        event.stopPropagation();
        handler();
    };
    return button;
}

function toggleSelection(path, checked) {
    if (checked) {
        selected.add(path);
    } else {
        selected.delete(path);
    }
    updateSelectionSummary();
}

function selectAllCurrent() {
    selected = new Set(fileItems.map(function(item) {
        return item.path;
    }));
    renderFiles();
}

function invertSelection() {
    const next = new Set();
    fileItems.forEach(function(item) {
        if (!selected.has(item.path)) {
            next.add(item.path);
        }
    });
    selected = next;
    renderFiles();
}

function clearSelection() {
    selected = new Set();
    renderFiles();
}

function toggleSelectAll(checked) {
    if (checked) {
        selectAllCurrent();
        return;
    }
    clearSelection();
}

function openPath(path) {
    currentPath = path || "/";
    selected = new Set();
    updateSelectionSummary();
    loadFiles();
}

function openItem(item) {
    if (item.is_dir) {
        openPath(item.path);
        return;
    }
    if (canPreview(item)) {
        previewItem(item);
        return;
    }
    downloadItem(item);
}

function createItemActions(item) {
    const box = document.createElement("div");
    box.className = "actions";

    if (!item.is_dir) {
        if (canPreview(item)) {
            box.appendChild(makeActionButton("预览", "secondary", function() {
                previewItem(item);
            }));
        }
        box.appendChild(makeActionButton("下载", "secondary", function() {
            downloadItem(item);
        }));
    }

    return box;
}

function renderListView(container) {
    const table = document.createElement("div");
    table.className = "table";

    const head = document.createElement("div");
    head.className = "table-head";
    const headSelect = document.createElement("div");
    const selectAll = document.createElement("input");
    selectAll.type = "checkbox";
    selectAll.className = "select-all-toggle";
    selectAll.setAttribute("aria-label", "全选当前目录");
    selectAll.onchange = function(event) {
        toggleSelectAll(event.target.checked);
    };
    headSelect.appendChild(selectAll);
    head.appendChild(headSelect);

    const nameHead = document.createElement("div");
    nameHead.textContent = "名称";
    head.appendChild(nameHead);

    const sizeHead = document.createElement("div");
    sizeHead.className = "size-col";
    sizeHead.textContent = "大小";
    head.appendChild(sizeHead);

    const modifiedHead = document.createElement("div");
    modifiedHead.className = "modified-col";
    modifiedHead.textContent = "修改时间";
    head.appendChild(modifiedHead);

    const actionHead = document.createElement("div");
    actionHead.textContent = "操作";
    head.appendChild(actionHead);
    table.appendChild(head);

    fileItems.forEach(function(item) {
        const row = document.createElement("div");
        row.className = "table-row" + (selected.has(item.path) ? " selected" : "");

        const checkboxWrap = document.createElement("div");
        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.checked = selected.has(item.path);
        checkbox.onchange = function(event) {
            toggleSelection(item.path, event.target.checked);
        };
        checkboxWrap.appendChild(checkbox);

        const nameCell = document.createElement("div");
        nameCell.className = "name-cell";

        const type = document.createElement("span");
        type.className = "item-type" + (item.is_dir ? "" : " file");
        type.textContent = kindText(item);
        nameCell.appendChild(type);

        const name = document.createElement("div");
        name.className = "item-name";
        name.textContent = item.name;
        name.onclick = function() {
            openItem(item);
        };
        nameCell.appendChild(name);

        const size = document.createElement("div");
        size.className = "size-col";
        size.textContent = item.is_dir ? "-" : formatSize(item.size);

        const modified = document.createElement("div");
        modified.className = "modified-col";
        modified.textContent = item.modified;

        row.appendChild(checkboxWrap);
        row.appendChild(nameCell);
        row.appendChild(size);
        row.appendChild(modified);
        row.appendChild(createItemActions(item));
        table.appendChild(row);
    });

    container.appendChild(table);
}

function renderCardView(container) {
    const cards = document.createElement("div");
    cards.className = "cards";

    fileItems.forEach(function(item) {
        const card = document.createElement("div");
        card.className = "file-card" + (selected.has(item.path) ? " selected" : "");

        const top = document.createElement("div");
        top.className = "card-top";

        const left = document.createElement("div");
        left.style.display = "grid";
        left.style.gap = "8px";

        const type = document.createElement("span");
        type.className = "item-type" + (item.is_dir ? "" : " file");
        type.style.width = "fit-content";
        type.textContent = kindText(item);
        left.appendChild(type);

        const name = document.createElement("div");
        name.className = "card-name";
        name.textContent = item.name;
        name.onclick = function() {
            openItem(item);
        };
        left.appendChild(name);
        top.appendChild(left);

        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.checked = selected.has(item.path);
        checkbox.onchange = function(event) {
            toggleSelection(item.path, event.target.checked);
        };
        top.appendChild(checkbox);

        const meta = document.createElement("div");
        meta.className = "meta";

        const sizeRow = document.createElement("div");
        sizeRow.className = "meta-row";
        sizeRow.innerHTML = "<span>大小</span><span>" + (item.is_dir ? "-" : formatSize(item.size)) + "</span>";

        const timeRow = document.createElement("div");
        timeRow.className = "meta-row";
        timeRow.innerHTML = "<span>修改时间</span><span>" + item.modified + "</span>";

        const pathRow = document.createElement("div");
        pathRow.className = "meta-row";
        const pathLabel = document.createElement("span");
        pathLabel.textContent = "路径";
        const pathValue = document.createElement("span");
        pathValue.textContent = item.path;
        pathValue.style.textAlign = "right";
        pathValue.style.wordBreak = "break-all";
        pathRow.appendChild(pathLabel);
        pathRow.appendChild(pathValue);

        meta.appendChild(sizeRow);
        meta.appendChild(timeRow);
        meta.appendChild(pathRow);

        card.appendChild(top);
        card.appendChild(meta);
        card.appendChild(createItemActions(item));
        cards.appendChild(card);
    });

    container.appendChild(cards);
}

function renderFiles() {
    const container = byId("fileList");
    if (!container) {
        return;
    }
    container.innerHTML = "";

    if (!fileItems.length) {
        const empty = document.createElement("div");
        empty.className = "empty";
        empty.textContent = "当前目录没有文件。";
        container.appendChild(empty);
        updateSelectionSummary();
        return;
    }

    if (viewMode === "card") {
        renderCardView(container);
    } else {
        renderListView(container);
    }
    updateSelectionSummary();
}

async function loadDisks() {
    const data = await apiJSON("/api/disks");
    const select = byId("diskList");
    const rootInput = byId("rootPath");
    const items = Array.isArray(data.items) ? data.items.slice() : [];
    if (data.current && items.indexOf(data.current) === -1) {
        items.unshift(data.current);
    }

    select.innerHTML = "";
    items.forEach(function(item) {
        const option = document.createElement("option");
        option.value = item;
        option.textContent = item;
        select.appendChild(option);
    });

    if (data.current) {
        select.value = data.current;
        rootInput.value = data.current;
    }
}

async function loadAccount() {
    const data = await apiJSON("/api/account");
    currentUsername = data.username || "";
    byId("accountSummary").textContent = "账号: " + (currentUsername || "--");
    byId("accountUsername").value = currentUsername;
}

async function loadFiles() {
    const requestToken = ++currentListToken;
    if (currentListController) {
        currentListController.abort();
    }
    const controller = new AbortController();
    currentListController = controller;

    try {
        setStatus("正在加载文件...", "loading");
        renderPathBar();
        const data = await apiJSON("/api/list?path=" + encodeURIComponent(currentPath), {
            signal: controller.signal
        });
        if (requestToken !== currentListToken) {
            return;
        }
        currentPath = data.path || "/";
        fileItems = Array.isArray(data.items) ? data.items : [];
        renderPathBar();
        renderFiles();
        setStatus("已加载 " + fileItems.length + " 项", "success");
    } catch (error) {
        if (error && error.name === "AbortError") {
            return;
        }
        if (requestToken !== currentListToken) {
            return;
        }
        fileItems = [];
        renderFiles();
        setStatus(error.message, "error");
    } finally {
        if (currentListController === controller) {
            currentListController = null;
        }
    }
}

async function mountDisk() {
    const path = byId("rootPath").value.trim();
    if (!path) {
        alert("请输入要挂载的目录路径");
        return;
    }

    try {
        setStatus("正在切换挂载目录...", "loading");
        await apiJSON("/api/mount", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: formBody({ path: path })
        });
        currentPath = "/";
        selected = new Set();
        updateSelectionSummary();
        await loadDisks();
        await loadFiles();
        setStatus("挂载目录已更新", "success");
    } catch (error) {
        setStatus(error.message, "error");
    }
}

function goBack() {
    if (currentPath === "/") {
        return;
    }
    const parts = currentPath.split("/").filter(Boolean);
    parts.pop();
    openPath(parts.length ? "/" + parts.join("/") : "/");
}

async function createFolder() {
    const name = prompt("请输入文件夹名称");
    if (!name) {
        return;
    }

    try {
        setStatus("正在创建文件夹...", "loading");
        await apiJSON("/api/mkdir", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: formBody({ path: currentPath, name: name })
        });
        await loadFiles();
        setStatus("文件夹已创建", "success");
    } catch (error) {
        setStatus(error.message, "error");
    }
}

function triggerUpload() {
    byId("uploadInput").click();
}

async function handleUpload(event) {
    const files = Array.from(event.target.files || []);
    if (!files.length) {
        return;
    }

    try {
        setStatus("正在上传 " + files.length + " 个文件...", "loading");
        const form = new FormData();
        form.append("path", currentPath);
        files.forEach(function(file) {
            form.append("files", file, file.name);
        });
        await apiJSON("/api/upload", {
            method: "POST",
            body: form
        });
        event.target.value = "";
        await loadFiles();
        setStatus("上传完成", "success");
    } catch (error) {
        setStatus(error.message, "error");
    }
}

function selectedPaths() {
    return Array.from(selected);
}

async function runSelectionAction(endpoint, options) {
    const paths = selectedPaths();
    if (!paths.length) {
        alert(options.emptyMessage);
        return false;
    }

    if (options.confirmMessage && !confirm(options.confirmMessage)) {
        return false;
    }

    try {
        setStatus(options.loadingMessage, "loading");
        await apiJSON(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ paths: paths })
        });
        selected = new Set();
        updateSelectionSummary();
        await loadFiles();
        setStatus(options.successMessage, "success");
        return true;
    } catch (error) {
        setStatus(error.message, "error");
        return false;
    }
}

function deleteSelected() {
    runSelectionAction("/api/delete", {
        emptyMessage: "请先选择要删除的文件或文件夹",
        confirmMessage: "确定删除选中的项目吗？",
        loadingMessage: "正在删除所选项目...",
        successMessage: "删除完成"
    });
}

function zipSelected() {
    runSelectionAction("/api/zip", {
        emptyMessage: "请先选择要压缩的项目",
        loadingMessage: "正在压缩所选项目...",
        successMessage: "压缩完成"
    });
}

function unzipSelected() {
    runSelectionAction("/api/unzip", {
        emptyMessage: "请先选择 zip 文件",
        loadingMessage: "正在解压所选项目...",
        successMessage: "解压完成"
    });
}

async function downloadItem(item) {
    try {
        setStatus("正在下载 " + item.name + "...", "loading");
        const response = await apiFetch(downloadURL(item.path));
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = item.name;
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.setTimeout(function() {
            URL.revokeObjectURL(url);
        }, 1000);
        setStatus("下载已开始", "success");
    } catch (error) {
        setStatus(error.message, "error");
    }
}

async function previewItem(item) {
    const kind = previewKind(item);
    if (!kind) {
        setStatus("当前文件不支持在线预览。", "error");
        return;
    }

    try {
        setStatus("正在加载预览...", "loading");
        byId("previewTitle").textContent = item.name;
        const body = byId("previewBody");
        body.innerHTML = "";

        if (kind === "image") {
            const img = document.createElement("img");
            img.src = downloadURL(item.path);
            img.alt = item.name;
            body.appendChild(img);
        } else if (kind === "video") {
            const video = document.createElement("video");
            video.src = downloadURL(item.path);
            video.controls = true;
            video.autoplay = true;
            body.appendChild(video);
        } else if (kind === "audio") {
            const audio = document.createElement("audio");
            audio.src = downloadURL(item.path);
            audio.controls = true;
            audio.autoplay = true;
            body.appendChild(audio);
        } else if (kind === "pdf") {
            const frame = document.createElement("iframe");
            frame.className = "preview-frame";
            frame.src = downloadURL(item.path);
            frame.title = item.name;
            body.appendChild(frame);
        } else if (kind === "text") {
            const data = await apiJSON("/api/preview?path=" + encodeURIComponent(item.path));
            const wrapper = document.createElement("div");
            wrapper.style.width = "100%";
            if (data.truncated) {
                const note = document.createElement("div");
                note.className = "preview-note";
                note.textContent = "为保证性能，仅显示前 256 KB 内容。";
                wrapper.appendChild(note);
            }
            const pre = document.createElement("pre");
            pre.className = "preview-text";
            pre.textContent = data.text || "";
            wrapper.appendChild(pre);
            body.appendChild(wrapper);
        } else {
            body.textContent = "当前文件不支持在线预览。";
        }

        byId("previewModal").classList.add("open");
        setStatus("预览已打开", "success");
    } catch (error) {
        setStatus(error.message, "error");
    }
}

function closePreview() {
    byId("previewModal").classList.remove("open");
    byId("previewBody").innerHTML = "";
}

function openAccountModal() {
    byId("accountUsername").value = currentUsername;
    byId("accountCurrentPassword").value = "";
    byId("accountNewPassword").value = "";
    byId("accountConfirmPassword").value = "";
    byId("accountModal").classList.add("open");
}

function closeAccountModal() {
    byId("accountModal").classList.remove("open");
}

async function saveAccount() {
    const newUsername = byId("accountUsername").value.trim();
    const currentPassword = byId("accountCurrentPassword").value;
    const newPassword = byId("accountNewPassword").value;
    const confirmPassword = byId("accountConfirmPassword").value;

    if (!newUsername) {
        alert("请输入账号");
        return;
    }
    if (!currentPassword) {
        alert("请输入当前密码");
        return;
    }
    if (newPassword !== confirmPassword) {
        alert("两次输入的新密码不一致");
        return;
    }

    try {
        setStatus("正在保存账号设置...", "loading");
        const verifyAuth = "Basic " + btoa(currentUsername + ":" + currentPassword);
        const data = await apiJSON("/api/account", {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": verifyAuth
            },
            body: formBody({
                username: newUsername,
                current_password: currentPassword,
                new_password: newPassword
            })
        });

        const effectivePassword = newPassword || currentPassword;
        authHeader = "Basic " + btoa(newUsername + ":" + effectivePassword);
        currentUsername = data.username || newUsername;
        byId("accountSummary").textContent = "账号: " + currentUsername;
        closeAccountModal();
        setStatus("账号设置已更新", "success");
    } catch (error) {
        setStatus(error.message, "error");
    }
}

function permissionText(permission) {
    if (permission === "download") return "只下载";
    if (permission === "view") return "可预览";
    if (permission === "edit") return "可编辑";
    return permission || "-";
}

function selectedShareTokens() {
    return Array.from(selectedShares);
}

function ensureShareUI() {
    if (byId("shareList")) {
        return;
    }

    const uploadButton = document.querySelector('.button-group button[onclick="triggerUpload()"]');
    if (uploadButton && uploadButton.parentElement) {
        const createBtn = document.createElement("button");
        createBtn.className = "secondary";
        createBtn.textContent = "创建分享";
        createBtn.onclick = openShareCreateModal;
        uploadButton.parentElement.insertBefore(createBtn, uploadButton.nextSibling);

        const batchBtn = document.createElement("button");
        batchBtn.className = "secondary";
        batchBtn.textContent = "批量权限";
        batchBtn.onclick = openSharePermissionModal;
        uploadButton.parentElement.insertBefore(batchBtn, createBtn.nextSibling);
    }

    const app = document.querySelector(".app");
    const fileList = byId("fileList");
    if (app && fileList) {
        const panel = document.createElement("div");
        panel.className = "share-panel";
        panel.innerHTML = '<div class="topbar" style="margin-bottom:14px;align-items:center">' +
            '<div><h3>分享管理</h3><p style="margin:6px 0 0;color:#6b7280;font-size:14px">支持只下载、可预览和可编辑三种权限。</p></div>' +
            '<div class="button-group"><button class="secondary" type="button" onclick="loadShares()">刷新分享</button></div>' +
            '</div><div id="shareList" class="share-list"></div>';
        app.appendChild(panel);
    }

    const accountModal = byId("accountModal");
    if (accountModal && accountModal.parentElement) {
        const createModal = document.createElement("div");
        createModal.id = "shareCreateModal";
        createModal.className = "modal";
        createModal.innerHTML = '<div class="dialog"><div class="dialog-head"><h3>创建分享</h3>' +
            '<button class="close-btn tiny" type="button" onclick="closeShareCreateModal()">关闭</button></div>' +
            '<div class="form-grid"><div><label for="sharePermission">分享权限</label>' +
            '<select id="sharePermission"><option value="download">只下载</option><option value="view">可预览 + 下载</option><option value="edit">可编辑</option></select></div>' +
            '<p id="shareCreateHint">请选择文件或文件夹后批量创建分享。</p>' +
            '<div class="button-group"><button type="button" onclick="createShares()">立即创建</button>' +
            '<button class="secondary" type="button" onclick="closeShareCreateModal()">取消</button></div></div></div>';

        const permissionModal = document.createElement("div");
        permissionModal.id = "sharePermissionModal";
        permissionModal.className = "modal";
        permissionModal.innerHTML = '<div class="dialog"><div class="dialog-head"><h3>批量设置权限</h3>' +
            '<button class="close-btn tiny" type="button" onclick="closeSharePermissionModal()">关闭</button></div>' +
            '<div class="form-grid"><div><label for="sharePermissionBatch">新权限</label>' +
            '<select id="sharePermissionBatch"><option value="download">只下载</option><option value="view">可预览 + 下载</option><option value="edit">可编辑</option></select></div>' +
            '<p id="sharePermissionHint">先在分享管理列表中勾选要修改的分享项。</p>' +
            '<div class="button-group"><button type="button" onclick="applySharePermission()">保存权限</button>' +
            '<button class="secondary" type="button" onclick="closeSharePermissionModal()">取消</button></div></div></div>';

        accountModal.parentElement.appendChild(createModal);
        accountModal.parentElement.appendChild(permissionModal);
    }
}
function renderShares() {
    const list = byId("shareList");
    if (!list) {
        return;
    }

    list.innerHTML = "";
    if (!shareItems.length) {
        const empty = document.createElement("div");
        empty.className = "share-empty";
        empty.textContent = "还没有分享链接。";
        list.appendChild(empty);
        return;
    }

    shareItems.forEach(function(item) {
        const row = document.createElement("div");
        row.className = "share-item";

        const top = document.createElement("div");
        top.className = "share-top";

        const left = document.createElement("div");
        left.style.display = "grid";
        left.style.gap = "8px";

        const title = document.createElement("div");
        title.className = "share-title";
        title.textContent = item.name;
        left.appendChild(title);

        const meta = document.createElement("div");
        meta.className = "share-meta";
        meta.innerHTML = "<div>创建人: " + (item.created_by || "-") + "</div><div>路径: " + (item.full_path || "-") + "</div><div>更新时间: " + (item.updated_at || "-") + "</div>";
        left.appendChild(meta);
        top.appendChild(left);

        const right = document.createElement("div");
        right.style.display = "grid";
        right.style.gap = "8px";
        right.style.justifyItems = "end";

        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.checked = selectedShares.has(item.token);
        checkbox.onchange = function(event) {
            if (event.target.checked) selectedShares.add(item.token);
            else selectedShares.delete(item.token);
        };
        right.appendChild(checkbox);

        const badge = document.createElement("span");
        badge.className = "permission-badge";
        badge.textContent = permissionText(item.permission);
        right.appendChild(badge);
        top.appendChild(right);

        const link = document.createElement("input");
        link.className = "share-link";
        link.readOnly = true;
        link.value = item.url || "";

        const actions = document.createElement("div");
        actions.className = "actions";
        actions.appendChild(makeActionButton("复制链接", "secondary", function() {
            copyShareLink(item.url || "");
        }));
        actions.appendChild(makeActionButton("打开", "secondary", function() {
            window.open(item.url, "_blank");
        }));
        actions.appendChild(makeActionButton("删除分享", "secondary", function() {
            removeShares([item.token]);
        }));

        row.appendChild(top);
        row.appendChild(link);
        row.appendChild(actions);
        list.appendChild(row);
    });
}

async function loadShares() {
    try {
        const data = await apiJSON("/api/shares");
        shareItems = Array.isArray(data.items) ? data.items : [];
        selectedShares = new Set(shareItems.filter(function(item) {
            return selectedShares.has(item.token);
        }).map(function(item) {
            return item.token;
        }));
        renderShares();
    } catch (error) {
        setStatus(error.message, "error");
    }
}

function openShareCreateModal() {
    const paths = selectedPaths();
    if (!paths.length) {
        alert("请先选择要分享的文件或文件夹");
        return;
    }
    byId("shareCreateHint").textContent = "将为 " + paths.length + " 个项目创建分享链接。";
    byId("shareCreateModal").classList.add("open");
}

function closeShareCreateModal() {
    const modal = byId("shareCreateModal");
    if (modal) modal.classList.remove("open");
}

async function createShares() {
    const paths = selectedPaths();
    if (!paths.length) {
        alert("请先选择要分享的项目");
        return;
    }

    try {
        setStatus("正在创建分享链接...", "loading");
        await apiJSON("/api/shares", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                paths: paths,
                permission: byId("sharePermission").value
            })
        });
        closeShareCreateModal();
        await loadShares();
        setStatus("分享链接已创建", "success");
    } catch (error) {
        setStatus(error.message, "error");
    }
}

function openSharePermissionModal() {
    const tokens = selectedShareTokens();
    if (!tokens.length) {
        alert("请先在分享管理中勾选分享项");
        return;
    }
    byId("sharePermissionHint").textContent = "将批量修改 " + tokens.length + " 个分享的权限。";
    byId("sharePermissionModal").classList.add("open");
}

function closeSharePermissionModal() {
    const modal = byId("sharePermissionModal");
    if (modal) modal.classList.remove("open");
}

async function applySharePermission() {
    const tokens = selectedShareTokens();
    if (!tokens.length) {
        alert("请先勾选要修改的分享");
        return;
    }

    try {
        setStatus("正在批量修改分享权限...", "loading");
        await apiJSON("/api/shares", {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                tokens: tokens,
                permission: byId("sharePermissionBatch").value
            })
        });
        closeSharePermissionModal();
        await loadShares();
        setStatus("分享权限已更新", "success");
    } catch (error) {
        setStatus(error.message, "error");
    }
}

async function removeShares(tokens) {
    if (!tokens.length) {
        return;
    }
    if (!confirm("确定删除选中的分享链接吗？")) {
        return;
    }

    try {
        setStatus("正在删除分享链接...", "loading");
        await apiJSON("/api/shares", {
            method: "DELETE",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ tokens: tokens })
        });
        tokens.forEach(function(token) {
            selectedShares.delete(token);
        });
        await loadShares();
        setStatus("分享链接已删除", "success");
    } catch (error) {
        setStatus(error.message, "error");
    }
}

async function copyShareLink(link) {
    if (!link) {
        return;
    }
    try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(link);
        } else {
            const temp = document.createElement("input");
            temp.value = link;
            document.body.appendChild(temp);
            temp.select();
            document.execCommand("copy");
            temp.remove();
        }
        setStatus("分享链接已复制", "success");
    } catch (error) {
        setStatus("复制链接失败，请手动复制", "error");
    }
}

function handleGlobalKeydown(event) {
    if (event.key === "Escape" && byId("previewModal").classList.contains("open")) {
        closePreview();
    }
}

async function init() {
    ensureShareUI();
    byId("uploadInput").addEventListener("change", handleUpload);
    document.addEventListener("keydown", handleGlobalKeydown);
    setViewMode(viewMode);
    renderPathBar();
    updateSelectionSummary();
    try {
        await loadDisks();
        await loadAccount();
        await loadFiles();
        await loadShares();
    } catch (error) {
        setStatus(error.message, "error");
    }
}

init();
</script>
</body>
</html>
`
