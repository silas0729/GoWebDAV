package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	pathpkg "path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"golang.org/x/net/webdav"
)

const (
	defaultHTTPPort = ":8081"
	davPrefix       = "/dav/"
	configPath      = "./disk_config.json"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AppConfig struct {
	Root  string `json:"root"`
	Users []User `json:"users"`
}

type FileItem struct {
	Name     string `json:"name"`
	IsDir    bool   `json:"is_dir"`
	Size     int64  `json:"size"`
	Path     string `json:"path"`
	Modified string `json:"modified"`
}

type dynamicWebDAVFS struct{}

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
)

func main() {
	loadConfig()
	if err := os.MkdirAll(getCurrentRoot(), 0755); err != nil {
		log.Fatal(err)
	}

	httpPort := getHTTPPort()

	http.HandleFunc("/api/disks", basicAuthFunc(apiGetDisks))
	http.HandleFunc("/api/mount", basicAuthFunc(apiMountDisk))
	http.HandleFunc("/api/list", basicAuthFunc(apiList))
	http.HandleFunc("/api/mkdir", basicAuthFunc(apiMkdir))
	http.HandleFunc("/api/upload", basicAuthFunc(apiUpload))
	http.HandleFunc("/api/delete", basicAuthFunc(apiDelete))
	http.HandleFunc("/api/download", basicAuthFunc(apiDownload))
	http.HandleFunc("/api/zip", basicAuthFunc(apiZip))
	http.HandleFunc("/api/unzip", basicAuthFunc(apiUnzip))
	http.HandleFunc("/api/account", basicAuthFunc(apiAccount))
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
		Root:  src.Root,
		Users: make([]User, 0, len(src.Users)),
	}
	dst.Users = append(dst.Users, src.Users...)
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
	return writeConfig(snapshot)
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
	return os.MkdirAll(full, perm)
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
	return os.OpenFile(full, flag, perm)
}

func (dynamicWebDAVFS) RemoveAll(_ context.Context, name string) error {
	if cleanVirtualPath(name) == "/" {
		return errors.New("cannot remove root")
	}
	full, err := resolvePath(getCurrentRoot(), name)
	if err != nil {
		return err
	}
	return os.RemoveAll(full)
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
	return os.Rename(oldFull, newFull)
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

	entries, err := os.ReadDir(full)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	items := make([]FileItem, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		items = append(items, FileItem{
			Name:     entry.Name(),
			IsDir:    entry.IsDir(),
			Size:     info.Size(),
			Path:     pathpkg.Join(virtualPath, entry.Name()),
			Modified: info.ModTime().Format("2006-01-02 15:04"),
		})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].IsDir != items[j].IsDir {
			return items[i].IsDir
		}
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})

	writeJSON(w, map[string]any{
		"path":  virtualPath,
		"items": items,
	})
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
	writeJSON(w, map[string]bool{"ok": true})
}

func apiUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	basePath := cleanVirtualPath(r.PostFormValue("path"))
	targetDir, err := resolvePath(getCurrentRoot(), basePath)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	filename := filepath.Base(header.Filename)
	if filename == "." || filename == string(os.PathSeparator) || filename == "" {
		http.Error(w, "invalid file name", http.StatusBadRequest)
		return
	}

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	dst, err := os.Create(filepath.Join(targetDir, filename))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func apiDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	virtualPath := cleanVirtualPath(r.PostFormValue("path"))
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
	writeJSON(w, map[string]bool{"ok": true})
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

func apiZip(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	virtualPath := cleanVirtualPath(r.PostFormValue("path"))
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
	writeJSON(w, map[string]bool{"ok": true})
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
		defer file.Close()

		_, err = io.Copy(w, file)
		return err
	})
}

func apiUnzip(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	virtualPath := cleanVirtualPath(r.PostFormValue("path"))
	full, err := resolvePath(getCurrentRoot(), virtualPath)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	if !strings.EqualFold(filepath.Ext(full), ".zip") {
		http.Error(w, "please select a zip file", http.StatusBadRequest)
		return
	}

	rc, err := zip.OpenReader(full)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rc.Close()

	zipExt := filepath.Ext(full)
	destDir := full[:len(full)-len(zipExt)]
	destAbs, err := filepath.Abs(destDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := os.MkdirAll(destAbs, 0755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for _, file := range rc.File {
		targetPath := filepath.Join(destAbs, filepath.FromSlash(file.Name))
		targetAbs, err := filepath.Abs(targetPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		relCheck, err := filepath.Rel(destAbs, targetAbs)
		if err != nil || relCheck == ".." || strings.HasPrefix(relCheck, ".."+string(os.PathSeparator)) {
			http.Error(w, "zip contains invalid path", http.StatusBadRequest)
			return
		}

		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(targetAbs, 0755); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(targetAbs), 0755); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		src, err := file.Open()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		dst, err := os.OpenFile(targetAbs, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			src.Close()
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_, copyErr := io.Copy(dst, src)
		closeErr := dst.Close()
		srcErr := src.Close()
		if copyErr != nil {
			http.Error(w, copyErr.Error(), http.StatusInternalServerError)
			return
		}
		if closeErr != nil {
			http.Error(w, closeErr.Error(), http.StatusInternalServerError)
			return
		}
		if srcErr != nil {
			http.Error(w, srcErr.Error(), http.StatusInternalServerError)
			return
		}
	}

	writeJSON(w, map[string]bool{"ok": true})
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
        .summary{
            display:flex;
            align-items:center;
            color:#6b7280;
            font-size:14px;
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
        .table-row:last-child{
            border-bottom:none;
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
            <div class="button-group">
                <button class="secondary" onclick="goBack()">返回上级</button>
                <button onclick="createFolder()">新建文件夹</button>
                <button onclick="triggerUpload()">上传文件</button>
                <button class="accent" onclick="zipSelected()">压缩</button>
                <button class="accent" onclick="unzipSelected()">解压</button>
                <button class="danger" onclick="deleteSelected()">删除</button>
            </div>
            <div class="summary" id="selectionSummary">未选中项目</div>
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
let previewObjectUrl = "";

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

function isImage(name) {
    return ["jpg", "jpeg", "png", "gif", "webp", "bmp", "svg"].includes(extOf(name));
}

function isVideo(name) {
    return ["mp4", "webm", "ogg", "mov", "m4v"].includes(extOf(name));
}

function isAudio(name) {
    return ["mp3", "wav", "ogg", "m4a", "flac"].includes(extOf(name));
}

function kindText(item) {
    if (item.is_dir) {
        return "目录";
    }
    const ext = extOf(item.name);
    return ext ? ext.toUpperCase() : "文件";
}

function updateSelectionSummary() {
    const count = selected.size;
    byId("selectionSummary").textContent = count === 0 ? "未选中项目" : "已选中 " + count + " 项";
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
    if (isImage(item.name) || isVideo(item.name) || isAudio(item.name)) {
        previewItem(item);
        return;
    }
    downloadItem(item);
}

function createItemActions(item) {
    const box = document.createElement("div");
    box.className = "actions";

    if (!item.is_dir) {
        if (isImage(item.name) || isVideo(item.name) || isAudio(item.name)) {
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
    head.innerHTML = "<div></div><div>名称</div><div class='size-col'>大小</div><div class='modified-col'>修改时间</div><div>操作</div>";
    table.appendChild(head);

    fileItems.forEach(function(item) {
        const row = document.createElement("div");
        row.className = "table-row";

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
        card.className = "file-card";

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
        return;
    }

    if (viewMode === "card") {
        renderCardView(container);
    } else {
        renderListView(container);
    }
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
    try {
        setStatus("正在加载文件...", "loading");
        renderPathBar();
        const data = await apiJSON("/api/list?path=" + encodeURIComponent(currentPath));
        currentPath = data.path || "/";
        fileItems = Array.isArray(data.items) ? data.items : [];
        renderPathBar();
        renderFiles();
        setStatus("已加载 " + fileItems.length + " 项", "success");
    } catch (error) {
        fileItems = [];
        renderFiles();
        setStatus(error.message, "error");
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
        for (const file of files) {
            const form = new FormData();
            form.append("path", currentPath);
            form.append("file", file);
            await apiJSON("/api/upload", {
                method: "POST",
                body: form
            });
        }
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
        for (const path of paths) {
            await apiJSON(endpoint, {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: formBody({ path: path })
            });
        }
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
        const response = await apiFetch("/api/download?path=" + encodeURIComponent(item.path));
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

function revokePreviewUrl() {
    if (previewObjectUrl) {
        URL.revokeObjectURL(previewObjectUrl);
        previewObjectUrl = "";
    }
}

async function previewItem(item) {
    try {
        setStatus("正在加载预览...", "loading");
        revokePreviewUrl();
        const response = await apiFetch("/api/download?path=" + encodeURIComponent(item.path));
        const blob = await response.blob();
        previewObjectUrl = URL.createObjectURL(blob);
        byId("previewTitle").textContent = item.name;
        const body = byId("previewBody");
        body.innerHTML = "";

        if (isImage(item.name)) {
            const img = document.createElement("img");
            img.src = previewObjectUrl;
            img.alt = item.name;
            body.appendChild(img);
        } else if (isVideo(item.name)) {
            const video = document.createElement("video");
            video.src = previewObjectUrl;
            video.controls = true;
            video.autoplay = true;
            body.appendChild(video);
        } else if (isAudio(item.name)) {
            const audio = document.createElement("audio");
            audio.src = previewObjectUrl;
            audio.controls = true;
            audio.autoplay = true;
            body.appendChild(audio);
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
    revokePreviewUrl();
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

async function init() {
    byId("uploadInput").addEventListener("change", handleUpload);
    setViewMode(viewMode);
    updateSelectionSummary();
    try {
        await loadDisks();
        await loadAccount();
        await loadFiles();
    } catch (error) {
        setStatus(error.message, "error");
    }
}

init();
</script>
</body>
</html>
`
