package main

import (
	"archive/zip"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/net/webdav"
)

var (
	currentRoot = "./files"
	httpPort    = ":8081"
	davPrefix   = "/dav/"
	configPath  = "./disk_config.json"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var users = []User{
	{Username: "admin", Password: "123456"},
}

func main() {
	loadConfig()
	os.MkdirAll(currentRoot, 0755)
	updateWebDAV()

	http.HandleFunc("/api/disks", basicAuthFunc(apiGetDisks))
	http.HandleFunc("/api/mount", basicAuthFunc(apiMountDisk))
	http.HandleFunc("/api/list", basicAuthFunc(apiList))
	http.HandleFunc("/api/mkdir", basicAuthFunc(apiMkdir))
	http.HandleFunc("/api/upload", basicAuthFunc(apiUpload))
	http.HandleFunc("/api/delete", basicAuthFunc(apiDelete))
	http.HandleFunc("/api/download", basicAuthFunc(apiDownload))
	http.HandleFunc("/api/zip", basicAuthFunc(apiZip))
	http.HandleFunc("/api/unzip", basicAuthFunc(apiUnzip))
	http.HandleFunc("/", basicAuthFunc(page))

	log.Println("启动：http://127.0.0.1" + httpPort)
	log.Println("WebDAV：http://127.0.0.1" + httpPort + davPrefix)
	log.Fatal(http.ListenAndServe(httpPort, nil))
}

func loadConfig() {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return
	}
	var cfg struct {
		Root string `json:"root"`
	}
	if json.Unmarshal(data, &cfg) == nil && cfg.Root != "" {
		currentRoot = cfg.Root
	}
}

func saveConfig() {
	data, _ := json.MarshalIndent(map[string]string{"root": currentRoot}, "", "  ")
	os.WriteFile(configPath, data, 0644)
}

func updateWebDAV() {
	dav := &webdav.Handler{
		Prefix:     davPrefix,
		FileSystem: webdav.Dir(currentRoot),
		LockSystem: webdav.NewMemLS(),
	}
	http.Handle(davPrefix, basicAuth(dav))
}

func apiGetDisks(w http.ResponseWriter, r *http.Request) {
	var disks []string
	if runtime.GOOS == "windows" {
		for c := 'A'; c <= 'Z'; c++ {
			path := string(c) + ":/"
			if _, err := os.ReadDir(path); err == nil {
				disks = append(disks, path)
			}
		}
	} else {
		disks = []string{"/", "/mnt", "/home", "/www/wwwroot"}
	}
	json.NewEncoder(w).Encode(disks)
}

func apiMountDisk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	path := r.PostFormValue("path")
	if _, err := os.ReadDir(path); err != nil {
		http.Error(w, "目录不可访问", 400)
		return
	}
	currentRoot = path
	saveConfig()
	updateWebDAV()
	w.Write([]byte(`{"ok":true}`))
}

func basicAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || !checkUser(u, p) {
			w.Header().Set("WWW-Authenticate", `Basic realm="disk"`)
			w.WriteHeader(401)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func basicAuthFunc(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || !checkUser(u, p) {
			w.Header().Set("WWW-Authenticate", `Basic realm="disk"`)
			w.WriteHeader(401)
			return
		}
		fn(w, r)
	}
}

func checkUser(username, password string) bool {
	for _, u := range users {
		if u.Username == username && u.Password == password {
			return true
		}
	}
	return false
}

type FileItem struct {
	Name  string `json:"name"`
	IsDir bool   `json:"is_dir"`
	Size  int64  `json:"size"`
	Path  string `json:"path"`
}

func apiList(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		path = "/"
	}
	full := filepath.Join(currentRoot, filepath.Clean(path))
	var items []FileItem
	entries, err := os.ReadDir(full)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	for _, e := range entries {
		info, _ := e.Info()
		items = append(items, FileItem{
			Name:  e.Name(),
			IsDir: e.IsDir(),
			Size:  info.Size(),
			Path:  filepath.Join(path, e.Name()),
		})
	}
	json.NewEncoder(w).Encode(items)
}

func apiMkdir(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	path := r.PostFormValue("path")
	name := r.PostFormValue("name")
	full := filepath.Join(currentRoot, filepath.Clean(path), name)
	os.MkdirAll(full, 0755)
	w.Write([]byte(`{"ok":true}`))
}

func apiUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	path := r.PostFormValue("path")
	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer file.Close()

	targetDir := filepath.Join(currentRoot, filepath.Clean(path))
	os.MkdirAll(targetDir, 0755)
	dstPath := filepath.Join(targetDir, handler.Filename)

	dst, err := os.Create(dstPath)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer dst.Close()
	io.Copy(dst, file)
	w.Write([]byte(`{"ok":true}`))
}

func apiDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	path := r.PostFormValue("path")
	full := filepath.Join(currentRoot, filepath.Clean(path))
	os.RemoveAll(full)
	w.Write([]byte(`{"ok":true}`))
}

func apiDownload(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	full := filepath.Join(currentRoot, filepath.Clean(path))
	http.ServeFile(w, r, full)
}

func apiZip(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	path := r.PostFormValue("path")
	full := filepath.Join(currentRoot, filepath.Clean(path))
	zipPath := full + ".zip"

	zipFile, err := os.Create(zipPath)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer zipFile.Close()

	zw := zip.NewWriter(zipFile)
	defer zw.Close()

	baseDir := filepath.Dir(full)
	filepath.Walk(full, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(baseDir, p)
		if info.IsDir() {
			rel += "/"
		}
		w, _ := zw.Create(rel)
		if !info.IsDir() {
			f, _ := os.Open(p)
			defer f.Close()
			io.Copy(w, f)
		}
		return nil
	})
	w.Write([]byte(`{"ok":true}`))
}

func apiUnzip(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	path := r.PostFormValue("path")
	full := filepath.Join(currentRoot, filepath.Clean(path))

	rc, err := zip.OpenReader(full)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rc.Close()

	destDir := strings.TrimSuffix(full, ".zip")
	os.MkdirAll(destDir, 0755)

	for _, f := range rc.File {
		fpath := filepath.Join(destDir, f.Name)
		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, 0755)
			continue
		}
		os.MkdirAll(filepath.Dir(fpath), 0755)
		outFile, _ := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		rcFile, _ := f.Open()
		io.Copy(outFile, rcFile)
		outFile.Close()
		rcFile.Close()
	}
	w.Write([]byte(`{"ok":true}`))
}

func page(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>磁盘管理器</title>
    <style>
        *{box-sizing:border-box}
        body{margin:20px;background:#f5f7fa}
        .disk-bar{display:flex;gap:10px;margin-bottom:10px;align-items:center}
        select{padding:8px;min-width:120px}
        .bar{display:flex;gap:10px;margin-bottom:15px;flex-wrap:wrap}
        button{padding:8px 12px;background:#1677ff;color:white;border:none;border-radius:4px;cursor:pointer}
        .del{background:#ff4d4f}
        .back{background:#666}
        .zip-btn{background:#faad14}
        #fileList{background:white;border-radius:8px}
        .item{padding:12px;border-bottom:1px solid #eee;display:flex;align-items:center}
        .name{flex:1;cursor:pointer}
        .opts{display:flex;gap:5px}
        .opts button{padding:4px 6px;font-size:12px}
        .modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);z-index:999}
        .modal .close{position:absolute;top:20px;right:30px;color:white;font-size:30px;cursor:pointer}
        .modal-content{margin:auto;max-width:90%;max-height:90%}
    </style>
</head>
<body>
<h2>磁盘管理器</h2>
<div class="disk-bar">
    选择磁盘：<select id="diskList"></select>
    <button onclick="mountDisk()">挂载</button>
</div>
<div class="bar">
    <button class="back" onclick="back()">返回上一级</button>
    <button onclick="mkdir()">新建文件夹</button>
    <button class="del" onclick="del()">删除</button>
    <button class="zip-btn" onclick="zipSelected()">压缩</button>
    <button class="zip-btn" onclick="unzipSelected()">解压</button>
    <input type="file" multiple onchange="upload()">
</div>
<div id="fileList"></div>

<div id="previewModal" class="modal">
    <span class="close" onclick="closePreview()">×</span>
    <div id="previewContent" class="modal-content"></div>
</div>

<script>
let currentPath = "/"
let selected = []

async function loadDisks() {
    let res = await fetch("/api/disks")
    let list = await res.json()
    let sel = document.getElementById("diskList")
    sel.innerHTML = ""
    list.forEach(d => {
        sel.innerHTML += '<option value="' + d + '">' + d + '</option>'
    })
}

async function mountDisk() {
    let path = document.getElementById("diskList").value
    await fetch("/api/mount", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "path=" + encodeURIComponent(path)
    })
    currentPath = "/"
    selected = []
    load()
}

async function load() {
    let res = await fetch("/api/list?path=" + encodeURIComponent(currentPath))
    let data = await res.json()
    let list = document.getElementById("fileList")
    list.innerHTML = ""
    data.forEach(item => {
        let isDir = item.is_dir
        let icon = isDir ? "📁" : "📄"
        let path = item.path
        let ext = item.name.split('.').pop().toLowerCase()

        let opts = ""
        if (!isDir) {
            if (["jpg","jpeg","png","gif","webp"].includes(ext)) {
                opts = '<div class="opts"><button onclick="download(\''+path+'\')">下载</button><button onclick="previewImg(\''+path+'\')">预览</button></div>'
            } else if (["mp4","webm","ogg","mp3"].includes(ext)) {
                opts = '<div class="opts"><button onclick="download(\''+path+'\')">下载</button><button onclick="previewVideo(\''+path+'\')">播放</button></div>'
            } else {
                opts = '<div class="opts"><button onclick="download(\''+path+'\')">下载</button></div>'
            }
        }

        let click = isDir ? "cd('" + path + "')" : ""
        list.innerHTML += '<div class="item"><input type="checkbox" value="' + path + '" onchange="toggle(this)"><div class="name" onclick="' + click + '">' + icon + ' ' + item.name + '</div>' + opts + '</div>'
    })
}

function toggle(cb) {
    if (cb.checked) selected.push(cb.value)
    else selected = selected.filter(p => p != cb.value)
}

function cd(p) {
    currentPath = p
    selected = []
    load()
}

function back() {
    if (currentPath == "/") return
    let arr = currentPath.split("/")
    arr.pop()
    currentPath = arr.join("/") || "/"
    selected = []
    load()
}

async function mkdir() {
    let name = prompt("文件夹名")
    if (!name) return
    await fetch("/api/mkdir", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "path=" + encodeURIComponent(currentPath) + "&name=" + encodeURIComponent(name)
    })
    load()
}

async function upload() {
    let files = event.target.files
    for (let f of files) {
        let form = new FormData()
        form.append("path", currentPath)
        form.append("file", f)
        await fetch("/api/upload", { method: "POST", body: form })
    }
    load()
}

async function del() {
    if (!confirm("确定删除？")) return
    for (let p of selected) {
        await fetch("/api/delete", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: "path=" + encodeURIComponent(p)
        })
    }
    selected = []
    load()
}

async function zipSelected() {
    if (selected.length === 0) return alert("请选择")
    for (let p of selected) {
        await fetch("/api/zip", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: "path=" + encodeURIComponent(p)
        })
    }
    load()
}

async function unzipSelected() {
    if (selected.length === 0) return alert("请选择zip")
    for (let p of selected) {
        await fetch("/api/unzip", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: "path=" + encodeURIComponent(p)
        })
    }
    load()
}

function download(p) {
    window.open("/api/download?path=" + encodeURIComponent(p), "_blank")
}

function previewImg(p) {
    let m = document.getElementById("previewModal")
    let c = document.getElementById("previewContent")
    c.innerHTML = '<img src="/api/download?path=' + encodeURIComponent(p) + '" style="width:100%">'
    m.style.display = "flex"
}

function previewVideo(p) {
    let m = document.getElementById("previewModal")
    let c = document.getElementById("previewContent")
    c.innerHTML = '<video controls autoplay style="width:100%"><source src="/api/download?path=' + encodeURIComponent(p) + '"></video>'
    m.style.display = "flex"
}

function closePreview() {
    document.getElementById("previewModal").style.display = "none"
}

loadDisks()
load()
</script>
</body>
</html>
`
	w.Write([]byte(html))
}
