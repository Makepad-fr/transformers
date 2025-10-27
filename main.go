package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

//
// ============================== Templates ===============================
//

var funcMap = template.FuncMap{
	"upper": strings.ToUpper,
}

// Fail-fast template loading
var tmplIndex = template.Must(template.ParseFiles("templates/index.html"))
var tmplSelect = template.Must(
	template.New("select_format.html").
		Funcs(funcMap).
		ParseFiles("templates/select_format.html"),
)

//
// ============================== Business Rules ===============================
//

// conversionMap: detected MIME → allowed target extensions.
var conversionMap = map[string][]string{
	// Images
	"image/jpeg": {"png", "webp", "bmp", "gif"},
	"image/png":  {"jpg", "webp", "bmp", "gif"},
	"image/webp": {"jpg", "png", "gif"},
	"image/tiff": {"jpg", "png"},
	"image/bmp":  {"jpg", "png", "webp", "gif"},
	"image/gif":  {"mp4", "webm"}, // treat animated GIF → video
	// Video
	"video/mp4":        {"webm", "avi", "mov", "gif", "mp3"},
	"video/webm":       {"mp4", "avi", "mp3", "gif"},
	"video/x-msvideo":  {"mp4", "webm", "mp3"},
	"video/quicktime":  {"mp4", "webm", "mp3"},
	"video/x-matroska": {"mp4", "webm", "mp3"},
	// Audio
	"audio/mpeg":  {"wav", "ogg", "aac", "flac"},
	"audio/wav":   {"mp3", "ogg", "flac", "aac"},
	"audio/ogg":   {"mp3", "wav", "flac"},
	"audio/flac":  {"mp3", "wav", "ogg"},
	"audio/aac":   {"mp3", "wav"},
	"audio/mp4":   {"mp3", "wav", "aac"}, // common for .m4a
	"audio/x-m4a": {"mp3", "wav", "aac"},
	"audio/x-aac": {"mp3", "wav"},
	// Documents
	"application/pdf": {"png", "jpg", "txt"},
}

// validExtMap: extension → expected MIME family
var validExtMap = map[string]string{
	// Images
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".png":  "image/png",
	".webp": "image/webp",
	".tif":  "image/tiff",
	".tiff": "image/tiff",
	".bmp":  "image/bmp",
	".gif":  "image/gif",
	// Video
	".mp4":  "video/mp4",
	".m4v":  "video/mp4",
	".webm": "video/webm",
	".avi":  "video/x-msvideo",
	".mov":  "video/quicktime",
	".mkv":  "video/x-matroska",
	// Audio
	".mp3":  "audio/mpeg",
	".wav":  "audio/wav",
	".ogg":  "audio/ogg",
	".flac": "audio/flac",
	".aac":  "audio/aac",
	".m4a":  "audio/mp4",
	// Documents
	".pdf": "application/pdf",
}

//
// ============================== Globals & Config ===============================
//

const (
	maxUploadSize            = 50 << 20 // 50 MB
	uploadsDir               = "uploads"
	convertedDir             = "converted"
	readTimeout              = 15 * time.Second
	writeTimeout             = 180 * time.Second // allow longer conversions
	idleTimeout              = 60 * time.Second
	conversionTimeout        = 150 * time.Second
	downloadCacheMaxAge      = 31536000 // 1 year
	maxConcurrentConversions = 3
)

var convSem = make(chan struct{}, maxConcurrentConversions)

//
// ============================== API Types ===============================
//

type apiError struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

func writeJSONErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(apiError{Error: msg, Code: code})
}

type uploadJSON struct {
	Filename string   `json:"filename"`
	Original string   `json:"original"`
	Formats  []string `json:"formats"`
}

type convertJSON struct {
	Download     string `json:"download"`
	DownloadName string `json:"downloadName"`
}

//
// ============================== Main ===================================
//

func main() {
	_ = os.MkdirAll(uploadsDir, 0755)
	_ = os.MkdirAll(convertedDir, 0755)

	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/upload", uploadHandler)
	mux.HandleFunc("/convert", convertHandler)
	mux.HandleFunc("/download", downloadHandler)

	// static hosting
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	mux.Handle("/converted/", http.StripPrefix("/converted/", http.FileServer(http.Dir(convertedDir))))

	// Wrap with security & request-id middleware
	handler := withSecurityHeaders(withRequestID(mux))

	srv := &http.Server{
		Addr:         ":3030",
		Handler:      handler,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	// Graceful shutdown
	go func() {
		log.Println("Server started on http://localhost:3030")
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	log.Println("Server gracefully stopped")
}

//
// ============================== Middleware ==============================
//

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "microphone=(), camera=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'")
		next.ServeHTTP(w, r)
	})
}

type ctxKey string

const reqIDKey ctxKey = "rid"

func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := randHex(8)
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), reqIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

//
// ============================== Handlers ================================
//

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if err := tmplIndex.Execute(w, nil); err != nil {
		log.Printf("index template error: %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// POST /upload
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Size cap
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

	// Parse multipart (will spill to /tmp for large files)
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		if wantsJSON(r) {
			writeJSONErr(w, http.StatusRequestEntityTooLarge, "file_too_large", "File too large. Limit is 50MB.")
			return
		}
		http.Error(w, "File too large. Limit is 50MB.", http.StatusRequestEntityTooLarge)
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	file, header, err := r.FormFile("file")
	if err != nil {
		if wantsJSON(r) {
			writeJSONErr(w, http.StatusBadRequest, "invalid_upload", "Invalid file upload")
			return
		}
		http.Error(w, "Invalid file upload", http.StatusBadRequest)
		return
	}
	defer file.Close()

	ext := strings.ToLower(filepath.Ext(header.Filename))
	safeBase := sanitizeFilename(strings.TrimSuffix(header.Filename, ext))

	// MIME sniff
	mimeType, err := detectMimeType(file)
	if err != nil {
		log.Printf("mime detection error: %v", err)
		if wantsJSON(r) {
			writeJSONErr(w, http.StatusBadRequest, "mime_detect_failed", "Could not verify file type")
			return
		}
		http.Error(w, "Could not verify file type", http.StatusBadRequest)
		return
	}

	// Cross-check ext ↔ mime (with a tolerant fallback)
	if err := validateMimeAndExt(ext, mimeType); err != nil {
		// Accept common octet-stream cases by trusting extension if known
		if mimeType != "application/octet-stream" || validExtMap[ext] == "" {
			log.Printf("mime mismatch: %v (detected=%s, ext=%s)", err, mimeType, ext)
			if wantsJSON(r) {
				writeJSONErr(w, http.StatusUnsupportedMediaType, "mime_mismatch", "File type not supported or mismatched")
				return
			}
			http.Error(w, "File type not supported or mismatched", http.StatusUnsupportedMediaType)
			return
		}
		// fallback: use the ext's expected MIME
		mimeType = validExtMap[ext]
	}

	formats, err := allowedTargetFormats(mimeType)
	if err != nil {
		log.Printf("unsupported MIME: %s", mimeType)
		if wantsJSON(r) {
			writeJSONErr(w, http.StatusUnsupportedMediaType, "unsupported_mime", "This file type is not supported for conversion")
			return
		}
		http.Error(w, "This file type is not supported for conversion", http.StatusUnsupportedMediaType)
		return
	}

	filename := generateSafeFilename(safeBase, ext)
	inputPath := filepath.Join(uploadsDir, filename)

	if err := saveFileToDisk(file, inputPath); err != nil {
		log.Printf("save error: %v", err)
		if wantsJSON(r) {
			writeJSONErr(w, http.StatusInternalServerError, "save_failed", "Could not save your file. Try again later.")
			return
		}
		http.Error(w, "Could not save your file. Try again later.", http.StatusInternalServerError)
		return
	}

	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(uploadJSON{
			Filename: filename,
			Original: header.Filename,
			Formats:  toUpperList(formats),
		})
		return
	}

	if err := tmplSelect.Execute(w, map[string]any{
		"Filename":     filename,
		"OriginalName": header.Filename,
		"Formats":      toUpperList(formats),
	}); err != nil {
		log.Printf("select template error: %v", err)
		http.Error(w, "Internal error rendering format selection", http.StatusInternalServerError)
	}
}

// POST /convert
func convertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	filename := sanitizePath(r.FormValue("filename"))
	original := sanitizePath(r.FormValue("original"))
	targetFormat := strings.ToLower(sanitizePath(r.FormValue("format")))

	if filename == "" || original == "" || targetFormat == "" {
		if wantsJSON(r) {
			writeJSONErr(w, http.StatusBadRequest, "missing_data", "Missing filename/original/format")
			return
		}
		http.Error(w, "Missing data", http.StatusBadRequest)
		return
	}

	ext := strings.ToLower(filepath.Ext(filename))
	mime, ok := validExtMap[ext]
	if !ok {
		if wantsJSON(r) {
			writeJSONErr(w, http.StatusBadRequest, "unknown_extension", "Unknown file extension")
			return
		}
		http.Error(w, "Unknown file extension", http.StatusBadRequest)
		return
	}

	allowedFormats, ok := conversionMap[mime]
	if !ok || !contains(allowedFormats, targetFormat) {
		if wantsJSON(r) {
			writeJSONErr(w, http.StatusBadRequest, "unsupported_target", "Unsupported target format for this file type")
			return
		}
		http.Error(w, "Unsupported target format for this file type", http.StatusBadRequest)
		return
	}

	inputPath := filepath.Join(uploadsDir, filename)
	base := strings.TrimSuffix(filename, filepath.Ext(filename))
	safeOutBase := sanitizeFilename(base)
	outputFilename := fmt.Sprintf("%s.%s", safeOutBase, targetFormat)
	outputPath := filepath.Join(convertedDir, outputFilename)

	// Validate paths live under expected roots
	if !filepathHasPrefix(inputPath, uploadsDir) || !filepathHasPrefix(outputPath, convertedDir) {
		if wantsJSON(r) {
			writeJSONErr(w, http.StatusBadRequest, "invalid_path", "Invalid file path")
			return
		}
		http.Error(w, "Invalid file path", http.StatusBadRequest)
		return
	}

	// Concurrency gate
	select {
	case convSem <- struct{}{}:
		defer func() { <-convSem }()
	default:
		if wantsJSON(r) {
			writeJSONErr(w, http.StatusTooManyRequests, "busy", "Too many concurrent conversions. Please try again.")
			return
		}
		http.Error(w, "Too many concurrent conversions. Please try again.", http.StatusTooManyRequests)
		return
	}

	// Conversion
	ctx, cancel := context.WithTimeout(context.Background(), conversionTimeout)
	defer cancel()

	if err := runConversion(ctx, mime, targetFormat, inputPath, outputPath, safeOutBase); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			if wantsJSON(r) {
				writeJSONErr(w, http.StatusRequestTimeout, "timeout", "Conversion timed out")
				return
			}
			http.Error(w, "Conversion timed out", http.StatusRequestTimeout)
			return
		}
		log.Printf("conversion error: %v", err)
		if wantsJSON(r) {
			writeJSONErr(w, http.StatusInternalServerError, "conversion_failed", "Conversion failed. Please try again later.")
			return
		}
		http.Error(w, "Conversion failed. Please try again later.", http.StatusInternalServerError)
		return
	}

	cleanBase := strings.TrimSuffix(original, filepath.Ext(original))
	downloadName := fmt.Sprintf("%s.%s", cleanBase, targetFormat)

	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(convertJSON{
			Download:     "/download?file=" + outputFilename + "&name=" + downloadName,
			DownloadName: downloadName,
		})
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<p>Conversion complete!</p>
<p>Original file: %s</p>
<a href="/download?file=%s&name=%s">Download</a>`,
		original, outputFilename, downloadName)
}

// GET /download?file=...&name=...
func downloadHandler(w http.ResponseWriter, r *http.Request) {
	file := filepath.Base(r.URL.Query().Get("file"))
	name := r.URL.Query().Get("name")

	if file == "" || name == "" {
		http.Error(w, "Missing file or name", http.StatusBadRequest)
		return
	}

	filePath := filepath.Join(convertedDir, file)
	if !filepathHasPrefix(filePath, convertedDir) {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// Prevent symlink traversal
	fi, err := os.Lstat(filePath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Caching for downloads
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d, immutable", downloadCacheMaxAge))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))

	// Support HEAD
	if r.Method == http.MethodHead {
		if _, err := os.Stat(filePath); err != nil {
			http.NotFound(w, r)
			return
		}
		return
	}

	http.ServeFile(w, r, filePath)
}

//
// ============================== Conversion Core =========================
//

// runConversion selects the right tool/flags for the requested conversion.
func runConversion(ctx context.Context, srcMIME, target, inputPath, outputPath, outBase string) error {
	// Special-case PDFs (use poppler utils when available)
	if srcMIME == "application/pdf" {
		switch target {
		case "png", "jpg":
			// pdftoppm -<fmt> -singlefile input.pdf outputBase
			outBaseNoExt := strings.TrimSuffix(outputPath, "."+target)
			cmd := exec.CommandContext(ctx, "pdftoppm", "-"+target, "-singlefile", inputPath, outBaseNoExt)
			return runCmdLogged(cmd)
		case "txt":
			cmd := exec.CommandContext(ctx, "pdftotext", "-layout", inputPath, outputPath)
			return runCmdLogged(cmd)
		default:
			return fmt.Errorf("unsupported PDF target: %s", target)
		}
	}

	// Images, Video, Audio (ffmpeg)
	switch {
	case strings.HasPrefix(srcMIME, "image/"):
		return convertImage(ctx, target, inputPath, outputPath, outBase)

	case strings.HasPrefix(srcMIME, "video/") || srcMIME == "image/gif":
		return convertVideo(ctx, target, inputPath, outputPath, outBase)

	case strings.HasPrefix(srcMIME, "audio/"):
		return convertAudio(ctx, target, inputPath, outputPath)

	default:
		return fmt.Errorf("unsupported source MIME: %s", srcMIME)
	}
}

func convertImage(ctx context.Context, target, inputPath, outputPath, outBase string) error {
	if target == "gif" {
		// palette trick for quality: two-step without using bash
		palette := filepath.Join(os.TempDir(), "pal_"+outBase+"_"+randHex(4)+".png")
		gen := exec.CommandContext(ctx, "ffmpeg", "-y", "-i", inputPath, "-vf", "fps=12,scale=iw:-1:flags=lanczos,palettegen", palette)
		if err := runCmdLogged(gen); err != nil {
			return err
		}
		use := exec.CommandContext(ctx, "ffmpeg", "-y", "-i", inputPath, "-i", palette, "-lavfi", "paletteuse", outputPath)
		return runCmdLogged(use)
	}
	// default image re-encode
	cmd := exec.CommandContext(ctx, "ffmpeg", "-y", "-i", inputPath, outputPath)
	return runCmdLogged(cmd)
}

func convertVideo(ctx context.Context, target, inputPath, outputPath, outBase string) error {
	switch target {
	case "mp4":
		cmd := exec.CommandContext(ctx, "ffmpeg", "-y", "-i", inputPath,
			"-c:v", "libx264", "-preset", "veryfast", "-crf", "23",
			"-movflags", "+faststart",
			"-c:a", "aac", "-b:a", "160k",
			outputPath)
		return runCmdLogged(cmd)
	case "webm":
		cmd := exec.CommandContext(ctx, "ffmpeg", "-y", "-i", inputPath,
			"-c:v", "libvpx-vp9", "-b:v", "0", "-crf", "33",
			"-c:a", "libopus",
			outputPath)
		return runCmdLogged(cmd)
	case "gif":
		// video → gif via palette trick (two-step)
		palette := filepath.Join(os.TempDir(), "pal_"+outBase+"_"+randHex(4)+".png")
		gen := exec.CommandContext(ctx, "ffmpeg", "-y", "-i", inputPath, "-vf", "fps=12,scale=iw:-1:flags=lanczos,palettegen", palette)
		if err := runCmdLogged(gen); err != nil {
			return err
		}
		use := exec.CommandContext(ctx, "ffmpeg", "-y", "-i", inputPath, "-i", palette, "-lavfi", "paletteuse", outputPath)
		return runCmdLogged(use)
	case "mp3":
		cmd := exec.CommandContext(ctx, "ffmpeg", "-y", "-i", inputPath, "-vn", "-c:a", "libmp3lame", "-b:a", "192k", outputPath)
		return runCmdLogged(cmd)
	default:
		cmd := exec.CommandContext(ctx, "ffmpeg", "-y", "-i", inputPath, outputPath)
		return runCmdLogged(cmd)
	}
}

func convertAudio(ctx context.Context, target, inputPath, outputPath string) error {
	switch target {
	case "mp3":
		cmd := exec.CommandContext(ctx, "ffmpeg", "-y", "-i", inputPath, "-c:a", "libmp3lame", "-b:a", "192k", outputPath)
		return runCmdLogged(cmd)
	case "wav":
		cmd := exec.CommandContext(ctx, "ffmpeg", "-y", "-i", inputPath, "-c:a", "pcm_s16le", outputPath)
		return runCmdLogged(cmd)
	case "ogg":
		cmd := exec.CommandContext(ctx, "ffmpeg", "-y", "-i", inputPath, "-c:a", "libvorbis", "-q:a", "5", outputPath)
		return runCmdLogged(cmd)
	case "flac":
		cmd := exec.CommandContext(ctx, "ffmpeg", "-y", "-i", inputPath, "-c:a", "flac", outputPath)
		return runCmdLogged(cmd)
	case "aac":
		cmd := exec.CommandContext(ctx, "ffmpeg", "-y", "-i", inputPath, "-c:a", "aac", "-b:a", "160k", outputPath)
		return runCmdLogged(cmd)
	default:
		cmd := exec.CommandContext(ctx, "ffmpeg", "-y", "-i", inputPath, outputPath)
		return runCmdLogged(cmd)
	}
}

func runCmdLogged(cmd *exec.Cmd) error {
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("exec failed: %w; output=%s", err, string(out))
	}
	return nil
}

//
// ============================== Utilities ===============================
//

func wantsJSON(r *http.Request) bool {
	for _, v := range r.Header.Values("Accept") {
		if strings.Contains(v, "application/json") {
			return true
		}
	}
	return false
}

// 🔐 Sanitize filenames to avoid path traversal & normalize chars
func sanitizeFilename(name string) string {
	name = filepath.Base(name)
	name = strings.ToLower(name)
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= '0' && r <= '9':
			return r
		}
		switch r {
		case '.', '_', '-':
			return r
		default:
			return '_'
		}
	}, name)
}

// Further path sanitization
func sanitizePath(name string) string {
	return strings.ReplaceAll(filepath.Base(name), "..", "_")
}

func detectMimeType(file multipart.File) (string, error) {
	buf := make([]byte, 512)
	n, err := file.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	_, _ = file.Seek(0, io.SeekStart)
	return http.DetectContentType(buf[:n]), nil
}

func validateMimeAndExt(ext, detected string) error {
	expected, ok := validExtMap[ext]
	if !ok {
		return fmt.Errorf("unsupported extension: %s", ext)
	}
	if expected != detected {
		return fmt.Errorf("mime mismatch: expected %s, got %s", expected, detected)
	}
	return nil
}

func allowedTargetFormats(mime string) ([]string, error) {
	formats, ok := conversionMap[mime]
	if !ok {
		return nil, fmt.Errorf("no conversion formats for MIME type: %s", mime)
	}
	return formats, nil
}

func generateSafeFilename(base, ext string) string {
	// time + random suffix to avoid collisions
	ts := time.Now().UnixNano()
	r := randHex(6)
	return fmt.Sprintf("%d_%s_%s%s", ts, r, base, ext)
}

func saveFileToDisk(file multipart.File, dstPath string) error {
	// Ensure dir exists
	if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
		return err
	}
	out, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, file)
	return err
}

func contains(list []string, item string) bool {
	for _, v := range list {
		if v == item {
			return true
		}
	}
	return false
}

func filepathHasPrefix(path, prefix string) bool {
	absPath, err1 := filepath.Abs(path)
	absPrefix, err2 := filepath.Abs(prefix)
	if err1 != nil || err2 != nil {
		return false
	}
	absPath = filepath.Clean(absPath)
	absPrefix = filepath.Clean(absPrefix)
	return strings.HasPrefix(absPath+string(os.PathSeparator), absPrefix+string(os.PathSeparator)) || absPath == absPrefix
}

func toUpperList(list []string) []string {
	upper := make([]string, len(list))
	for i, v := range list {
		upper[i] = strings.ToUpper(v)
	}
	return upper
}
