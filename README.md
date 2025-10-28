

# Transformers
<p align="center"><img src="./logo.png" alt="Transformers" width="120" /></p>

![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go)
![FFmpeg](https://img.shields.io/badge/FFmpeg-required-007808)
![Poppler](https://img.shields.io/badge/Poppler-pdftoppm%2Fpdftotext-informational)
![License](https://img.shields.io/badge/License-MIT-green)

 
Upload a file → pick a target format → download the converted output. Works via **web UI** or **JSON API**.

---

## Features

- Image, video, audio, and PDF conversions (via **ffmpeg** & **poppler**).
- Safe uploads with size cap (**50 MB**) and MIME sniffing.
- Extension ↔ MIME validation, path sanitization, and strict static serving.
- Concurrency gate (**3 concurrent jobs**) + **150s** conversion timeout.
- Security headers, request ID (`X-Request-ID`), and graceful shutdown.
- JSON or HTML responses (auto‑select via `Accept` header).

---

## Requirements

Install the external tools first:

- **ffmpeg** (images / audio / video)
- **poppler** (for PDF → image/text via `pdftoppm` / `pdftotext`)

**macOS (Homebrew):**
```bash
brew install ffmpeg poppler
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt-get update && sudo apt-get install -y ffmpeg poppler-utils
```

---

## Run locally

```bash
go run .
# Server will start at http://localhost:3030
```

Static assets:
- UI: `templates/index.html`, `templates/select_format.html`
- Uploaded files: `uploads/`
- Converted files: `converted/` (also served at `/converted/…`)

---

## Supported conversions

**Images**
- jpeg ↔ png ↔ webp ↔ bmp ↔ gif  
- tiff → jpg/png  
- gif → mp4/webm (animated GIF → video)

**Video**
- mp4 ↔ webm, mp4/webm → gif, any → mp3

**Audio**
- mp3 ↔ wav ↔ ogg ↔ flac; aac/m4a ↔ mp3/wav

**Documents**
- pdf → png/jpg/txt

---

## Web UI

Open http://localhost:3030  
1) Upload a file  
2) Choose a target format (only valid options shown)  
3) Download the converted file

---

## JSON API

The server auto‑detects `Accept: application/json` and returns JSON.

### 1) Upload

**POST** `/upload` (multipart/form-data)

- Field: `file` — the file to upload

```bash
curl -H "Accept: application/json" \
  -F file=@example.mp4 \
  http://localhost:3030/upload
```

**Response**
```json
{
  "filename": "1730112345678_ab12cd_example.mp4",
  "original": "example.mp4",
  "formats": ["WEBM","AVI","MOV","GIF","MP3"]
}
```

### 2) Convert

**POST** `/convert` (application/x-www-form-urlencoded or JSON)

- Params:  
  - `filename` — server‑side stored name from `/upload`  
  - `original` — original filename (used to suggest download name)  
  - `format` — target extension (e.g., `webm`, `mp3`, `png`)

```bash
curl -H "Accept: application/json" \
  -X POST http://localhost:3030/convert \
  -d "filename=1730112345678_ab12cd_example.mp4" \
  -d "original=example.mp4" \
  -d "format=webm"
```

**Response**
```json
{
  "download": "/download?file=1730112345678_ab12cd_example.webm&name=example.webm",
  "downloadName": "example.webm"
}
```

### 3) Download

**GET** `/download?file=<stored>&name=<suggested>`

Supports `HEAD`. Sets immutable caching & `Content-Disposition` for attachment.

---

## Safety & limits

- **Upload limit:** 50 MB (`maxUploadSize`)
- **Conversion timeout:** 150 s (`conversionTimeout`)
- **Concurrency:** 3 parallel conversions (`maxConcurrentConversions`)
- **Security headers:** CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
- **Request ID:** every response includes `X-Request-ID`

> Adjust these in the `const` block in `main.go` if needed.

---

## Project structure

```
.
├─ templates/
│  ├─ index.html
│  └─ select_format.html
├─ static/                # optional CSS/JS
├─ uploads/               # runtime (gitignored)
├─ converted/             # runtime (gitignored)
└─ main.go
```

