package media

import (
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"path"
	"strings"
	"unicode"

	domainmedia "starter-kit/internal/domain/media"
)

var defaultContentTypes = []string{
	"application/pdf",
	"image/gif",
	"image/jpeg",
	"image/png",
	"image/webp",
}

func detectContentType(file multipart.File) (string, error) {
	buffer := make([]byte, 512)
	n, err := io.ReadFull(file, buffer)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return "", err
	}
	if n == 0 {
		return "", domainmedia.ErrEmptyFile
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}

	return normalizeContentType(http.DetectContentType(buffer[:n])), nil
}

func normalizeContentType(contentType string) string {
	contentType, _, _ = strings.Cut(strings.ToLower(strings.TrimSpace(contentType)), ";")
	return strings.TrimSpace(contentType)
}

func extensionForContentType(contentType string) string {
	switch contentType {
	case "application/pdf":
		return ".pdf"
	case "image/gif":
		return ".gif"
	case "image/jpeg":
		return ".jpg"
	case "image/png":
		return ".png"
	case "image/webp":
		return ".webp"
	default:
		return ""
	}
}

// maxOriginalNameChars caps the stored original_name.
const maxOriginalNameChars = 255

// safeFilename reduces a client-supplied name to its base name without control
// characters or invalid UTF-8, capped at 255 characters, or "file" when nothing
// usable is left.
func safeFilename(filename string) string {
	name := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(filename, ""))
	name = strings.TrimSpace(path.Base(strings.ReplaceAll(strings.TrimSpace(name), "\\", "/")))
	if runes := []rune(name); len(runes) > maxOriginalNameChars {
		name = string(runes[:maxOriginalNameChars])
	}
	if name == "" || name == "." || name == ".." || name == "/" {
		return "file"
	}
	return name
}
