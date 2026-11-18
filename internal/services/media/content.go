package media

import (
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"path"
	"strings"

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

func safeFilename(filename string) string {
	return path.Base(strings.ReplaceAll(strings.TrimSpace(filename), "\\", "/"))
}
