package media

import (
	"errors"
	"io"
	"mime/multipart"
	"net/http"

	domainmedia "starter-kit/internal/domain/media"
)

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

	return domainmedia.NormalizeContentType(http.DetectContentType(buffer[:n])), nil
}
