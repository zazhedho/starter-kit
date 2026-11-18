package handlermedia

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/zazhedho/gokit"

	domainmedia "starter-kit/internal/domain/media"
)

func TestMediaErrorResponseMapsDomainErrors(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
		msg    string
	}{
		{"not found", domainmedia.ErrNotFound, http.StatusNotFound, "media not found"},
		{"wrapped not found", fmt.Errorf("lookup: %w", domainmedia.ErrNotFound), http.StatusNotFound, "media not found"},
		{"forbidden hides existence", domainmedia.ErrMediaForbidden, http.StatusNotFound, "media not found"},
		{"empty file", domainmedia.ErrEmptyFile, http.StatusBadRequest, domainmedia.ErrEmptyFile.Error()},
		{"too large", domainmedia.ErrFileTooLarge, http.StatusRequestEntityTooLarge, domainmedia.ErrFileTooLarge.Error()},
		{"unexpected", errors.New("database down"), http.StatusInternalServerError, gokit.MsgSomethingWrong},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status, msg := mediaErrorResponse(c.err)
			if status != c.status || msg != c.msg {
				t.Fatalf("got (%d, %q), want (%d, %q)", status, msg, c.status, c.msg)
			}
		})
	}
}
