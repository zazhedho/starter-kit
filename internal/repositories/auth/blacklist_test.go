package repositoryauth

import (
	domainauth "starter-kit/internal/domain/auth"
	"testing"
)

func expectPanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	fn()
}

func TestNewBlacklistRepoAndNilDBMethodPanics(t *testing.T) {
	repo := NewBlacklistRepo(nil)
	if repo == nil {
		t.Fatal("expected repo")
	}
	expectPanic(t, func() { _ = repo.Store(domainauth.Blacklist{Token: "token"}) })
	expectPanic(t, func() { _, _ = repo.GetByToken("token") })
	expectPanic(t, func() { _, _ = repo.ExistsByToken("token") })
}
