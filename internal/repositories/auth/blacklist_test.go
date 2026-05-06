package repositoryauth

import (
	"context"
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
	ctx := context.Background()
	expectPanic(t, func() { _ = repo.Store(ctx, domainauth.Blacklist{Token: "token"}) })
	expectPanic(t, func() { _, _ = repo.GetByToken(ctx, "token") })
	expectPanic(t, func() { _, _ = repo.ExistsByToken(ctx, "token") })
}
