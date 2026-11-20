package media

import (
	"errors"

	"github.com/zazhedho/gokit"

	httpmedia "starter-kit/internal/handlers/http/media"
	repositorymedia "starter-kit/internal/repositories/media"
	"starter-kit/internal/router/module"
	servicemedia "starter-kit/internal/services/media"
)

type wired struct {
	handler *httpmedia.Handler
}

func wire(d module.Deps) (*wired, error) {
	if d.Storage == nil {
		return nil, errors.New("storage is required when media is enabled")
	}
	m := d.Config.Media
	repo := repositorymedia.NewRepository(d.DB)
	svc := servicemedia.NewService(repo, d.Storage, servicemedia.Options{
		MaxFileSize:         m.MaxFileSizeBytes,
		AllowedContentTypes: m.AllowedContentTypes,
		NewID:               gokit.CreateUUID,
	})
	return &wired{handler: httpmedia.New(svc, d.Kit.Audit(), m.UploadTimeout, m.UploadMaxConcurrent, m.UploadMaxConcurrentPerUser)}, nil
}
