package router

import (
	routerlocation "starter-kit/internal/router/location"
	routermedia "starter-kit/internal/router/media"
	"starter-kit/internal/router/module"
)

var modules = []module.Entry{
	{Name: "location", Register: routerlocation.Register},
	{Name: "media", Register: routermedia.Register},
}
