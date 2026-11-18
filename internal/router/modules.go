package router

import (
	routerlocation "starter-kit/internal/router/location"
	routermedia "starter-kit/internal/router/media"
	"starter-kit/internal/router/module"
)

// modules is every module mounted under /api, after authkit's routes, in
// alphabetical order. Adding a module is one line here; its own
// router/<module>/routes_test.go pins its routes.
var modules = []module.Entry{
	{Name: "location", Register: routerlocation.Register},
	{Name: "media", Register: routermedia.Register},
}
