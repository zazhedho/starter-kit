package media

// Actor is who performs a media operation, reduced to what the rules need.
// Handlers build it from the authenticated request, so services never import
// the auth framework.
type Actor struct {
	UserID       string
	IsSuperAdmin bool
}
