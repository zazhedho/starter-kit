package media

// Actor is who performs a media operation, reduced to what the rules need, so
// services never import the auth framework.
type Actor struct {
	UserID       string
	IsSuperAdmin bool
}
