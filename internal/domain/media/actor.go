package media

// Actor is who performs a media operation, reduced to what the rules need, so
// services never import the auth framework. The Can*Any flags carry the
// media:<action>_any permissions: acting on one's own files needs none.
type Actor struct {
	UserID       string
	CanListAny   bool
	CanDeleteAny bool
}
