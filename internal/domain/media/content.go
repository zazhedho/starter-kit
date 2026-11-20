package media

import (
	"path"
	"slices"
	"strings"
	"unicode"
)

// contentTypeExtensions is every content type the module can store, with the
// extension its objects get. HTML and SVG are left out: served from a public
// bucket they would run script.
var contentTypeExtensions = map[string]string{
	"application/pdf": ".pdf",
	"image/gif":       ".gif",
	"image/jpeg":      ".jpg",
	"image/png":       ".png",
	"image/webp":      ".webp",
}

// SupportedContentTypes lists the storable content types, sorted.
func SupportedContentTypes() []string {
	types := make([]string, 0, len(contentTypeExtensions))
	for contentType := range contentTypeExtensions {
		types = append(types, contentType)
	}
	slices.Sort(types)
	return types
}

func ExtensionFor(contentType string) string {
	return contentTypeExtensions[NormalizeContentType(contentType)]
}

// NormalizeContentType lower-cases a media type and drops its parameters.
func NormalizeContentType(contentType string) string {
	contentType, _, _ = strings.Cut(strings.ToLower(strings.TrimSpace(contentType)), ";")
	return strings.TrimSpace(contentType)
}

// MaxOriginalNameChars caps the stored original_name.
const MaxOriginalNameChars = 255

// SafeFilename reduces a client-supplied name to its base name without control
// or format characters (bidi overrides, zero-width), or invalid UTF-8, capped at
// 255 characters, or "file" when nothing usable is left.
func SafeFilename(filename string) string {
	name := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(filename, ""))
	name = strings.TrimSpace(path.Base(strings.ReplaceAll(strings.TrimSpace(name), "\\", "/")))
	if runes := []rune(name); len(runes) > MaxOriginalNameChars {
		name = string(runes[:MaxOriginalNameChars])
	}
	if name == "" || name == "." || name == ".." || name == "/" {
		return "file"
	}
	return name
}
