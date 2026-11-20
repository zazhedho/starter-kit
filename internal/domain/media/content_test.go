package media

import (
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSafeFilename(t *testing.T) {
	long := strings.Repeat("a", 300) + ".png"
	cases := []struct{ name, in, want string }{
		{"plain", "photo.png", "photo.png"},
		{"directories dropped", "../../etc/passwd", "passwd"},
		{"windows path", `C:\Users\me\photo.png`, "photo.png"},
		{"control characters removed", "ph\x00o\x1b[31mto\r\n.png", "pho[31mto.png"},
		{"tab and newline removed", "a\tb\nc.png", "abc.png"},
		{"bidi override removed", "invoice\u202Efdp.exe", "invoicefdp.exe"},
		{"zero-width removed", "pa\u200Bss\u200D.png\uFEFF", "pass.png"},
		{"only format characters", "\u202E\u200B", "file"},
		{"unicode kept", "foto-kucing-\u732b.png", "foto-kucing-\u732b.png"},
		{"capped at 255 characters", long, strings.Repeat("a", 255)},
		{"empty", "", "file"},
		{"blank", "   ", "file"},
		{"only controls", "\x00\x01", "file"},
		{"dot", ".", "file"},
		{"dot dot", "..", "file"},
		{"slash", "/", "file"},
		{"invalid utf-8 dropped", "a\xffb.png", "ab.png"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := SafeFilename(c.in)
			if got != c.want {
				t.Fatalf("SafeFilename(%q) = %q, want %q", c.in, got, c.want)
			}
			if utf8.RuneCountInString(got) > 255 {
				t.Fatalf("result has %d characters", utf8.RuneCountInString(got))
			}
		})
	}
}

func TestEverySupportedContentTypeHasAnExtension(t *testing.T) {
	supported := SupportedContentTypes()
	if !slices.IsSorted(supported) || len(supported) == 0 {
		t.Fatalf("SupportedContentTypes = %v, want a sorted, non-empty list", supported)
	}
	for _, contentType := range supported {
		if ExtensionFor(contentType) == "" {
			t.Errorf("%s is supported but has no extension", contentType)
		}
	}
	if ExtensionFor("Image/PNG; charset=binary") != ".png" || ExtensionFor("text/html") != "" {
		t.Error("ExtensionFor must normalize its argument and know nothing about unsupported types")
	}
}
