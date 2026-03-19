package banner

import (
	_ "embed"
	"strings"
)

//go:embed nice_detectbot.txt
var bannerText string

// Get returns the configured ASCII banner.
// It trims trailing newlines and ensures exactly one newline at the end.
func Get() string {
	return strings.TrimRight(bannerText, "\n") + "\n"
}
