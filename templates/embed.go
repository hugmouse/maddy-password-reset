package templates

import "embed"

//go:embed *.gohtml
var Templates embed.FS
