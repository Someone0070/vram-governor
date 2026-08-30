// Package dashboard embeds the legacy static compatibility root. The
// separately built React Studio and Operator applications are embedded by
// web/ui and served from their dedicated routes.
package dashboard

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed index.html
var files embed.FS

// FS returns an http.FileSystem rooted at the dashboard's static assets.
func FS() http.FileSystem {
	sub, err := fs.Sub(files, ".")
	if err != nil {
		panic(err)
	}
	return http.FS(sub)
}
