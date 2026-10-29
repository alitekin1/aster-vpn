package ui

import (
	"embed"
	"strings"
)

//go:embed index.html style.css app.js
var files embed.FS

func HTML() string {
	h, _ := files.ReadFile("index.html")
	c, _ := files.ReadFile("style.css")
	j, _ := files.ReadFile("app.js")
	return strings.ReplaceAll(strings.ReplaceAll(string(h), "/*ASTER_CSS*/", string(c)), "/*ASTER_JS*/", string(j))
}
