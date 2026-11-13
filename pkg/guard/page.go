package guard

import (
	"html/template"
	"net/http"
)

type pageCopy struct{ Lang, Title, Button, Wrong, OtherApp string }

var pageCopies = [2]pageCopy{ // English, French
	{"en", "Access code", "Open", "Wrong code", "This code does not open this app"},
	{"fr", "Code d'accès", "Ouvrir", "Code incorrect", "Ce code n'ouvre pas cette app"},
}

const (
	msgNone = iota
	msgWrong
	msgOtherApp
)

var page = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="{{.C.Lang}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{{.App}} · {{.C.Title}}</title>
<style>
:root{color-scheme:light dark}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;background:#f4f5f7;color:#1f2328}
main{box-sizing:border-box;width:min(22rem,calc(100% - 2rem));padding:2rem;border-radius:12px;background:#fff;box-shadow:0 2px 12px rgba(0,0,0,.08)}
h1{margin:0 0 1rem;font-size:1.25rem;overflow-wrap:anywhere}
label{display:block;margin-bottom:.25rem;font-weight:600}
input{box-sizing:border-box;width:100%;padding:.6rem;border:1px solid #d0d7de;border-radius:8px;font:1.1rem ui-monospace,monospace;letter-spacing:.08em;text-transform:uppercase}
button{width:100%;margin-top:1rem;padding:.6rem;border:0;border-radius:8px;background:#0969da;color:#fff;font:inherit;font-weight:600;cursor:pointer}
.err{margin:0 0 .5rem;color:#cf222e;font-weight:600}
@media (prefers-color-scheme:dark){body{background:#0d1117;color:#e6edf3}main{background:#161b22}input{background:#0d1117;color:inherit;border-color:#30363d}.err{color:#ff7b72}}
</style>
</head>
<body>
<main>
<h1>{{.App}}</h1>
<form method="post" action="/.recasaos/acces">
<label for="code">{{.C.Title}}</label>
{{if .Error}}<p class="err" id="err" role="alert">{{.Error}}</p>{{end}}
<input id="code" name="code" required autofocus autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="XXXX-XXXX-XXXX"{{if .Error}} aria-describedby="err"{{end}}>
<input type="hidden" name="next" value="{{.Next}}">
<button type="submit">{{.C.Button}}</button>
</form>
</main>
</body>
</html>
`))

// showPage writes the entry page for app with status, in the visitor's language.
func showPage(w http.ResponseWriter, r *http.Request, app AppConfig, next string, msg, status int) {
	c := pageCopies[lang(r)]
	data := struct {
		C                pageCopy
		App, Next, Error string
	}{C: c, App: app.App, Next: next, Error: [...]string{"", c.Wrong, c.OtherApp}[msg]}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	w.WriteHeader(status)
	_ = page.Execute(w, data)
}
