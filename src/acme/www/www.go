package www

import (
	"acme"
	"html/template"
	"model"
	"net/http"
)

type templateData struct {
	Domain    string
	ServerURL string
}

// ServeTemplate execute named template
func ServeTemplate(templateName string, acmes *model.AcmeServer, w http.ResponseWriter, r *http.Request) {
	acme.DebugRequest(r)

	tpl, err := template.ParseFiles(templateName)
	if err != nil {
		panic(err)
	}
	w.WriteHeader(http.StatusOK)
	err = tpl.Execute(w, templateData{
		Domain:    acmes.Hostname,
		ServerURL: "https://" + acmes.Hostname + ":" + acmes.Port,
	})
	if err != nil {
		panic(err)
	}
}
