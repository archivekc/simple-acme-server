package directory

import (
	"acme"
	"encoding/json"
	"model"
	"net/http"
)

type directoryResponse struct {
	NewReg     string `json:"new-reg"`
	RecoverReg string `json:"recover-reg"`
	NewAuthz   string `json:"new-authz"`
	NewCert    string `json:"new-cert"`
	RevokeCert string `json:"revoke-cert"`
}

// HandleDirectory deals with ACME directory request
func HandleDirectory(server *model.AcmeServer, w http.ResponseWriter, r *http.Request) {
	acme.DebugRequest(r)
	dirRes := directoryResponse{
		NewReg:     "https://" + server.Hostname + ":" + server.Port + "/new-reg",
		RecoverReg: "https://" + server.Hostname + ":" + server.Port + "/recover-reg",
		NewAuthz:   "https://" + server.Hostname + ":" + server.Port + "/new-authz",
		NewCert:    "https://" + server.Hostname + ":" + server.Port + "/new-cert",
		RevokeCert: "https://" + server.Hostname + ":" + server.Port + "/revoke-cert",
	}
	client := server.Clients[acme.GetIP(r)]
	if client == nil {
		client = new(model.RegisterClient)
		server.Clients[acme.GetIP(r)] = client
		client.Authorizations = []*model.Authorization{}
	}
	acme.DefaultHeaderWithNonce(client, w)
	json.NewEncoder(w).Encode(dirRes)
}
