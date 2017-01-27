package acme

import (
	"encoding/base64"
	"fmt"
	"html"
	"io/ioutil"
	"math/rand"
	"model"
	"net/http"
	"strings"
)

// DebugRequest output request Headers and then content
func DebugRequest(r *http.Request) []byte {
	fmt.Println("========== New Request ==========")
	fmt.Println("Request on path => ", html.EscapeString(r.URL.Path), r.Method)
	for k, v := range r.Header {
		fmt.Println(k, "=>", v)
	}
	fmt.Println("==========    Body     ==========")
	content, _ := ioutil.ReadAll(r.Body)
	fmt.Println(string(content))
	fmt.Println("========== End Request ==========")
	return content
}

// DefaultHeader add all common header suche as cross origin
func DefaultHeader(client *model.RegisterClient, w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
}

// DefaultHeaderWithNonce add all common header suche as cross origin and renew the nonce
func DefaultHeaderWithNonce(client *model.RegisterClient, w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	client.Nonce = CreateNonce(62)
	fmt.Println("Nonce created is", client.Nonce)
	w.Header().Set("Replay-Nonce", base64.StdEncoding.EncodeToString([]byte(client.Nonce)))
}

// GetIP return client ip
func GetIP(r *http.Request) string {
	s := strings.Split(r.RemoteAddr, ":")
	return s[0]
}

// GetLastPart Use to get last part of the uri
func GetLastPart(r *http.Request) string {
	s := strings.Split(r.URL.Path, "/")
	return s[len(s)-1]
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

// CreateNonce use it for creating Replay Nonce
func CreateNonce(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
