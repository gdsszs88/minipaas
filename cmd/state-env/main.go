package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
)

func encrypt(aead cipher.AEAD, plaintext string) (string, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil { return "", err }
	return base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte(plaintext), nil)), nil
}

func main() {
	if len(os.Args) != 5 { panic("usage: state-env STATE MASTER_KEY APP_ID ENV_FILE") }
	key, err := os.ReadFile(os.Args[2]); if err != nil { panic(err) }
	block, err := aes.NewCipher(key); if err != nil { panic(err) }
	aead, err := cipher.NewGCM(block); if err != nil { panic(err) }
	f, err := os.Open(os.Args[4]); if err != nil { panic(err) }; defer f.Close()
	variables := []any{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") { continue }
		keyName, value, ok := strings.Cut(line, "=")
		keyName, value = strings.TrimSpace(keyName), strings.TrimSpace(value)
		if !ok || !strings.HasPrefix(keyName, "VITE_") { continue }
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) { value = value[1:len(value)-1] }
		ciphertext, encErr := encrypt(aead, value); if encErr != nil { panic(encErr) }
		variables = append(variables, map[string]any{"key": keyName, "encryptedValue": ciphertext, "secret": true})
	}
	if err := scanner.Err(); err != nil { panic(err) }
	if len(variables) == 0 { panic("no VITE_ variables found") }
	b, err := os.ReadFile(os.Args[1]); if err != nil { panic(err) }
	var state map[string]any
	if err := json.Unmarshal(b, &state); err != nil { panic(err) }
	apps, ok := state["apps"].([]any); if !ok { panic(errors.New("apps missing")) }
	found := false
	for _, raw := range apps {
		app, ok := raw.(map[string]any); if !ok || app["id"] != os.Args[3] { continue }
		app["variables"], app["autoDeploy"], app["gitCommit"], app["status"] = variables, true, "", "draft"
		found = true
	}
	if !found { panic("app not found") }
	out, err := json.MarshalIndent(state, "", "  "); if err != nil { panic(err) }
	tmp := os.Args[1]+".tmp"
	if err := os.WriteFile(tmp, out, 0600); err != nil { panic(err) }
	if err := os.Rename(tmp, os.Args[1]); err != nil { panic(err) }
}
