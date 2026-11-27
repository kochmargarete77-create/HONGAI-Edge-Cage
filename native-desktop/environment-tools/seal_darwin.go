//go:build darwin

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os/exec"
	"strings"
)

func keychainAccount(root string) string {
	s := sha256.Sum256([]byte(root))
	return hex.EncodeToString(s[:16])
}
func keychainKey(root string, create bool) ([]byte, error) {
	account := keychainAccount(root)
	c := exec.Command("/usr/bin/security", "find-generic-password", "-a", account, "-s", "com.hongai.environment.mcp-privacy", "-w")
	if out, e := c.Output(); e == nil {
		key, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
		if e == nil && len(key) == 32 {
			return key, nil
		}
		return nil, errors.New("KEYCHAIN_KEY_INVALID")
	}
	if !create {
		return nil, errors.New("KEYCHAIN_KEY_UNAVAILABLE")
	}
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		return nil, e
	}
	// Secret passes through a private stdin pipe, not the process argument list.
	command := "add-generic-password -a " + account + " -s com.hongai.environment.mcp-privacy -w " + base64.StdEncoding.EncodeToString(key) + "\n"
	c = exec.Command("/usr/bin/security", "-i")
	c.Stdin = strings.NewReader(command)
	if e := c.Run(); e != nil {
		return nil, errors.New("KEYCHAIN_CREATE_FAILED")
	}
	stored, e := keychainKey(root, false)
	if e != nil || string(stored) != string(key) {
		return nil, errors.New("KEYCHAIN_CONFIRM_FAILED")
	}
	return key, nil
}
func platformSeal(data []byte, root string) ([]byte, error) {
	key, e := keychainKey(root, true)
	if e != nil {
		return nil, e
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, g.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	return g.Seal(nonce, nonce, data, []byte("HONGAI-MCP-V1|"+root)), nil
}
func platformOpen(data []byte, root string) ([]byte, error) {
	key, e := keychainKey(root, false)
	if e != nil {
		return nil, e
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	if len(data) < g.NonceSize() {
		return nil, errors.New("SEALED_PAYLOAD_TRUNCATED")
	}
	out, e := g.Open(nil, data[:g.NonceSize()], data[g.NonceSize():], []byte("HONGAI-MCP-V1|"+root))
	if e != nil {
		return nil, errors.New("SEALED_PAYLOAD_REJECTED")
	}
	return out, nil
}
