package edgegrid

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/corbaltcode/go-akamai"
)

const timeFormat = "20060102T15:04:05-0700"

// The information found in the Authorization header under
// Akamai's "EdgeGrid" authentication scheme
type AuthHeaderInfo struct {
	ClientToken string
	AccessToken string
	Timestamp   string
	Nonce       string
	Signature   string
	FullHeader  string
}

func ParseHeader(header string) (*AuthHeaderInfo, error) {
	pieces := strings.SplitN(header, " ", 2)
	if len(pieces) != 2 || pieces[0] != "EG1-HMAC-SHA256" {
		return nil, errors.New("Invalid auth header format")
	}
	pieces = strings.SplitN(pieces[1], ";", 5)
	if len(pieces) != 5 {
		return nil, errors.New("Invalid auth header format")
	}
	parsed := make(map[string]string)
	for i, key := range []string{"client_token", "access_token", "timestamp", "nonce", "signature"} {
		split := strings.SplitN(pieces[i], "=", 2)
		if len(split) != 2 {
			return nil, errors.New("Invalid auth header format")
		}
		if split[0] != key {
			return nil, fmt.Errorf("Missing key %s", key)
		}
		parsed[key] = split[1]
	}
	return &AuthHeaderInfo{
		ClientToken: parsed["client_token"],
		AccessToken: parsed["access_token"],
		Timestamp:   parsed["timestamp"],
		Nonce:       parsed["nonce"],
		Signature:   parsed["signature"],
		FullHeader:  header,
	}, nil
}

// Returns the auth header up through the semicolon before "signature=".
func generateAuthHeaderPrefix(c akamai.Credentials, timestamp string, nonce string) (string, error) {
	if nonce == "" {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		nonce = fmt.Sprintf("%x", b)
	}
	return fmt.Sprintf("EG1-HMAC-SHA256 client_token=%s;access_token=%s;timestamp=%s;nonce=%s;",
		c.ClientToken, c.AccessToken, timestamp, nonce), nil
}

func generateAuthHeader(c akamai.Credentials, method, scheme, path string, body []byte, nonce, timestamp string) (string, error) {
	method = strings.ToUpper(method)
	if path == "" || path[0] != '/' {
		path = "/" + path
	}
	if timestamp == "" {
		timestamp = time.Now().UTC().Format(timeFormat)
	}
	prefix, err := generateAuthHeaderPrefix(c, timestamp, nonce)
	if err != nil {
		return "", err
	}
	contentDigest := ""
	if method == "POST" && len(body) > 0 {
		contentHash := sha256.Sum256(body)
		contentDigest = base64.StdEncoding.EncodeToString(contentHash[:])
	}
	headers := "" // no signed headers required for FastDNS
	toSign := strings.Join([]string{
		method,
		scheme,
		c.Host,
		path,
		headers,
		contentDigest,
		prefix,
	}, "\t")
	// log.Printf("To sign: %s", strings.Replace(toSign, "\t", "\\t", -1))

	mac := hmac.New(sha256.New, []byte(c.ClientSecret))
	mac.Write([]byte(timestamp))
	signingKey := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	mac = hmac.New(sha256.New, []byte(signingKey))
	mac.Write([]byte(toSign))

	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("%ssignature=%s", prefix, sig), nil
}

// Returns the value that should be set for the "Authorization" header for a request
// under Akamai's "EdgeGrid" authentication scheme
func GenerateAuthHeader(c akamai.Credentials, method, scheme, path string, body []byte) (string, error) {
	return generateAuthHeader(c, method, scheme, path, body, "", "")
}

// Returns true if the AuthHeaderInfo is correct for the given request
func CheckRequest(c akamai.Credentials, method, scheme, path string, body []byte, i *AuthHeaderInfo) bool {
	h, err := generateAuthHeader(c, method, scheme, path, body, i.Nonce, i.Timestamp)
	if err != nil {
		log.Printf("Unexpected error while checking request: %s", err)
	}
	return h == i.FullHeader
}
