package edgegrid

import (
	"context"
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
func generateAuthHeaderPrefix(ctx context.Context, c akamai.Credentials, timestamp string, nonce string) (string, error) {
	if nonce == "" {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		nonce = fmt.Sprintf("%x", b)
	}

	header := fmt.Sprintf("EG1-HMAC-SHA256 client_token=%s;access_token=%s;timestamp=%s;nonce=%s;",
		c.ClientToken, c.AccessToken, timestamp, nonce)

	if akamai.DebugEnabled(ctx) {
		log.Printf("generated Akamai EdgeGrid Authorization header prefix: %s", header)
	}

	return header, nil
}

// Returns the full value that should be set for the "Authorization" header for a request under Akamai's
// "EdgeGrid" authentication scheme, including the signature.
func generateAuthHeader(ctx context.Context, c akamai.Credentials, method, scheme, path string, body []byte, nonce, timestamp string) (string, error) {
	method = strings.ToUpper(method)
	if path == "" || path[0] != '/' {
		path = "/" + path
	}
	if timestamp == "" {
		timestamp = time.Now().UTC().Format(timeFormat)
	}
	prefix, err := generateAuthHeaderPrefix(ctx, c, timestamp, nonce)
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

	mac := hmac.New(sha256.New, []byte(c.ClientSecret))
	mac.Write([]byte(timestamp))
	signingKey := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	mac = hmac.New(sha256.New, []byte(signingKey))
	mac.Write([]byte(toSign))

	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	header := fmt.Sprintf("%ssignature=%s", prefix, sig)

	if akamai.DebugEnabled(ctx) {
		log.Printf("generated Akamai EdgeGrid Authorization header: %ssignature=<redacted>", prefix)
	}

	return header, nil
}

// GenerateAuthHeader returns the value that should be set for the "Authorization" header for a request under Akamai's
// "EdgeGrid" authentication scheme.
//
// This is a compatibility wrapper around GenerateAuthHeaderWithContext that uses context.Background() as the context.
func GenerateAuthHeader(c akamai.Credentials, method, scheme, path string, body []byte) (string, error) {
	return GenerateAuthHeaderWithContext(context.Background(), c, method, scheme, path, body)
}

// GenerateAuthHeaderWithContext returns the value that should be set for the "Authorization" header for a
// request under Akamai's "EdgeGrid" authentication scheme.
func GenerateAuthHeaderWithContext(ctx context.Context, c akamai.Credentials, method, scheme, path string, body []byte) (string, error) {
	return generateAuthHeader(ctx, c, method, scheme, path, body, "", "")
}

// CheckRequest returns true if the AuthHeaderInfo is correct for the given request.
//
// This is a compatibility wrapper around CheckRequestWithContext that uses context.Background() as the context.
func CheckRequest(c akamai.Credentials, method, scheme, path string, body []byte, i *AuthHeaderInfo) bool {
	return CheckRequestWithContext(context.Background(), c, method, scheme, path, body, i)
}

// CheckRequestWithContext returns true if the AuthHeaderInfo is correct for the given request.
func CheckRequestWithContext(ctx context.Context, c akamai.Credentials, method, scheme, path string, body []byte, i *AuthHeaderInfo) bool {
	h, err := generateAuthHeader(ctx, c, method, scheme, path, body, i.Nonce, i.Timestamp)
	if err != nil {
		log.Printf("Unexpected error while checking request: %s", err)
	}
	return h == i.FullHeader
}
