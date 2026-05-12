package request

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/corbaltcode/go-akamai"
	"github.com/corbaltcode/go-akamai/edgegrid"
)

const scheme = "https"

// Do performs an HTTP request to the Akamai API with the given method, path, and body, and stores the response body in
// out.
//
// This is a compatibility wrapper around DoWithContext that uses context.Background() as the context.
func Do(c akamai.Credentials, method string, path string, in []byte, out *[]byte) error {
	return DoWithContext(context.Background(), c, method, path, in, out)
}

// DoWithContext performs an HTTP request to the Akamai API with the given method, path, and body, and stores the
// response body in out.
//
// The context is used to determine whether debugging is enabled and to allow cancellation of the request.
func DoWithContext(ctx context.Context, c akamai.Credentials, method string, path string, in []byte, out *[]byte) error {
	url := fmt.Sprintf("%s://%s%s", scheme, c.Host, path)
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(in))
	if err != nil {
		log.Printf("Error creating request: %v", err)
		return err
	}
	req.Header.Add("Accept", "application/json")

	authHeader, err := edgegrid.GenerateAuthHeader(c, method, scheme, path, in)
	if err != nil {
		log.Printf("Error generating auth header: %v", err)
		return err
	}
	req.Header.Add("Authorization", authHeader)

	if len(in) > 0 {
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Content-Length", fmt.Sprintf("%d", len(in)))
	}

	log.Printf("%s %s", method, url)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Request failed: %v", err)
		return err
	}

	defer resp.Body.Close()
	*out, err = io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body: %v", err)
		return err
	}

	if akamai.DebugEnabled(ctx) {
		log.Printf("Response status: %d", resp.StatusCode)
		log.Printf("Response body -------------------------\n%s\n-----------------------------", string(*out))
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New(string(*out))
	}

	return nil
}

// DoJSON performs an HTTP request to the Akamai API with the given method, path, and body, and unmarshals the JSON
// response body into out.
//
// This is a compatibility wrapper around DoJSONWithContext that uses context.Background() as the context.
func DoJSON(c akamai.Credentials, method string, path string, in interface{}, out interface{}) error {
	return DoJSONWithContext(context.Background(), c, method, path, in, out)
}

// DoJSONWithContext performs an HTTP request to the Akamai API with the given method, path, and body, and unmarshals
// the JSON response body into out.
//
// The context is used to determine whether debugging is enabled and to allow cancellation of the request.
func DoJSONWithContext(ctx context.Context, c akamai.Credentials, method string, path string, in interface{}, out interface{}) error {
	var bufIn []byte
	var bufOut []byte
	var err error

	if in != nil {
		bufIn, err = json.Marshal(in)
		if err != nil {
			return err
		}
	}

	err = Do(c, method, path, bufIn, &bufOut)
	if err != nil {
		return err
	}

	if out != nil && len(bufOut) > 0 {
		err = json.Unmarshal(bufOut, out)
		if err != nil {
			return err
		}
	}

	return nil
}
