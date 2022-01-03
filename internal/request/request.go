package request

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/corbaltcode/go-akamai"
	"github.com/corbaltcode/go-akamai/edgegrid"
)

const scheme = "https"

func Do(c akamai.Credentials, method string, path string, in []byte, out *[]byte) error {
	req, err := http.NewRequest(method, fmt.Sprintf("%s://%s%s", scheme, c.Host, path), bytes.NewReader(in))
	if err != nil {
		return err
	}
	req.Header.Add("Accept", "application/json")

	authHeader, err := edgegrid.GenerateAuthHeader(c, method, scheme, path, in)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", authHeader)

	if len(in) > 0 {
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Content-Length", fmt.Sprintf("%d", len(in)))
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	*out, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New(string(*out))
	}

	return nil
}

func DoJSON(c akamai.Credentials, method string, path string, in interface{}, out interface{}) error {
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
