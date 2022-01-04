package akamai

import (
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/ini.v1"
)

type Credentials struct {
	ClientSecret string
	AccessToken  string
	ClientToken  string
	Host         string
}

func LoadCredentialsFromEdgercFile(name string, section string) (Credentials, error) {
	f, err := os.Open(name)
	if err != nil {
		return Credentials{}, err
	}
	defer f.Close()
	return LoadCredentialsFromEdgerc(f, section)
}

func LoadCredentialsFromEdgerc(r io.Reader, section string) (Credentials, error) {
	f, err := ini.Load(r)
	if err != nil {
		return Credentials{}, err
	}

	if !f.HasSection(section) {
		return Credentials{}, fmt.Errorf("no section %q", section)
	}
	s := f.Section(section)

	clientToken := s.Key("client_token").String()
	if clientToken == "" {
		return Credentials{}, errors.New("missing client_token")
	}
	clientSecret := s.Key("client_secret").String()
	if clientSecret == "" {
		return Credentials{}, errors.New("missing client_secret")
	}
	accessToken := s.Key("access_token").String()
	if accessToken == "" {
		return Credentials{}, errors.New("missing access_token")
	}
	host := s.Key("host").String()
	if host == "" {
		return Credentials{}, errors.New("missing host")
	}

	return Credentials{
		ClientToken:  clientToken,
		ClientSecret: clientSecret,
		AccessToken:  accessToken,
		Host:         host,
	}, nil
}
