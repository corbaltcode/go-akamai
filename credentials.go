package akamai

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
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
	return LoadCredentialsFromEdgercFileWithContext(context.Background(), name, section)
}

func LoadCredentialsFromEdgercFileWithContext(ctx context.Context, name string, section string) (Credentials, error) {
	f, err := os.Open(name)
	if err != nil {
		return Credentials{}, err
	}
	defer f.Close()
	return LoadCredentialsFromEdgercWithContext(ctx, f, section)
}

func LoadCredentialsFromEdgerc(r io.Reader, section string) (Credentials, error) {
	return LoadCredentialsFromEdgercWithContext(context.Background(), r, section)
}

func LoadCredentialsFromEdgercWithContext(ctx context.Context, r io.Reader, section string) (Credentials, error) {
	debug := DebugEnabled(ctx)
	f, err := ini.Load(r)
	if err != nil {
		if debug {
			log.Printf("go-akamai: error loading credentials: %v", err)
		}
		return Credentials{}, err
	}

	if !f.HasSection(section) {
		if debug {
			log.Printf("go-akamai: no section %q in credentials file", section)
		}
		return Credentials{}, fmt.Errorf("no section %q", section)
	}
	s := f.Section(section)

	clientToken := s.Key("client_token").String()
	if clientToken == "" {
		if debug {
			log.Printf("go-akamai: missing client_token in section %q", section)
		}
		return Credentials{}, errors.New("missing client_token")
	}
	clientSecret := s.Key("client_secret").String()
	if clientSecret == "" {
		if debug {
			log.Printf("go-akamai: missing client_secret in section %q", section)
		}
		return Credentials{}, errors.New("missing client_secret")
	}
	accessToken := s.Key("access_token").String()
	if accessToken == "" {
		if debug {
			log.Printf("go-akamai: missing access_token in section %q", section)
		}
		return Credentials{}, errors.New("missing access_token")
	}
	host := s.Key("host").String()
	if host == "" {
		if debug {
			log.Printf("go-akamai: missing host in section %q", section)
		}
		return Credentials{}, errors.New("missing host")
	}

	return Credentials{
		ClientToken:  clientToken,
		ClientSecret: clientSecret,
		AccessToken:  accessToken,
		Host:         host,
	}, nil
}
