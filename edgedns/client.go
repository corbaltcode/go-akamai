package edgedns

import (
	"net/http"
	"strings"

	"github.com/corbaltcode/go-akamai"
	"github.com/corbaltcode/go-akamai/internal/request"
)

const defaultTTL = 300

const (
	RecordTypeCNAME = "CNAME"
	RecordTypeTXT   = "TXT"
)

type TypesResponse struct {
	Types []string `json:"types"`
}

type Recordset struct {
	Name  string   `json:"name"`
	Type  string   `json:"type"`
	TTL   int      `json:"ttl"`
	Rdata []string `json:"rdata"`
}

type RecordsetQueryArgs struct {
	Page     int
	PageSize int
	Search   string
	ShowAll  bool
	SortBy   string
	Types    string
}

type RecordsetResponse struct {
	Metadata   MetadataH   `json:"metadata"`
	Recordsets []Recordset `json:"recordsets"`
}

type MetadataH struct {
	LastPage      int  `json:"lastPage"`
	Page          int  `json:"page"`
	PageSize      int  `json:"pageSize"`
	ShowAll       bool `json:"showAll"`
	TotalElements int  `json:"totalElements"`
}

type Client struct {
	Credentials akamai.Credentials
}

func handleQueryArgs(q map[string]string) string {
	if len(q) == 0 {
		return ""
	}
	keyValues := make([]string, len(q))
	var counter int
	for key, value := range q {
		keyValues[counter] = key + "=" + value
		counter += 1
	}
	return "?" + strings.Join(keyValues, "&")
}

func (c *Client) ListRecordsets(zone string, queryArgs map[string]string) ([]Recordset, error) {
	var rs RecordsetResponse
	err := request.DoJSON(c.Credentials, http.MethodGet, "/config-dns/v2/zones/"+zone+"/recordsets"+handleQueryArgs(queryArgs), nil, &rs)
	if err != nil {
		return nil, err
	}
	return rs.Recordsets, nil
}

func (c *Client) RetrieveRecordsetTypes(zone, name string) ([]string, error) {
	var tr TypesResponse
	err := request.DoJSON(c.Credentials, http.MethodGet, "/config-dns/v2/zones/"+zone+"/names/"+name+"/types", nil, &tr)
	if err != nil {
		return nil, err
	}
	return tr.Types, nil
}

func (c *Client) RetrieveRecordset(zone, name, recordSetType string) (*Recordset, error) {
	var rs Recordset
	err := request.DoJSON(c.Credentials, http.MethodGet, "/config-dns/v2/zones/"+zone+"/names/"+name+"/types/"+recordSetType, nil, &rs)
	if err != nil {
		return nil, err
	}
	return &rs, nil
}

func (c *Client) CreateRecordset(zone, name, recordSetType string, body *Recordset) error {
	err := request.DoJSON(c.Credentials, http.MethodPost, "/config-dns/v2/zones/"+zone+"/names/"+name+"/types/"+recordSetType, body, nil)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) UpdateRecordset(zone, name, recordSetType string, body *Recordset) error {
	err := request.DoJSON(c.Credentials, http.MethodPut, "/config-dns/v2/zones/"+zone+"/names/"+name+"/types/"+recordSetType, body, nil)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) DeleteRecordset(zone, name, recordSetType string) error {
	return request.DoJSON(c.Credentials, http.MethodDelete, "/config-dns/v2/zones/"+zone+"/names/"+name+"/types/"+recordSetType, nil, nil)
}