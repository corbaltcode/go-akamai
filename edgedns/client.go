package edgedns

import (
	"net/http"
	"net/url"

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

func handleQueryArgs(q url.Values) string {
	s := q.Encode()
	if len(s) == 0 {
		return s
	}
	return "?" + s
}

func (c *Client) ListRecordsets(zone string, queryArgs url.Values) (*RecordsetResponse, error) {
	var rs RecordsetResponse
	err := request.DoJSON(c.Credentials, http.MethodGet, "/config-dns/v2/zones/"+zone+"/recordsets"+handleQueryArgs(queryArgs), nil, &rs)
	if err != nil {
		return nil, err
	}
	return &rs, nil
}

func (c *Client) RetrieveRecordsetTypes(zone, name string) (*TypesResponse, error) {
	var tr TypesResponse
	err := request.DoJSON(c.Credentials, http.MethodGet, "/config-dns/v2/zones/"+zone+"/names/"+name+"/types", nil, &tr)
	if err != nil {
		return nil, err
	}
	return &tr, nil
}

func (c *Client) RetrieveRecordset(zone, name, recordSetType string) (*Recordset, error) {
	var rs Recordset
	err := request.DoJSON(c.Credentials, http.MethodGet, "/config-dns/v2/zones/"+zone+"/names/"+name+"/types/"+recordSetType, nil, &rs)
	if err != nil {
		return nil, err
	}
	return &rs, nil
}

func (c *Client) CreateRecordset(zone, name, recordSetType string, body *Recordset) (*Recordset, error) {
	var rs Recordset
	err := request.DoJSON(c.Credentials, http.MethodPost, "/config-dns/v2/zones/"+zone+"/names/"+name+"/types/"+recordSetType, body, &rs)
	if err != nil {
		return nil, err
	}
	return &rs, nil
}

func (c *Client) UpdateRecordset(zone, name, recordSetType string, body *Recordset) (*Recordset, error) {
	var rs Recordset
	err := request.DoJSON(c.Credentials, http.MethodPut, "/config-dns/v2/zones/"+zone+"/names/"+name+"/types/"+recordSetType, body, &rs)
	if err != nil {
		return nil, err
	}
	return &rs, nil
}

func (c *Client) DeleteRecordset(zone, name, recordSetType string) error {
	return request.DoJSON(c.Credentials, http.MethodDelete, "/config-dns/v2/zones/"+zone+"/names/"+name+"/types/"+recordSetType, nil, nil)
}
