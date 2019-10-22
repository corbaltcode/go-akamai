package dns

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
)

type ZoneResponse struct {
	Token string `json:"token"`
	Zone  Zone   `json:"zone"`
}

// Records besides SOA do not have their contents exported because the only
// user of this package (the server) does not need to inspect any of them.
type Zone struct {
	// Name of zone
	Name string `json:"name"`

	// SOA
	SOA SOARecord `json:"soa"`

	// Other records
	A          ARecordList          `json:"a,omitempty"`
	AAAA       AAAARecordList       `json:"aaaa,omitempty"`
	AFSDB      AFSDBRecordList      `json:"afsdb,omitempty"`
	CNAME      CNAMERecordList      `json:"cname,omitempty"`
	DNSKEY     DNSKEYRecordList     `json:"dnskey,omitempty"`
	DS         DSRecordList         `json:"ds,omitempty"`
	HINFO      HINFORecordList      `json:"hinfo,omitempty"`
	LOC        LOCRecordList        `json:"loc,omitempty"`
	MX         MXRecordList         `json:"mx,omitempty"`
	NAPTR      NAPTRRecordList      `json:"naptr,omitempty"`
	NS         NSRecordList         `json:"ns,omitempty"`
	NSEC3      NSEC3RecordList      `json:"nsec3,omitempty"`
	NSEC3PARAM NSEC3PARAMRecordList `json:"nsec3param,omitempty"`
	PTR        PTRRecordList        `json:"ptr,omitempty"`
	RP         RPRecordList         `json:"rp,omitempty"`
	RRSIG      RRSIGRecordList      `json:"rrsig,omitempty"`
	SPF        SPFRecordList        `json:"spf,omitempty"`
	SRV        SRVRecordList        `json:"srv,omitempty"`
	SSHFP      SSHFPRecordList      `json:"sshfp,omitempty"`
	TXT        TXTRecordList        `json:"txt,omitempty"`

	// Undocumented fields
	ID        int64   `json:"id"`
	Instance  string  `json:"instance"`
	Publisher string  `json:"publisher"`
	Time      int64   `json:"time"`
	Version   float64 `json:"version"`
}

type SOARecord struct {
	TTL          int    `json:"ttl,omitempty"`
	Originserver string `json:"originserver,omitempty"`
	Contact      string `json:"contact,omitempty"`
	Serial       int    `json:"serial,omitempty"`
	Refresh      int    `json:"refresh,omitempty"`
	Retry        int    `json:"retry,omitempty"`
	Expire       int    `json:"expire,omitempty"`
	Minimum      int    `json:"minimum,omitempty"`
}

type DNSRecord map[string]interface{}

func ZoneResponseFromJSON(b []byte) (*ZoneResponse, error) {
	zr := new(ZoneResponse)
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(zr)
	if err != nil {
		return nil, err
	}

	// Akamai clients and servers randomize the order of some records. By returning
	// them to the caller in sorted order, we enable the caller to use reflect.DeepEqual
	// to two sets of records.
	sort.Sort(zr.Zone.A)
	sort.Sort(zr.Zone.AAAA)
	sort.Sort(zr.Zone.AFSDB)
	sort.Sort(zr.Zone.CNAME)
	sort.Sort(zr.Zone.DNSKEY)
	sort.Sort(zr.Zone.DS)
	sort.Sort(zr.Zone.HINFO)
	sort.Sort(zr.Zone.LOC)
	sort.Sort(zr.Zone.MX)
	sort.Sort(zr.Zone.NAPTR)
	sort.Sort(zr.Zone.NS)
	sort.Sort(zr.Zone.NSEC3)
	sort.Sort(zr.Zone.NSEC3PARAM)
	sort.Sort(zr.Zone.PTR)
	sort.Sort(zr.Zone.RP)
	sort.Sort(zr.Zone.RRSIG)
	sort.Sort(zr.Zone.SPF)
	sort.Sort(zr.Zone.SRV)
	sort.Sort(zr.Zone.SSHFP)
	sort.Sort(zr.Zone.TXT)

	return zr, err
}

type FastDNS interface {
	GetZone(name string) (*ZoneResponse, error)
	SetZone(name string, zr *ZoneResponse) error
}

type fastDNS struct {
	*Auth
}

const timeFormat = "20060102T15:04:05-0700"

// If the body is not empty it should be marshaled JSON.
func (d *fastDNS) doRequest(method, path string, body []byte) ([]byte, error) {
	auth, err := d.Auth.GenerateAuthHeader(method, path, body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, fmt.Sprintf("%s://%s%s", d.Scheme, d.Host, path), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", auth)
	if len(body) > 0 {
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Content-Length", fmt.Sprintf("%d", len(body)))
	}
	resp, err := new(http.Client).Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.New(string(b))
	}
	return ioutil.ReadAll(resp.Body)
}

func NewFastDNS(c Auth) FastDNS {
	return &fastDNS{Auth: &c}
}

// Returns the current zone info, with each set of records sorted in an arbitrary but
// consistent order.
func (d *fastDNS) GetZone(name string) (*ZoneResponse, error) {
	b, err := d.doRequest(http.MethodGet, "/config-dns/v1/zones/"+name, nil)
	if err != nil {
		return nil, err
	}
	zr, err := ZoneResponseFromJSON(b)
	return zr, err
}

// Updates the current zone.
func (d *fastDNS) SetZone(name string, zr *ZoneResponse) error {
	b, err := json.Marshal(zr)
	if err != nil {
		return err
	}
	_, err = d.doRequest(http.MethodPost, "/config-dns/v1/zones/"+name, b)
	return err
}
