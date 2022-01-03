package fastdns

import (
	"net/http"
	"sort"

	"github.com/corbaltcode/go-akamai"
	"github.com/corbaltcode/go-akamai/internal/request"
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

func (z *Zone) Sort() {
	// Akamai clients and servers randomize the order of some records. By returning
	// them to the caller in sorted order, we enable the caller to use reflect.DeepEqual
	// to two sets of records.
	sort.Sort(z.A)
	sort.Sort(z.AAAA)
	sort.Sort(z.AFSDB)
	sort.Sort(z.CNAME)
	sort.Sort(z.DNSKEY)
	sort.Sort(z.DS)
	sort.Sort(z.HINFO)
	sort.Sort(z.LOC)
	sort.Sort(z.MX)
	sort.Sort(z.NAPTR)
	sort.Sort(z.NS)
	sort.Sort(z.NSEC3)
	sort.Sort(z.NSEC3PARAM)
	sort.Sort(z.PTR)
	sort.Sort(z.RP)
	sort.Sort(z.RRSIG)
	sort.Sort(z.SPF)
	sort.Sort(z.SRV)
	sort.Sort(z.SSHFP)
	sort.Sort(z.TXT)
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

type Client struct {
	Credentials akamai.Credentials
}

// Returns the current zone info, with each set of records sorted in an arbitrary but
// consistent order.
func (c *Client) GetZone(name string) (*ZoneResponse, error) {
	var zr ZoneResponse
	err := request.DoJSON(c.Credentials, http.MethodGet, "/config-dns/v1/zones/"+name, nil, &zr)
	if err != nil {
		return nil, err
	}
	zr.Zone.Sort()
	return &zr, nil
}

// Updates the current zone.
func (c *Client) SetZone(name string, zr *ZoneResponse) error {
	return request.DoJSON(c.Credentials, http.MethodPost, "/config-dns/v1/zones/"+name, zr, nil)
}
