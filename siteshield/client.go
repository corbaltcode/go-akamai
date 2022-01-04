package siteshield

import (
	"fmt"
	"net/http"
	"time"

	"github.com/corbaltcode/go-akamai"
	"github.com/corbaltcode/go-akamai/internal/request"
	"inet.af/netaddr"
)

const basePath = "/siteshield/v1/"

// A Client allows access to the Akamai Site Shield API.
type Client struct {
	Credentials akamai.Credentials
}

// GetMaps returns all maps that belong to the client's account.
func (c *Client) GetMaps() ([]Map, error) {
	var resp mapsResp

	err := request.DoJSON(c.Credentials, http.MethodGet, basePath+"maps", nil, &resp)
	if err != nil {
		return nil, err
	}

	maps := make([]Map, len(resp.SiteShieldMaps))

	for i, mapResp := range resp.SiteShieldMaps {
		m, err := newMapFromResp(mapResp)
		if err != nil {
			return nil, err
		}
		maps[i] = m
	}

	return maps, nil
}

// GetMap returns information about a map by ID.
func (c *Client) GetMap(id int) (Map, error) {
	var resp mapResp

	err := request.DoJSON(c.Credentials, http.MethodGet, fmt.Sprintf("%smaps/%d", basePath, id), nil, &resp)
	if err != nil {
		return Map{}, err
	}

	m, err := newMapFromResp(resp)
	if err != nil {
		return Map{}, err
	}

	return m, nil
}

type Map struct {
	AcknowledgeRequiredBy time.Time
	Acknowledged          bool
	AcknowledgedBy        string
	Alias                 string
	Contacts              []string
	CurrentCIDRs          []netaddr.IPPrefix
	ID                    int
	IsShared              bool
	LatestTicketID        int
	ProposedCIDRs         []netaddr.IPPrefix
	RuleName              string
	Service               Service
	SureRouteName         string
	Type                  string
}

func newMapFromResp(r mapResp) (Map, error) {
	var m Map
	// m.AcknowledgeRequiredBy = time.UnixMilli(r.AcknowledgeRequiredBy)
	acknowledgeRequiredBy, err := time.Parse(time.RFC3339, r.AcknowledgeRequiredBy)
	if err != nil {
		return Map{}, err
	}
	m.AcknowledgeRequiredBy = acknowledgeRequiredBy

	m.Acknowledged = r.Acknowledged
	m.AcknowledgedBy = r.AcknowledgedBy
	m.Alias = r.MapAlias

	m.Contacts = make([]string, len(r.Contacts))
	copy(m.Contacts, r.Contacts)

	m.CurrentCIDRs = make([]netaddr.IPPrefix, len(r.CurrentCIDRs))
	for i, str := range r.CurrentCIDRs {
		prefix, err := netaddr.ParseIPPrefix(str)
		if err != nil {
			return Map{}, err
		}
		m.CurrentCIDRs[i] = prefix
	}

	m.ID = r.ID
	m.IsShared = r.Shared
	m.LatestTicketID = r.LatestTicketID

	m.ProposedCIDRs = make([]netaddr.IPPrefix, len(r.ProposedCIDRs))
	for i, str := range r.ProposedCIDRs {
		prefix, err := netaddr.ParseIPPrefix(str)
		if err != nil {
			return Map{}, err
		}
		m.ProposedCIDRs[i] = prefix
	}

	m.RuleName = r.RuleName
	m.Service = parseService(r.Service)
	m.SureRouteName = r.SureRouteName
	m.Type = r.Type

	return m, nil
}

type mapsResp struct {
	SiteShieldMaps []mapResp `json:"siteShieldMaps"`
}

type mapResp struct {
	AcknowledgeRequiredBy string   `json:"acknowledgeRequiredBy"`
	Acknowledged          bool     `json:"acknowledged"`
	AcknowledgedBy        string   `json:"acknowledgedBy"`
	Contacts              []string `json:"contacts"`
	CurrentCIDRs          []string `json:"currentCidrs"`
	ID                    int      `json:"id"`
	LatestTicketID        int      `json:"latestTicketId"`
	MapAlias              string   `json:"mapAlias"`
	MCMMapRuleID          int      `json:"mcmMapRuleId"`
	ProposedCIDRs         []string `json:"proposedCidrs"`
	RuleName              string   `json:"ruleName"`
	Service               string   `json:"service"`
	Shared                bool     `json:"shared"`
	SureRouteName         string   `json:"sureRouteName"`
	Type                  string   `json:"type"`
}

type Service string

const (
	ServiceOther    = "other"
	ServiceScript   = "script"
	ServiceESSL     = "ESSL"
	ServiceFreeFlow = "FreeFlow"
)

func parseService(s string) Service {
	switch s {
	case "C":
		return ServiceScript
	case "S":
		return ServiceESSL
	case "W":
		return ServiceFreeFlow
	default:
		return ServiceOther
	}
}
