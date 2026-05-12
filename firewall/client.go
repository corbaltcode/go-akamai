package firewall

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"net/netip"

	"cloud.google.com/go/civil"
	"github.com/corbaltcode/go-akamai"
	"github.com/corbaltcode/go-akamai/internal/request"
)

const basePath = "/firewall-rules-manager/v1/"

// A Client allows access to the Akamai Firewall Rules Notification API.
type Client struct {
	Credentials akamai.Credentials
}

// GetCIDRBlocks returns all CIDR blocks for all services the client is
// subscribed to.
func (c *Client) GetCIDRBlocks() ([]CIDRBlock, error) {
	return c.GetCIDRBlocksWithContext(context.Background())
}

// GetCIDRBlocksWithContext returns all CIDR blocks for all services the client is
// subscribed to.
//
// The context is used to determine whether debugging is enabled and to allow cancellation of the
// request.
func (c *Client) GetCIDRBlocksWithContext(ctx context.Context) ([]CIDRBlock, error) {
	var respBlocks []cidrBlockResp

	err := request.DoJSONWithContext(ctx, c.Credentials, http.MethodGet, basePath+"cidr-blocks", nil, &respBlocks)
	if err != nil {
		return nil, err
	}

	blocks := make([]CIDRBlock, len(respBlocks))

	for i, respBlock := range respBlocks {
		block, err := newCIDRBlockFromResp(ctx, respBlock)
		if err != nil {
			return nil, err
		}
		blocks[i] = block
	}

	return blocks, nil
}

// GetService returns information about a service by ID.
//
// This is a compatibility wrapper around GetServiceWithContext that uses context.Background() as the context.
func (c *Client) GetService(id int) (Service, error) {
	return c.GetServiceWithContext(context.Background(), id)
}

// GetServiceWithContext returns information about a service by ID.
//
// The context is used to determine whether debugging is enabled and to allow cancellation of the
// request.
func (c *Client) GetServiceWithContext(ctx context.Context, id int) (Service, error) {
	var service Service

	err := request.DoJSONWithContext(ctx, c.Credentials, http.MethodGet, fmt.Sprintf("%sservices/%d", basePath, id), nil, &service)
	if err != nil {
		return Service{}, err
	}

	return service, nil
}

// Service represents an Akamai service that a client is subscribed to.
type Service struct {
	ID          int    `json:"serviceId"`
	Name        string `json:"serviceName"`
	Description string `json:"description"`
}

// CIDRBlock represents a CIDR block that is allowed to access an Akamai service under the Firewall Rules
// Notification API.
type CIDRBlock struct {
	ID            int
	ServiceID     int
	ServiceName   string
	CIDR          netip.Prefix
	Ports         []int
	CreationDate  civil.Date
	EffectiveDate civil.Date
	ChangeDate    civil.Date
	MinIP         netip.Addr
	MaxIP         netip.Addr
	LastAction    LastAction
}

func newCIDRBlockFromResp(ctx context.Context, r cidrBlockResp) (CIDRBlock, error) {
	var err error
	var v CIDRBlock
	debug := akamai.DebugEnabled(ctx)

	v.ID = r.CIDRID
	v.ServiceID = r.ServiceID
	v.ServiceName = r.ServiceName

	v.CIDR, err = netip.ParsePrefix(r.CIDR + r.CIDRMask)
	if err != nil {
		if debug {
			log.Printf("newCIDRBlockFromResp: error parsing CIDR and mask %s%s: %v", r.CIDR, r.CIDRMask, err)
		}

		return CIDRBlock{}, err
	}

	for _, portStr := range strings.Split(r.Port, ",") {
		port, err := strconv.ParseUint(portStr, 10, 0)
		if err != nil {
			if debug {
				log.Printf("newCIDRBlockFromResp: error parsing port %s: %v", portStr, err)
			}

			return CIDRBlock{}, err
		}
		v.Ports = append(v.Ports, int(port))
	}

	if r.CreationDate == "" {
		v.CreationDate = civil.Date{}
	} else {
		v.CreationDate, err = civil.ParseDate(r.CreationDate)
		if err != nil {
			if debug {
				log.Printf("newCIDRBlockFromResp: error parsing creation date %s: %v", r.CreationDate, err)
			}

			return CIDRBlock{}, err
		}
	}
	if r.EffectiveDate == "" {
		v.EffectiveDate = civil.Date{}
	} else {
		v.EffectiveDate, err = civil.ParseDate(r.EffectiveDate)
		if err != nil {
			if debug {
				log.Printf("newCIDRBlockFromResp: error parsing effective date %s: %v", r.EffectiveDate, err)
			}

			return CIDRBlock{}, err
		}
	}
	if r.ChangeDate == "" {
		v.EffectiveDate = civil.Date{}
	} else {
		v.ChangeDate, err = civil.ParseDate(r.ChangeDate)
		if err != nil {
			if debug {
				log.Printf("newCIDRBlockFromResp: error parsing change date %s: %v", r.ChangeDate, err)
			}

			return CIDRBlock{}, err
		}
	}

	v.MinIP, err = netip.ParseAddr(r.MinIP)
	if err != nil {
		if debug {
			log.Printf("newCIDRBlockFromResp: error parsing min IP %s: %v", r.MinIP, err)
		}

		return CIDRBlock{}, err
	}
	v.MaxIP, err = netip.ParseAddr(r.MaxIP)
	if err != nil {
		if debug {
			log.Printf("newCIDRBlockFromResp: error parsing max IP %s: %v", r.MaxIP, err)
		}

		return CIDRBlock{}, err
	}

	v.LastAction = parseLastAction(r.LastAction)

	return v, nil
}

// cidrBlockResp is the struct used to unmarshal the JSON response for a CIDR block from the API.
type cidrBlockResp struct {
	CIDRID        int    `json:"cidrId"`
	ServiceID     int    `json:"serviceId"`
	ServiceName   string `json:"serviceName"`
	CIDR          string `json:"cidr"`
	CIDRMask      string `json:"cidrMask"`
	Port          string `json:"port"`
	CreationDate  string `json:"creationDate"`
	EffectiveDate string `json:"effectiveDate"`
	ChangeDate    string `json:"changeDate"`
	MinIP         string `json:"minIp"`
	MaxIP         string `json:"maxIp"`
	LastAction    string `json:"lastAction"`
}

type LastAction string

const (
	LastActionOther  LastAction = "other"
	LastActionAdd    LastAction = "add"
	LastActionUpdate LastAction = "update"
	LastActionDelete LastAction = "delete"
)

func parseLastAction(s string) LastAction {
	switch s {
	case "add":
		return LastActionAdd
	case "update":
		return LastActionUpdate
	case "delete":
		return LastActionDelete
	default:
		return LastActionOther
	}
}
