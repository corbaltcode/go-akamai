package firewall

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"cloud.google.com/go/civil"
	"github.com/corbaltcode/go-akamai"
	"github.com/corbaltcode/go-akamai/internal/request"
	"inet.af/netaddr"
)

const basePath = "/firewall-rules-manager/v1/"

type Client struct {
	Credentials akamai.Credentials
}

func (c *Client) GetCIDRBlocks() ([]CIDRBlock, error) {
	var respBlocks []cidrBlockResp

	err := request.DoJSON(c.Credentials, http.MethodGet, basePath+"cidr-blocks", nil, &respBlocks)
	if err != nil {
		return nil, err
	}

	blocks := make([]CIDRBlock, len(respBlocks))

	for i, respBlock := range respBlocks {
		block, err := newCIDRBlockFromResp(respBlock)
		if err != nil {
			return nil, err
		}
		blocks[i] = block
	}

	return blocks, nil
}

func (c *Client) GetService(id int) (Service, error) {
	var service Service

	err := request.DoJSON(c.Credentials, http.MethodGet, fmt.Sprintf("%sservices/%d", basePath, id), nil, &service)
	if err != nil {
		return Service{}, err
	}

	return service, nil
}

type Service struct {
	ID          int    `json:"serviceId"`
	Name        string `json:"serviceName"`
	Description string `json:"description"`
}

type CIDRBlock struct {
	ID            int
	ServiceID     int
	ServiceName   string
	CIDR          netaddr.IPPrefix
	Ports         []int
	CreationDate  civil.Date
	EffectiveDate civil.Date
	ChangeDate    civil.Date
	MinIP         netaddr.IP
	MaxIP         netaddr.IP
	LastAction    LastAction
}

func newCIDRBlockFromResp(r cidrBlockResp) (CIDRBlock, error) {
	var err error
	var v CIDRBlock

	v.ID = r.CIDRID
	v.ServiceID = r.ServiceID
	v.ServiceName = r.ServiceName

	v.CIDR, err = netaddr.ParseIPPrefix(r.CIDR + r.CIDRMask)
	if err != nil {
		return CIDRBlock{}, err
	}

	for _, portStr := range strings.Split(r.Port, ",") {
		port, err := strconv.ParseUint(portStr, 10, 0)
		if err != nil {
			return CIDRBlock{}, err
		}
		v.Ports = append(v.Ports, int(port))
	}

	if r.CreationDate == "" {
		v.CreationDate = civil.Date{}
	} else {
		v.CreationDate, err = civil.ParseDate(r.CreationDate)
		if err != nil {
			return CIDRBlock{}, err
		}
	}
	if r.EffectiveDate == "" {
		v.EffectiveDate = civil.Date{}
	} else {
		v.EffectiveDate, err = civil.ParseDate(r.EffectiveDate)
		if err != nil {
			return CIDRBlock{}, err
		}
	}
	if r.ChangeDate == "" {
		v.EffectiveDate = civil.Date{}
	} else {
		v.ChangeDate, err = civil.ParseDate(r.ChangeDate)
		if err != nil {
			return CIDRBlock{}, err
		}
	}

	v.MinIP, err = netaddr.ParseIP(r.MinIP)
	if err != nil {
		return CIDRBlock{}, err
	}
	v.MaxIP, err = netaddr.ParseIP(r.MaxIP)
	if err != nil {
		return CIDRBlock{}, err
	}
	v.LastAction = parseLastAction(r.LastAction)

	return v, nil
}

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
