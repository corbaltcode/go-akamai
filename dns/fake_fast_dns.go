package dns

import (
	"fmt"
	"time"
)

type FakeFastDNS struct {
	// Set before using
	DefaultZoneResponse ZoneResponse

	zones map[string]*ZoneResponse
}

func (f *FakeFastDNS) GetZone(name string) (*ZoneResponse, error) {
	if f.zones == nil {
		f.zones = make(map[string]*ZoneResponse)
	}
	zone := f.zones[name]
	if zone == nil {
		zrCopy := f.DefaultZoneResponse
		zrCopy.Zone.Name = name
		f.zones[name] = &zrCopy
		zone = &zrCopy
	}
	return zone, nil
}

func (f *FakeFastDNS) SetZone(name string, zr *ZoneResponse) error {
	if f.zones == nil {
		f.zones = make(map[string]*ZoneResponse)
	}
	zrCopy := *zr
	// If token is not updated the CLI will think the zone wasn't changed.
	zrCopy.Token = fmt.Sprintf("%x", time.Now().UnixNano())
	f.zones[name] = &zrCopy
	return nil
}
