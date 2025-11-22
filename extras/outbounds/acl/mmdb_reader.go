package acl

import (
	"github.com/oschwald/maxminddb-golang"
	"net"
	"strings"
	"sync"
)

type geoip2Country struct {
	Country struct {
		IsoCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

type IPReader struct {
	*maxminddb.Reader
	lock  sync.Mutex
	close bool
}

type ASNReader struct {
	*maxminddb.Reader
}

type GeoLite2 struct {
	AutonomousSystemNumber       uint32 `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

func (r *IPReader) LookupCode(ipAddress net.IP) []string {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.close {
		return []string{}
	}
	var country geoip2Country
	_ = r.Lookup(ipAddress, &country)
	if country.Country.IsoCode == "" {
		return []string{}
	}
	return []string{strings.ToLower(country.Country.IsoCode)}
}
