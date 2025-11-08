package acl

import (
	"github.com/apernet/hysteria/extras/v2/outbounds/acl/v2geo"
)

type DomainSet struct {
	Set *Set
}

func (d *DomainSet) Match(host HostInfo) bool {
	if d.Set == nil {
		return false
	}
	return d.Set.Has(host.Name)
}

func (d *DomainSet) Size() int {
	if d.Set == nil {
		return 0
	}
	return d.Set.Size()
}

func newSSKVMatcher(list *v2geo.GeoSite, attrs []string) (*DomainSet, error) {
	ds := &DomainSet{}
	strs := make([]string, 0, len(list.Domain))
	for _, domain := range list.Domain {
		switch domain.Type {
		case v2geo.Domain_Plain:
			fallthrough
		case v2geo.Domain_Full:
			fallthrough
		case v2geo.Domain_RootDomain:
			{
				strs = append(strs, domain.Value)
			}
		case v2geo.Domain_Regex:
		default:

		}
	}
	ds.Set = NewSet(strs)
	return ds, nil
}
