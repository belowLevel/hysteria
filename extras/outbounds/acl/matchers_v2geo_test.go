package acl

import (
	lru "github.com/hashicorp/golang-lru/v2"
	"net"
	"testing"

	"github.com/apernet/hysteria/extras/v2/outbounds/acl/v2geo"
	"github.com/stretchr/testify/assert"
)

func Test_geoipMatcher_Match(t *testing.T) {
	geoipMap, err := v2geo.LoadGeoIP("v2geo/geoip.dat")
	assert.NoError(t, err)
	m, err := newGeoIPMatcher(geoipMap["us"])
	assert.NoError(t, err)

	tests := []struct {
		name string
		host HostInfo
		want bool
	}{
		{
			name: "IPv4 match",
			host: HostInfo{
				IPv4: net.ParseIP("73.222.1.100"),
			},
			want: true,
		},
		{
			name: "IPv4 no match",
			host: HostInfo{
				IPv4: net.ParseIP("123.123.123.123"),
			},
			want: false,
		},
		{
			name: "IPv6 match",
			host: HostInfo{
				IPv6: net.ParseIP("2607:f8b0:4005:80c::2004"),
			},
			want: true,
		},
		{
			name: "IPv6 no match",
			host: HostInfo{
				IPv6: net.ParseIP("240e:947:6001::1f8"),
			},
			want: false,
		},
		{
			name: "both nil",
			host: HostInfo{
				IPv4: nil,
				IPv6: nil,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, m.Match(tt.host), "Match(%v)", tt.host)
		})
	}
}

func Test_geositeMatcher_Match(t *testing.T) {
	geositeMap, err := v2geo.LoadGeoSite("v2geo/geosite.dat")
	assert.NoError(t, err)
	m, err := newGeositeMatcher(geositeMap["apple"], nil)
	assert.NoError(t, err)

	tests := []struct {
		name  string
		attrs []string
		host  HostInfo
		want  bool
	}{
		{
			name:  "subdomain",
			attrs: nil,
			host: HostInfo{
				Name: "poop.i-book.com",
			},
			want: true,
		},
		{
			name:  "subdomain root",
			attrs: nil,
			host: HostInfo{
				Name: "applepaycash.net",
			},
			want: true,
		},
		{
			name:  "full",
			attrs: nil,
			host: HostInfo{
				Name: "courier-push-apple.com.akadns.net",
			},
			want: true,
		},
		{
			name:  "regexp",
			attrs: nil,
			host: HostInfo{
				Name: "cdn4.apple-mapkit.com",
			},
			want: true,
		},
		{
			name:  "attr match",
			attrs: []string{"cn"},
			host: HostInfo{
				Name: "bag.itunes.apple.com",
			},
			want: true,
		},
		{
			name:  "attr multi no match",
			attrs: []string{"cn", "haha"},
			host: HostInfo{
				Name: "bag.itunes.apple.com",
			},
			want: false,
		},
		{
			name:  "attr no match",
			attrs: []string{"cn"},
			host: HostInfo{
				Name: "mr-apple.com.tw",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.Attrs = tt.attrs
			assert.Equalf(t, tt.want, m.Match(tt.host), "Match(%v)", tt.host)
		})
	}
}
func BenchmarkIpMatcher(b *testing.B) {
	geoipMap, err := v2geo.LoadGeoIP("v2geo/geoip.dat")
	assert.NoError(b, err)
	m, err := newGeoIPMatcher(geoipMap["us"])
	assert.NoError(b, err)
	ip := net.ParseIP("73.222.1.100")
	for i := 0; i < b.N; i++ {
		m.matchIP(ip)
	}
}

func BenchmarkDomainMatcher(b *testing.B) {

	geositeMap, err := v2geo.LoadGeoSite("v2geo/geosite.dat")
	assert.NoError(b, err)
	m, err := newGeositeMatcher(geositeMap["cn"], nil)
	assert.NoError(b, err)
	host := HostInfo{Name: "baidu.com"}
	for i := 0; i < b.N; i++ {
		m.Match(host)
	}
}
func TestDomainMatcher(t *testing.T) {
	geositeMap, err := v2geo.LoadGeoSite("v2geo/geosite.dat")
	assert.NoError(t, err)
	for k, _ := range geositeMap {
		m, err := newGeositeMatcher(geositeMap[k], nil)
		assert.NoError(t, err)
		for _, domain := range m.Domains {
			if domain.Type == geositeDomainRegex {
				t.Log(k, "|", domain.Type, "|", domain.Regex)
			}
		}
	}

}

func BenchmarkCache(b *testing.B) {
	cache, err := lru.New[matchResultCacheKey, matchResult[string]](10000)
	assert.NoError(b, err)
	geositeMap, err := v2geo.LoadGeoSite("v2geo/geosite.dat")
	assert.NoError(b, err)
	m, err := newGeositeMatcher(geositeMap["cn"], nil)
	assert.NoError(b, err)
	for _, v := range m.Domains {
		cache.Add(matchResultCacheKey{
			Host:  v.Value,
			Proto: 0,
			Port:  0,
		}, matchResult[string]{
			Outbound: v.Value,
		})
	}
	for i := 0; i < b.N; i++ {
		cache.Get(matchResultCacheKey{
			Host:  "google.com",
			Proto: 0,
			Port:  0,
		})
	}
}

func BenchmarkSSKV(b *testing.B) {
	geositeMap, err := v2geo.LoadGeoSite("v2geo/geosite.dat")
	assert.NoError(b, err)
	m, err := newGeositeMatcher(geositeMap["cn"], nil)
	assert.NoError(b, err)
	ds, _ := newSSKVMatcher(geositeMap["cn"], nil)
	b.Logf("loaded %d line, mem size %f MB", len(m.Domains), float32(ds.Size())/1024/1024)
	host := HostInfo{Name: "baidu.com"}
	for i := 0; i < b.N; i++ {
		ds.Match(host)
	}
}
func TestSSKV(t *testing.T) {
	geositeMap, err := v2geo.LoadGeoSite("v2geo/geosite.dat")
	assert.NoError(t, err)
	m, err := newGeositeMatcher(geositeMap["cn"], nil)
	assert.NoError(t, err)
	ds, _ := newSSKVMatcher(geositeMap["cn"], nil)
	t.Logf("loaded %d line, mem size %f MB", len(m.Domains), float32(ds.Size())/1024/1024)
	host := HostInfo{Name: "ewwd121.com"}
	t.Log(ds.Match(host))

}
