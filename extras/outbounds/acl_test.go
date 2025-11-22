package outbounds

import (
	"github.com/apernet/hysteria/extras/v2/outbounds/acl"
	"log"
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestACLEngine(t *testing.T) {
	ob1, ob2, ob3 := &mockPluggableOutbound{}, &mockPluggableOutbound{}, &mockPluggableOutbound{}
	obs := []OutboundEntry{
		{"ob1", ob1},
		{"ob2", ob2},
		{"ob3", ob3},
		{"direct", ob2},
	}
	acl, err := NewACLEngineFromString(`
ob2(google.com,tcp)
ob3(youtube.com,udp)
ob1 (1.1.1.1/24,*,8.8.8.8)
Direct(cia.gov)
reJect(nsa.gov)
`, obs, nil)
	assert.NoError(t, err)

	// No match, default, should be the first (ob1)
	ob1.EXPECT().TCP(&AddrEx{Host: "example.com"}).Return(nil, nil).Once()
	conn, err := acl.TCP(&AddrEx{Host: "example.com"})
	assert.NoError(t, err)
	assert.Nil(t, conn)

	// Match ob2
	ob2.EXPECT().TCP(&AddrEx{Host: "google.com"}).Return(nil, nil).Once()
	conn, err = acl.TCP(&AddrEx{Host: "google.com"})
	assert.NoError(t, err)
	assert.Nil(t, conn)

	// Match ob3
	ob3.EXPECT().UDP(&AddrEx{Host: "youtube.com"}).Return(nil, nil).Once()
	udpConn, err := acl.UDP(&AddrEx{Host: "youtube.com"})
	assert.NoError(t, err)
	assert.Nil(t, udpConn)

	// Match ob1 hijack IP
	ob1.EXPECT().TCP(&AddrEx{Host: "8.8.8.8", ResolveInfo: &ResolveInfo{IPv4: net.ParseIP("8.8.8.8").To4()}}).Return(nil, nil).Once()
	conn, err = acl.TCP(&AddrEx{ResolveInfo: &ResolveInfo{IPv4: net.ParseIP("1.1.1.22")}})
	assert.NoError(t, err)
	assert.Nil(t, conn)

	// direct should be ob2 as we override it
	ob2.EXPECT().TCP(&AddrEx{Host: "cia.gov"}).Return(nil, nil).Once()
	conn, err = acl.TCP(&AddrEx{Host: "cia.gov"})
	assert.NoError(t, err)
	assert.Nil(t, conn)

	// reject
	conn, err = acl.TCP(&AddrEx{Host: "nsa.gov"})
	assert.Error(t, err)
	assert.Nil(t, conn)
}

func TestACL(t *testing.T) {
	var urls = map[string]string{
		"p1": "socks5://alice:secret123@203.0.113.5:1080",
	}
	var obs = buildOutbounds(urls)
	var uOb PluggableOutbound
	Inline := []string{
		//"v6_only(suffix:gstatic.com)",
		"reject(geoip:cn)",
		"default(geoip:private)",
		"v6_only(geosite:youtube)",
		"v4_only(all)",
		"v4_only(geoip:cn)",
		"v4_only(all)",
	}
	gLoader := &acl.GeoLoaderT{
		DownloadFunc: func(filename, url string) {
			t.Logf("%s %s", filename, url)
		},
		DownloadErrFunc: func(err error) {
			t.Errorf("%v", err)
		},
	}
	acl, err := NewACLEngineFromString(strings.Join(Inline, "\n"), obs, gLoader)
	if err != nil {
		t.Errorf("%v", err)
	}
	uOb = acl
	//uOb = outbounds.NewSystemResolver(uOb)
	ob := &PluggableOutboundAdapter{PluggableOutbound: uOb}
	//conn, err := ob.TCP("baidu.com:80")
	conn, err := ob.TCP("vvvvvvvvvxxxxxxxxee.com:80")

	if err != nil {
		t.Errorf("%v", err)
	} else {
		defer conn.Close()
	}
}
func buildOutbounds(urls map[string]string) []OutboundEntry {
	var obs []OutboundEntry
	for k, v := range urls {
		upstreamURL, err := url.Parse(v)
		if err != nil {
			continue
		}
		switch upstreamURL.Scheme {
		case "socks":
			fallthrough
		case "socks5":
			fallthrough
		case "socks5h":
			{
				password, _ := upstreamURL.User.Password()
				obs = append(obs, OutboundEntry{
					Name:     k,
					Outbound: NewSOCKS5Outbound(upstreamURL.Host, upstreamURL.User.Username(), password),
				})
			}
		case "http":
			fallthrough
		case "https":
			{
				ob, err := NewHTTPOutbound(v, true)
				if err != nil {
					log.Fatalln(err)
				} else {
					obs = append(obs, OutboundEntry{
						Name:     k,
						Outbound: ob,
					})
				}
			}
		default:
			log.Fatalln("unknown Scheme", v)

		}
	}
	obs = append(obs, OutboundEntry{
		Name:     "default",
		Outbound: NewDirectOutboundSimple(DirectOutboundModeAuto),
	})
	obs = append(obs, OutboundEntry{
		Name:     "v6_only",
		Outbound: NewDirectOutboundSimple(DirectOutboundMode6),
	})
	obs = append(obs, OutboundEntry{
		Name:     "v4_only",
		Outbound: NewDirectOutboundSimple(DirectOutboundMode4),
	})
	return obs
}
