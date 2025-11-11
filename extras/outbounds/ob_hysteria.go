package outbounds

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"github.com/belowLevel/hysteria/extras/v2/outbounds/sockopts"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/apernet/hysteria/extras/v2/transport/udphop"
)

var (
	disableUpdateCheck bool
)

type clientConfig struct {
	Server    string                `mapstructure:"server"`
	Auth      string                `mapstructure:"auth"`
	Transport clientConfigTransport `mapstructure:"transport"`
	Obfs      clientConfigObfs      `mapstructure:"obfs"`
	TLS       clientConfigTLS       `mapstructure:"tls"`
	QUIC      clientConfigQUIC      `mapstructure:"quic"`
	Bandwidth clientConfigBandwidth `mapstructure:"bandwidth"`
	FastOpen  bool                  `mapstructure:"fastOpen"`
	Lazy      bool                  `mapstructure:"lazy"`
}

type clientConfigTransportUDP struct {
	HopInterval time.Duration `mapstructure:"hopInterval"`
}

type clientConfigTransport struct {
	Type string                   `mapstructure:"type"`
	UDP  clientConfigTransportUDP `mapstructure:"udp"`
}

type clientConfigObfsSalamander struct {
	Password string `mapstructure:"password"`
}

type clientConfigObfs struct {
	Type       string                     `mapstructure:"type"`
	Salamander clientConfigObfsSalamander `mapstructure:"salamander"`
}

type clientConfigTLS struct {
	SNI               string `mapstructure:"sni"`
	Insecure          bool   `mapstructure:"insecure"`
	PinSHA256         string `mapstructure:"pinSHA256"`
	CA                string `mapstructure:"ca"`
	ClientCertificate string `mapstructure:"clientCertificate"`
	ClientKey         string `mapstructure:"clientKey"`
}

type clientConfigQUIC struct {
	InitStreamReceiveWindow     uint64                   `mapstructure:"initStreamReceiveWindow"`
	MaxStreamReceiveWindow      uint64                   `mapstructure:"maxStreamReceiveWindow"`
	InitConnectionReceiveWindow uint64                   `mapstructure:"initConnReceiveWindow"`
	MaxConnectionReceiveWindow  uint64                   `mapstructure:"maxConnReceiveWindow"`
	MaxIdleTimeout              time.Duration            `mapstructure:"maxIdleTimeout"`
	KeepAlivePeriod             time.Duration            `mapstructure:"keepAlivePeriod"`
	DisablePathMTUDiscovery     bool                     `mapstructure:"disablePathMTUDiscovery"`
	Sockopts                    clientConfigQUICSockopts `mapstructure:"sockopts"`
}

type clientConfigQUICSockopts struct {
	BindInterface       *string `mapstructure:"bindInterface"`
	FirewallMark        *uint32 `mapstructure:"fwmark"`
	FdControlUnixSocket *string `mapstructure:"fdControlUnixSocket"`
}

type clientConfigBandwidth struct {
	Up   string `mapstructure:"up"`
	Down string `mapstructure:"down"`
}

func (c *clientConfig) fillServerAddr(hyConfig *client.Config) error {
	if c.Server == "" {
		return errors.New("server address is empty")
	}
	var addr net.Addr
	var err error
	host, port, hostPort := parseServerAddrString(c.Server)
	if !isPortHoppingPort(port) {
		addr, err = net.ResolveUDPAddr("udp", hostPort)
	} else {
		addr, err = udphop.ResolveUDPHopAddr(hostPort)
	}
	if err != nil {
		return err
	}
	hyConfig.ServerAddr = addr
	// Special handling for SNI
	if c.TLS.SNI == "" {
		// Use server hostname as SNI
		hyConfig.TLSConfig.ServerName = host
	}
	return nil
}

// fillConnFactory must be called after fillServerAddr, as we have different logic
// for ConnFactory depending on whether we have a port hopping address.
func (c *clientConfig) fillConnFactory(hyConfig *client.Config) error {
	so := &sockopts.SocketOptions{
		BindInterface:       c.QUIC.Sockopts.BindInterface,
		FirewallMark:        c.QUIC.Sockopts.FirewallMark,
		FdControlUnixSocket: c.QUIC.Sockopts.FdControlUnixSocket,
	}
	if err := so.CheckSupported(); err != nil {
		return err
	}
	// Inner PacketConn
	var newFunc func(addr net.Addr) (net.PacketConn, error)
	switch strings.ToLower(c.Transport.Type) {
	case "", "udp":
		if hyConfig.ServerAddr.Network() == "udphop" {
			hopAddr := hyConfig.ServerAddr.(*udphop.UDPHopAddr)
			newFunc = func(addr net.Addr) (net.PacketConn, error) {
				return udphop.NewUDPHopPacketConn(hopAddr, c.Transport.UDP.HopInterval, so.ListenUDP)
			}
		} else {
			newFunc = func(addr net.Addr) (net.PacketConn, error) {
				return so.ListenUDP()
			}
		}
	default:
		return errors.New("unsupported transport type")
	}
	// Obfuscation
	var ob obfs.Obfuscator
	var err error
	switch strings.ToLower(c.Obfs.Type) {
	case "", "plain":
		// Keep it nil
	case "salamander":
		ob, err = obfs.NewSalamanderObfuscator([]byte(c.Obfs.Salamander.Password))
		if err != nil {
			return err
		}
	default:
		return errors.New("unsupported obfuscation type")
	}
	hyConfig.ConnFactory = &adaptiveConnFactory{
		NewFunc:    newFunc,
		Obfuscator: ob,
	}
	return nil
}

func (c *clientConfig) fillAuth(hyConfig *client.Config) error {
	hyConfig.Auth = c.Auth
	return nil
}

func (c *clientConfig) fillTLSConfig(hyConfig *client.Config) error {
	if c.TLS.SNI != "" {
		hyConfig.TLSConfig.ServerName = c.TLS.SNI
	}
	hyConfig.TLSConfig.InsecureSkipVerify = c.TLS.Insecure
	if c.TLS.PinSHA256 != "" {
		nHash := normalizeCertHash(c.TLS.PinSHA256)
		hyConfig.TLSConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			cert := rawCerts[0] // only check the end-entity cert hash in the chain of trust
			hash := sha256.Sum256(cert)
			hashHex := hex.EncodeToString(hash[:])
			if hashHex == nHash {
				return nil
			}
			// No match
			return errors.New("no certificate matches the pinned hash")
		}
	}
	if c.TLS.CA != "" {
		ca, err := os.ReadFile(c.TLS.CA)
		if err != nil {
			return err
		}
		cPool := x509.NewCertPool()
		if !cPool.AppendCertsFromPEM(ca) {
			return errors.New("failed to parse CA certificate")
		}
		hyConfig.TLSConfig.RootCAs = cPool
	}
	return nil
}

func (c *clientConfig) fillQUICConfig(hyConfig *client.Config) error {
	hyConfig.QUICConfig = client.QUICConfig{
		InitialStreamReceiveWindow:     c.QUIC.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         c.QUIC.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: c.QUIC.InitConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     c.QUIC.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 c.QUIC.MaxIdleTimeout,
		KeepAlivePeriod:                c.QUIC.KeepAlivePeriod,
		DisablePathMTUDiscovery:        c.QUIC.DisablePathMTUDiscovery,
	}
	return nil
}

func (c *clientConfig) fillBandwidthConfig(hyConfig *client.Config) error {
	// New core now allows users to omit bandwidth values and use built-in congestion control
	return nil
}

func (c *clientConfig) fillFastOpen(hyConfig *client.Config) error {
	hyConfig.FastOpen = c.FastOpen
	return nil
}

// URI generates a URI for sharing the config with others.
// Note that only the bare minimum of information required to
// connect to the server is included in the URI, specifically:
// - server address
// - authentication
// - obfuscation type
// - obfuscation password
// - TLS SNI
// - TLS insecure
// - TLS pinned SHA256 hash (normalized)
func (c *clientConfig) URI() string {
	q := url.Values{}
	switch strings.ToLower(c.Obfs.Type) {
	case "salamander":
		q.Set("obfs", "salamander")
		q.Set("obfs-password", c.Obfs.Salamander.Password)
	}
	if c.TLS.SNI != "" {
		q.Set("sni", c.TLS.SNI)
	}
	if c.TLS.Insecure {
		q.Set("insecure", "1")
	}
	if c.TLS.PinSHA256 != "" {
		q.Set("pinSHA256", normalizeCertHash(c.TLS.PinSHA256))
	}
	var user *url.Userinfo
	if c.Auth != "" {
		// We need to handle the special case of user:pass pairs
		rs := strings.SplitN(c.Auth, ":", 2)
		if len(rs) == 2 {
			user = url.UserPassword(rs[0], rs[1])
		} else {
			user = url.User(c.Auth)
		}
	}
	u := url.URL{
		Scheme:   "hysteria2",
		User:     user,
		Host:     c.Server,
		Path:     "/",
		RawQuery: q.Encode(),
	}
	return u.String()
}

// parseURI tries to parse the server address field as a URI,
// and fills the config with the information contained in the URI.
// Returns whether the server address field is a valid URI.
// This allows a user to use put a URI as the server address and
// omit the fields that are already contained in the URI.
func (c *clientConfig) parseURI() bool {
	u, err := url.Parse(c.Server)
	if err != nil {
		return false
	}
	if u.Scheme != "hysteria2" && u.Scheme != "hy2" {
		return false
	}
	if u.User != nil {
		auth, err := url.QueryUnescape(u.User.String())
		if err != nil {
			return false
		}
		c.Auth = auth
	}
	c.Server = u.Host
	q := u.Query()
	if obfsType := q.Get("obfs"); obfsType != "" {
		c.Obfs.Type = obfsType
		switch strings.ToLower(obfsType) {
		case "salamander":
			c.Obfs.Salamander.Password = q.Get("obfs-password")
		}
	}
	if sni := q.Get("sni"); sni != "" {
		c.TLS.SNI = sni
	}
	if insecure, err := strconv.ParseBool(q.Get("insecure")); err == nil {
		c.TLS.Insecure = insecure
	}
	if pinSHA256 := q.Get("pinSHA256"); pinSHA256 != "" {
		c.TLS.PinSHA256 = pinSHA256
	}
	return true
}

// Config validates the fields and returns a ready-to-use Hysteria client config
func (c *clientConfig) Config() (*client.Config, error) {
	c.parseURI()
	hyConfig := &client.Config{}
	fillers := []func(*client.Config) error{
		c.fillServerAddr,
		c.fillConnFactory,
		c.fillAuth,
		c.fillTLSConfig,
		c.fillQUICConfig,
		c.fillBandwidthConfig,
		c.fillFastOpen,
	}
	for _, f := range fillers {
		if err := f(hyConfig); err != nil {
			return nil, err
		}
	}
	return hyConfig, nil
}

// parseServerAddrString parses server address string.
// Server address can be in either "host:port" or "host" format (in which case we assume port 443).
func parseServerAddrString(addrStr string) (host, port, hostPort string) {
	h, p, err := net.SplitHostPort(addrStr)
	if err != nil {
		return addrStr, "443", net.JoinHostPort(addrStr, "443")
	}
	return h, p, addrStr
}

// isPortHoppingPort returns whether the port string is a port hopping port.
// We consider a port string to be a port hopping port if it contains "-" or ",".
func isPortHoppingPort(port string) bool {
	return strings.Contains(port, "-") || strings.Contains(port, ",")
}

// normalizeCertHash normalizes a certificate hash string.
// It converts all characters to lowercase and removes possible separators such as ":" and "-".
func normalizeCertHash(hash string) string {
	r := strings.ToLower(hash)
	r = strings.ReplaceAll(r, ":", "")
	r = strings.ReplaceAll(r, "-", "")
	return r
}

type adaptiveConnFactory struct {
	NewFunc    func(addr net.Addr) (net.PacketConn, error)
	Obfuscator obfs.Obfuscator // nil if no obfuscation
}

func (f *adaptiveConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	if f.Obfuscator == nil {
		return f.NewFunc(addr)
	} else {
		conn, err := f.NewFunc(addr)
		if err != nil {
			return nil, err
		}
		return obfs.WrapPacketConn(conn, f.Obfuscator), nil
	}
}

type HysteriaOutbound struct {
	client client.Client
}

func (ho *HysteriaOutbound) TCP(reqAddr *AddrEx) (net.Conn, error) {
	url := reqAddr.Host
	if reqAddr.Port != 0 {
		url = url + ":" + strconv.Itoa(int(reqAddr.Port))
	}
	return ho.client.TCP(url)
}

func (ho *HysteriaOutbound) UDP(reqAddr *AddrEx) (UDPConn, error) {
	return nil, errors.New("not supported")
}

func (ho *HysteriaOutbound) Close() error {
	return ho.client.Close()
}

func NewHysteriaOutbound(proxyURL string) (*HysteriaOutbound, error) {
	clientConfig := &clientConfig{Server: proxyURL}
	if !clientConfig.parseURI() {
		return nil, errors.New("hysteria2 url invalid")
	}
	c, err := client.NewReconnectableClient(
		clientConfig.Config,
		func(c client.Client, info *client.HandshakeInfo, count int) {
		}, clientConfig.Lazy)
	if err != nil {
		return nil, err
	}
	return &HysteriaOutbound{client: c}, nil

}
