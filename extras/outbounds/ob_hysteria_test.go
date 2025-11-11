package outbounds

import (
	"io"
	"testing"
)

func TestNewHy2(t *testing.T) {
	url := "hysteria2://6fxx8@xxx.xx.xx:443/"
	hyClient, err := NewHysteriaOutbound(url)
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer hyClient.Close()
	conn, err := hyClient.TCP(&AddrEx{
		Host:        "xx.com",
		Port:        80,
		ResolveInfo: nil,
		Txt:         "",
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	_, err = conn.Write([]byte("GET xx.com\r\n\r\n"))
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer conn.Close()
	bs, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Log(string(bs))

}
