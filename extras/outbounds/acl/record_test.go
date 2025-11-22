package acl

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewRecord(t *testing.T) {
	reader, err := NewIPInstance("v2geo/country.mmdb")
	assert.NoError(t, err)
	ipReader = reader
	d, err := newRecord("record:domain.txt:and:!lan:!cn:!private")
	assert.NoError(t, err)
	if err == nil {
		t.Logf("mem size %f MB", float32(d.Size())/1024/1024)
	}
	domain := "google.com"
	t.Log(d.Match(&HostInfo{
		Name: domain,
		IPv4: nil,
		IPv6: nil,
	}))
	t.Log(d.Match(&HostInfo{
		Name: domain,
		IPv4: nil,
		IPv6: nil,
	}))
}
