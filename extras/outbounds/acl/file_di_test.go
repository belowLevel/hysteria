package acl

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewFileDi(t *testing.T) {
	d, err := newFileDI("domf:domain.txt")
	assert.NoError(t, err)
	t.Logf("mem size %f MB", float32(d.Size())/1024/1024)
}
