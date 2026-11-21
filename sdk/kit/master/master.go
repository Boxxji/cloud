package master

import (
	"testing"

	"github.com/hanzoai/cek"
)

func init() {
	if !testing.Testing() || cek.HasMaster() {
		return
	}
	if _, err := cek.SetDevMaster(); err != nil {
		panic("devmaster: " + err.Error())
	}
}
