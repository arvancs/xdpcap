package internal

import (
	"github.com/arvancs/xdpcap"
	"github.com/cilium/ebpf"
	"testing"
)

const hookSymbol = "foo"

// Test CheckHookMap with valid and invalid HookMap ABI
func TestCheckHookMap(t *testing.T) {
	scpec := &ebpf.MapSpec{
		Name:       ebpf.SanitizeName(hookSymbol, '_'),
		Type:       xdpcap.HookMapABI.Type,
		KeySize:    xdpcap.HookMapABI.KeySize,
		ValueSize:  xdpcap.HookMapABI.ValueSize,
		MaxEntries: 4,
	}
	valid, err := ebpf.NewMap(scpec)
	if err != nil {
		t.Fatal(err)
	}
	defer valid.Close()

	if CheckHookMap(valid) != nil {
		t.Fatal(err)
	}

	scpec.Type = ebpf.Array
	inValid, err := ebpf.NewMap(scpec)
	if err != nil {
		t.Fatal(err)
	}
	defer inValid.Close()

	if CheckHookMap(inValid) == nil {
		t.Fatal("CheckHookMap expected to return error")
	}
}
