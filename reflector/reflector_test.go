package reflector

import (
	"strings"
	"testing"
)

func TestStartInvalidInterface(t *testing.T) {
	closer, err := Start("nonexistent_iface_9999")
	if err == nil {
		if closer != nil {
			_ = closer.Close()
		}
		t.Fatal("expected error for nonexistent interface, got nil")
	}
	if !strings.Contains(err.Error(), "nonexistent_iface_9999") && !strings.Contains(err.Error(), "only supported on linux") {
		t.Fatalf("unexpected error message: %v", err)
	}
}
