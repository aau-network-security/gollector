package store

import (
	"testing"
)

func TestBatchEntities(t *testing.T) {
	be := NewBatchEntities(2)
	if be.IsFull() {
		t.Fatalf("expected batch entities to be not full, but it is")
	}
	if be.Len() != 0 {
		t.Fatalf("unexpected batch size: expected %d, but got %d", 0, be.Len())
	}

	be.certByFingerprint["fp1"] = &certstruct{}
	be.zoneEntries = append(be.zoneEntries, &zoneentrystruct{})

	if !be.IsFull() {
		t.Fatalf("expected batch entities to be full, but is not")
	}
	if be.Len() != 2 {
		t.Fatalf("unexpected batch size: expected %d, but got %d", 2, be.Len())
	}

	be.Reset()
	if be.IsFull() {
		t.Fatalf("expected batch entities to be not full, but it is")
	}
	if be.Len() != 0 {
		t.Fatalf("unexpected batch size: expected %d, but got %d", 0, be.Len())
	}
}
