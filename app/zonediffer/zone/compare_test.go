package zone

import (
	"reflect"
	"testing"
)

func TestCompare(t *testing.T) {
	a := map[string]interface{}{
		"1": nil,
		"2": nil,
	}
	b := map[string]interface{}{
		"1": nil,
		"3": nil,
	}
	expectedA := []string{"2"}
	expectedB := []string{"3"}
	actualA, actualB := Compare(a, b)
	if !reflect.DeepEqual(expectedA, actualA) {
		t.Fatalf("expected A to be %+v, but got %+v", expectedA, actualA)
	}

	if !reflect.DeepEqual(expectedB, actualB) {
		t.Fatalf("expected B to be %+v, but got %+v", expectedB, actualB)
	}
}
