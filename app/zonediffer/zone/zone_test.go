package zone

import (
	"io"
	"testing"
	"time"
)

func StringListEquals(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestNewZoneFileProvider(t *testing.T) {
	dir := "resources/"

	start, err := time.Parse("2006-01-02", "2021-02-01")
	if err != nil {
		t.Fatalf("unexpected error while parsing start time: %s", err)
	}

	end, err := time.Parse("2006-01-02", "2021-02-03")
	if err != nil {
		t.Fatalf("unexpected error while parsing start time: %s", err)
	}
	zfp, err := NewZonefileProvider(dir, start, end)
	if err != nil {
		t.Fatalf("unexpected error while creating zone file provider: %s", err)
	}

	actual := zfp.Count("com")
	expected := 0
	if actual != expected {
		t.Fatalf("expected %d .com zone files, but got %d", expected, actual)
	}

	// check the right number of zone files
	actual = zfp.Count("test")
	expected = 3
	if actual != expected {
		t.Fatalf("expected %d .test zone files, but got %d", expected, actual)
	}

	// check if the tlds are as expected
	actualTlds := zfp.Tlds()
	expectedTlds := []string{"test"}

	if !StringListEquals(actualTlds, expectedTlds) {
		t.Fatalf("expected tlds to be %v, but got %v", expectedTlds, actualTlds)
	}

	// (1) check for correctness of file names
	// (2) check for correct
	expectedZoneFileNames := []string{
		"resources/test.2021-02-01.gz",
		"resources/test.2021-02-02.gz",
		"resources/test.2021-02-03.gz",
	}
	expectedEntriesList := [][]string{
		{
			"example.test",
		}, {
			"example.test", "example2.test",
		}, {
			"example.test",
		},
	}
	expectedExpiredList := [][]string{
		{},
		{"example2.test"},
	}
	expectedRegisteredList := [][]string{
		{"example2.test"},
		{},
	}

	prevDomains := make(map[string]interface{})
	curDomains := make(map[string]interface{})

	i := 0
	for {
		zf, err := zfp.Next("test")
		if err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("unexpected error while obtaining zone files: %s", err)
			break
		}
		expectedName := expectedZoneFileNames[i]
		actualName := zf.Name()
		if expectedName != actualName {
			t.Fatalf("expected zone file name to be %s, but got %s", expectedName, actualName)
		}

		// iterative over entires in file
		expectedEntries := expectedEntriesList[i]
		var actualEntries []string
		for {
			zfe, err := zf.Next()
			if err == io.EOF {
				break
			} else if err != nil {
				t.Fatalf("unexpected error while obtaining entry from zone file: %s", err)
				break
			}
			actualEntries = append(actualEntries, zfe.Domain)
			// using a map also ensures that duplicate domains are only counted once
			curDomains[zfe.Domain] = nil
		}
		if !StringListEquals(expectedEntries, actualEntries) {
			t.Fatalf("expected zone file entries to be %v, but got %v", expectedEntries, actualEntries)
		}

		if i == 0 {
			prevDomains = curDomains
			curDomains = make(map[string]interface{})
			i++
			continue
		}

		actualExpired, actualRegistered := Compare(prevDomains, curDomains)
		expectedRegistered := expectedRegisteredList[i-1]
		expectedExpired := expectedExpiredList[i-1]
		if !StringListEquals(actualRegistered, expectedRegistered) {
			t.Fatalf("expected registered to be %v, but got %v", expectedRegistered, actualRegistered)
		}
		if !StringListEquals(actualExpired, expectedExpired) {
			t.Fatalf("expected expired to be %v, but got %v", expectedExpired, actualExpired)
		}

		prevDomains = curDomains
		curDomains = make(map[string]interface{})

		i++
	}
}
