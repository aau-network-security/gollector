package zone

import (
	"io"
	"reflect"
	"testing"
	"time"
)

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

	if !reflect.DeepEqual(actualTlds, expectedTlds) {
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
		}
		if !reflect.DeepEqual(expectedEntries, actualEntries) {
			t.Fatalf("expected zone file entries to be %v, but got %v", expectedEntries, actualEntries)
		}
		i++
	}
}
