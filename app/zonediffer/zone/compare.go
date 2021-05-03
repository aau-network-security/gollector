package zone

// return two lists: one of elements only in a, and one of elements only in b
func Compare(a, b map[string]interface{}) ([]string, []string) {
	// copy b in c
	c := make(map[string]interface{})
	for k := range b {
		c[k] = nil
	}

	var onlyA []string
	for v := range a {
		if _, ok := c[v]; ok {
			// element from a also in b
			delete(c, v)
		} else {
			// element from a *not* in b
			onlyA = append(onlyA, v)
		}
	}

	// b now consist of elements only in b
	var onlyB []string
	for v := range c {
		onlyB = append(onlyB, v)
	}

	return onlyA, onlyB
}
