package textutils

func Pad(s string, n int) string {
	for len(s) < n {
		s = " " + s
	}
	return s
}
