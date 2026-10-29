package collect

import "fmt"

// nWord says a count with its noun — "1 pod", "3 pods". A reading is read by people and quoted word for word, and
// "1 pod(s)" is the engine's grammar, not an answer. The same helper lives in internal/rules.
func nWord[N ~int | ~int32 | ~int64](n N, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
