package redact

import (
	"fmt"
	"math/rand"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// regexpReplacer is buildReplacer as it was written first: one alternation of every identifier, longest first,
// matched by package regexp. It is kept here as the ORACLE the faster replacer is held to, byte for byte.
func regexpReplacer(idents map[string]string) func(string) string {
	keys := make([]string, 0, len(idents))
	for k := range idents {
		if k != "" {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return func(s string) string { return s }
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) > len(keys[j])
		}
		return keys[i] < keys[j]
	})
	quoted := make([]string, 0, len(keys))
	for _, k := range keys {
		quoted = append(quoted, regexp.QuoteMeta(k))
	}
	re := regexp.MustCompile(strings.Join(quoted, "|"))
	return func(s string) string {
		if s == "" {
			return s
		}
		var b strings.Builder
		last := 0
		for _, loc := range re.FindAllStringIndex(s, -1) {
			if loc[0] < last {
				continue
			}
			if loc[0] > 0 && wordChar.MatchString(s[loc[0]-1:loc[0]]) {
				continue
			}
			if loc[1] < len(s) && wordChar.MatchString(s[loc[1]:loc[1]+1]) {
				continue
			}
			b.WriteString(s[last:loc[0]])
			b.WriteString(idents[s[loc[0]:loc[1]]])
			last = loc[1]
		}
		if last == 0 {
			return s
		}
		b.WriteString(s[last:])
		return b.String()
	}
}

// THE REPLACER IS THE REGEXP ONE, TO THE BYTE, ON EVERY STRING.
//
// Identifiers that nest (svc-01 inside svc-01-a inside svc-01-ab), that share long prefixes, that contain the
// regexp's metacharacters, and that are one character long; strings that put them beside letters, digits,
// hyphens, dots, spaces and multi-byte runes, overlapping each other and abutting each other. Twenty thousand
// strings, each compared with what the alternation produced.
func TestBuildReplacer_IsTheAlternationToTheByte(t *testing.T) {
	r := rand.New(rand.NewSource(11))
	idents := map[string]string{}
	parts := []string{"svc", "team", "ip-10-0", "payments", "a", "1", "x.y", "web+api", "(db)", "café", "ns", "0"}
	for len(idents) < 400 {
		k := parts[r.Intn(len(parts))]
		for n := r.Intn(4); n > 0; n-- {
			k += []string{"-", ".", "", "_"}[r.Intn(4)] + parts[r.Intn(len(parts))]
		}
		idents[k] = fmt.Sprintf("tok-%04d", len(idents))
	}
	keys := make([]string, 0, len(idents))
	for k := range idents {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want, got := regexpReplacer(idents), buildReplacer(idents)
	glue := []string{" ", "-", ".", "", "x", "7", "/", "é", " ", ": ", "\xff"}
	for i := 0; i < 20000; i++ {
		var b strings.Builder
		for n := r.Intn(8); n >= 0; n-- {
			b.WriteString(glue[r.Intn(len(glue))])
			k := keys[r.Intn(len(keys))]
			if r.Intn(5) == 0 && len(k) > 1 {
				k = k[:1+r.Intn(len(k)-1)] // a prefix of an identifier, which is not one
			}
			b.WriteString(k)
		}
		s := b.String()
		if w, g := want(s), got(s); w != g {
			t.Fatalf("on %q\n the alternation gives %q\n the replacer gives   %q", s, w, g)
		}
	}
}
