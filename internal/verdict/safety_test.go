package verdict

import "testing"

// A COMMAND'S VERB READS AS ENGLISH. The safety sentence built "the command patchs something".
func TestThirdPerson_TheVerbsTheSafetySentenceUses(t *testing.T) {
	for v, want := range map[string]string{"patch": "patches", "delete": "deletes", "apply": "applies",
		"set": "sets", "evict": "evicts", "taint": "taints", "drain": "drains"} {
		if got := thirdPerson(v); got != want {
			t.Errorf("thirdPerson(%q) = %q, want %q", v, got, want)
		}
	}
}
