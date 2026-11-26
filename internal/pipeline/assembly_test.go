package pipeline

import (
	"strings"
	"testing"
)

func TestOrderStages_RefusesAMisdeclaration(t *testing.T) {
	nop := func(*assembly) {}
	for _, c := range []struct {
		name string
		decl []stage
		want string
	}{
		{"a need nothing provides", []stage{{name: "a", needs: []string{"x"}, run: nop}}, `a needs "x", which no stage provides`},
		{"two providers", []stage{{name: "a", provides: []string{"x"}, run: nop}, {name: "b", provides: []string{"x"}, run: nop}},
			`"x" is provided by both a and b`},
		{"the report provided again", []stage{{name: "a", provides: []string{keyReport}, run: nop}}, "provided by both the report itself and a"},
		{"a cycle", []stage{{name: "a", needs: []string{"y"}, provides: []string{"x"}, run: nop},
			{name: "b", needs: []string{"x"}, provides: []string{"y"}, run: nop}}, "a cycle among: a, b"},
	} {
		if _, err := orderStages(c.decl); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error containing %q", c.name, err, c.want)
		}
	}
}

func TestOrderStages_NeedsBeforeDeclaration(t *testing.T) {
	nop := func(*assembly) {}
	got, err := orderStages([]stage{
		{name: "late", needs: []string{"x"}, run: nop},
		{name: "early", provides: []string{"x"}, run: nop},
		{name: "free", run: nop},
	})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range got {
		names = append(names, s.name)
	}
	if strings.Join(names, ",") != "early,late,free" {
		t.Fatalf("order = %v, want early,late,free: a stage runs once its needs are met, the earliest declared first", names)
	}
}

// The declared assembly itself orders without error.
func TestAssemblyStages_AreWellDeclared(t *testing.T) {
	if _, err := orderStages(assemblyStages); err != nil {
		t.Fatal(err)
	}
}
