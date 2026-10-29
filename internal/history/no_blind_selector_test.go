package history

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// THE STORE MUST NOT OFFER A SELECTOR THAT IGNORES CLUSTER IDENTITY.
//
// Until 2026-09-10 it did, and the hazard was not theoretical: `Store.Latest(cluster, before)` returned the
// newest file in slug(Cluster.Name)'s directory, and that directory holds every cluster whose display name
// slugs the same way. `shoalcheck audit` and the desktop app both asked it for "the prior reading" and got a
// stranger's — the comparison gates then refused, correctly, and named somebody else's cluster as the
// reason. The listing had been honest about the mixture since ClusterRef.DistinctUIDs; only the selection
// was not.
//
// WHY THIS SHAPE OF GATE. The fix could have been "call LatestOf at the three known call sites", which is a
// gate that must enumerate the callers it distrusts — and the next caller written is invisible to it. This
// asserts instead that the identity-blind API DOES NOT EXIST. A caller with no identity passes "" and that
// choice is legible in its own diff (cmd/shoalcheck/reading.go does, with the reason written above the call).
//
// It names the two exported selectors rather than a pattern, because a selector is not a shape: it is a
// method on Store that returns an *types.AuditReport, and the honest way to keep this list current is to
// fail when a new one appears.
func TestStore_HasNoIdentityBlindSelector(t *testing.T) {
	const allowed = "LatestOf" // takes a uid; "" means "no identity", not "any cluster"

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var offenders []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, f, src, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Name == nil || !fn.Name.IsExported() {
				continue
			}
			if !receiverIsStore(fn.Recv) || !returnsAuditReport(fn.Type.Results) {
				continue
			}
			if fn.Name.Name == allowed || takesAUID(fn.Type.Params) {
				continue
			}
			// Load(path) is addressed by path, which IS an identity: the caller already chose one file.
			if hasStringParamNamed(fn.Type.Params, "path") {
				continue
			}
			offenders = append(offenders, fn.Name.Name+" at "+fset.Position(fn.Pos()).String())
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("Store offers %d selector(s) that return a reading without asking WHICH CLUSTER: %s\n"+
			"A history directory is keyed on the cluster's display name, so it can hold more than one "+
			"cluster. Take a uid parameter (see LatestOf) — \"\" is how a caller says it has no identity, "+
			"and it must say so at the call site.", len(offenders), strings.Join(offenders, ", "))
	}
}

func receiverIsStore(recv *ast.FieldList) bool {
	if recv == nil || len(recv.List) != 1 {
		return false
	}
	t := recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	id, ok := t.(*ast.Ident)
	return ok && id.Name == "Store"
}

func returnsAuditReport(res *ast.FieldList) bool {
	if res == nil {
		return false
	}
	for _, f := range res.List {
		star, ok := f.Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		sel, ok := star.X.(*ast.SelectorExpr)
		if ok && sel.Sel != nil && sel.Sel.Name == "AuditReport" {
			return true
		}
	}
	return false
}

func takesAUID(params *ast.FieldList) bool {
	return hasStringParamNamed(params, "uid")
}

func hasStringParamNamed(params *ast.FieldList, want string) bool {
	if params == nil {
		return false
	}
	for _, f := range params.List {
		id, ok := f.Type.(*ast.Ident)
		if !ok || id.Name != "string" {
			continue
		}
		for _, n := range f.Names {
			if n != nil && n.Name == want {
				return true
			}
		}
	}
	return false
}
