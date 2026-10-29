package prom

import (
	"net/http"
	"testing"
)

func TestPromAuthApply(t *testing.T) {
	cases := []struct {
		name       string
		auth       PromAuth
		wantHeader string
		wantValue  string
		wantCaveat bool
	}{
		{"none sets nothing", PromAuth{Mode: AuthNone}, "Authorization", "", false},
		{"static bearer", PromAuth{Mode: AuthBearerStatic, Token: "tok"}, "Authorization", "Bearer tok", false},
		{"sa bearer", PromAuth{Mode: AuthBearerSA, Token: "satok"}, "Authorization", "Bearer satok", false},
		{"scope orgid", PromAuth{Mode: AuthScopeOrgID, OrgID: "tenant-7"}, "X-Scope-OrgID", "tenant-7", false},
		{"sigv4 unimplemented records caveat", PromAuth{Mode: AuthSigV4, Region: "eu-central-1"}, "Authorization", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "http://x/api/v1/query", nil)
			cav := tc.auth.apply(req)
			if got := req.Header.Get(tc.wantHeader); got != tc.wantValue {
				t.Errorf("%s = %q, want %q", tc.wantHeader, got, tc.wantValue)
			}
			if (cav != "") != tc.wantCaveat {
				t.Errorf("caveat = %q, wantCaveat=%v", cav, tc.wantCaveat)
			}
		})
	}
}

func TestPromAuthBasic(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://x/api/v1/query", nil)
	PromAuth{Mode: AuthBasic, Username: "u", Password: "p"}.apply(req)
	user, pass, ok := req.BasicAuth()
	if !ok || user != "u" || pass != "p" {
		t.Errorf("BasicAuth = (%q,%q,%v), want (u,p,true)", user, pass, ok)
	}
}
