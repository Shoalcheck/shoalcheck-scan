package prom

import (
	"fmt"
	"net/http"
)

// PromAuthMode is the auth axis — the ONLY thing that differs across
// Prometheus/Thanos/Mimir/VictoriaMetrics/Grafana-Cloud/AMP/GMP/Azure-managed/
// OpenShift, which all speak PromQL over /api/v1/query.
type PromAuthMode string

const (
	AuthNone         PromAuthMode = "none"        // in-cluster / unauthenticated
	AuthBearerSA     PromAuthMode = "sa-bearer"   // in-cluster SA token
	AuthBearerStatic PromAuthMode = "bearer"      // OpenShift route token
	AuthBasic        PromAuthMode = "basic"       // Grafana Cloud
	AuthScopeOrgID   PromAuthMode = "scope-orgid" // Cortex/Mimir X-Scope-OrgID
	AuthSigV4        PromAuthMode = "sigv4"       // AWS AMP (signing not built in P1)
	AuthGCPOAuth2    PromAuthMode = "gcp-oauth2"  // GMP (OAuth2 not built in P1)
	AuthEntra        PromAuthMode = "entra"       // Azure Monitor managed Prometheus (not built in P1)
)

// PromAuth carries the resolved auth for one endpoint. Built by cmd/shoalcheck from
// flags/env; pipeline threads it through. The OSS tree holds NO cloud SDK, so
// the signing/OAuth modes are recorded as a caveat rather than silently faking
// a credential — honest "this backend needs auth we didn't apply".
type PromAuth struct {
	Mode                             PromAuthMode
	Token, Username, Password, OrgID string
	Region, AWSProfile               string // SigV4 (future)
	GCPProject                       string // GMP (future)
}

// apply mutates req per the mode and returns a non-empty caveat string when the
// mode is recognized but NOT implemented in the OSS tree (no SDK). An empty
// caveat means the request was fully prepared.
func (a PromAuth) apply(req *http.Request) (caveat string) {
	switch a.Mode {
	case "", AuthNone:
		return ""
	case AuthBearerSA, AuthBearerStatic:
		if a.Token != "" {
			req.Header.Set("Authorization", "Bearer "+a.Token)
		}
		return ""
	case AuthBasic:
		req.SetBasicAuth(a.Username, a.Password)
		return ""
	case AuthScopeOrgID:
		if a.OrgID != "" {
			req.Header.Set("X-Scope-OrgID", a.OrgID)
		}
		return ""
	case AuthSigV4, AuthGCPOAuth2, AuthEntra:
		return fmt.Sprintf("auth mode %q requires a cloud credential not applied by the OSS client — endpoint may reject the request", a.Mode)
	default:
		return fmt.Sprintf("unknown auth mode %q — request sent unauthenticated", a.Mode)
	}
}
