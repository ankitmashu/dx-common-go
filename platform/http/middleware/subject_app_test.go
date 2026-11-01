package middleware_test

import (
	"net/http/httptest"
	"testing"

	"github.com/datakaveri/dx-common-go/auth"
	"github.com/datakaveri/dx-common-go/platform/http/middleware"
	"github.com/datakaveri/dx-common-go/platform/security/identity"
)

// An application credential becomes a KindApp delegation naming the app,
// with the app's scopes — also when the app has none (Java: no scopes means
// forScopes refuses; it must not read as a plain user).
func TestSubjectFromAppCredential(t *testing.T) {
	for _, scopes := range [][]auth.DelegationScopeEntry{{{Scope: "data-access"}}, nil} {
		r := httptest.NewRequest("GET", "/", nil)
		r = r.WithContext(auth.WithUser(r.Context(), auth.DxUser{ID: "owner-1", Roles: []string{"consumer"}, AppID: "app-1", Scopes: scopes}))
		s, ok := middleware.SubjectFrom(r)
		if !ok || s.ID != "owner-1" || s.Delegation == nil || s.Delegation.Kind != identity.KindApp ||
			s.Delegation.Actor != "app-1" || len(s.Delegation.Scopes) != len(scopes) {
			t.Fatalf("scopes %v: subject = %+v (delegation %+v)", scopes, s, s.Delegation)
		}
	}
}
