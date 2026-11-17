package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/paagoduura/provisioning/internal/domain"
)

func TestLaterSessionStageRoutesAreOwnerScopedAndReturnStableStateErrors(t *testing.T) {
	h := newTestHandler(testVerifier{"owner-token": "owner-1", "other-token": "owner-2"})
	session := createSessionForTest(t, h, "owner-token", "stage-route-contract")
	actions := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{name: "authenticate", body: `{"proof":"opaque-proof"}`, wantStatus: http.StatusConflict, wantCode: "STATE_CONFLICT"},
		{name: "token-request", body: "", wantStatus: http.StatusConflict, wantCode: "STATE_CONFLICT"},
		{name: "wrap-payload", body: "", wantStatus: http.StatusNotImplemented, wantCode: "STAGE_UNAVAILABLE"},
		{name: "transfer-apdu", body: "", wantStatus: http.StatusNotImplemented, wantCode: "STAGE_UNAVAILABLE"},
		{name: "verify-device", body: `{"proof":"opaque-proof"}`, wantStatus: http.StatusConflict, wantCode: "STATE_CONFLICT"},
		{name: "complete", body: "", wantStatus: http.StatusConflict, wantCode: "STATE_CONFLICT"},
	}
	for _, action := range actions {
		t.Run(action.name, func(t *testing.T) {
			path := "/v1/provisioning-sessions/" + session.ID + "/" + action.name
			request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(action.body))
			request.Header.Set("Authorization", "Bearer other-token")
			unauthorized := httptest.NewRecorder()
			h.Routes().ServeHTTP(unauthorized, request)
			if unauthorized.Code != http.StatusNotFound || strings.Contains(unauthorized.Body.String(), session.ID) {
				t.Fatalf("non-owner request status/body = %d %s, want opaque 404", unauthorized.Code, unauthorized.Body.String())
			}

			request = httptest.NewRequest(http.MethodPost, path, strings.NewReader(action.body))
			request.Header.Set("Authorization", "Bearer owner-token")
			response := httptest.NewRecorder()
			h.Routes().ServeHTTP(response, request)
			if response.Code != action.wantStatus {
				t.Fatalf("owner stage request status/body = %d %s, want %d", response.Code, response.Body.String(), action.wantStatus)
			}
			var payload map[string]string
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if payload["failure_code"] != action.wantCode || payload["detail"] != "" {
				t.Fatalf("stage error is not the stable, non-detail contract: %#v", payload)
			}
		})
	}
}

func TestStageProofValidationAndEmptyBodyContracts(t *testing.T) {
	h := newTestHandler(testVerifier{"owner-token": "owner-1"})
	session := createSessionForTest(t, h, "owner-token", "stage-validation-contract")
	cases := []struct {
		name   string
		action string
		body   string
	}{
		{name: "missing authentication proof", action: "authenticate", body: `{}`},
		{name: "blank authentication proof", action: "authenticate", body: `{"proof":"  "}`},
		{name: "unknown proof field", action: "verify-device", body: `{"proof":"p","request_hash":"caller-controlled"}`},
		{name: "oversized proof", action: "verify-device", body: `{"proof":"` + strings.Repeat("a", maxStageProofLength+1) + `"}`},
		{name: "body forbidden on token request", action: "token-request", body: `{}`},
		{name: "body forbidden on wrap", action: "wrap-payload", body: `null`},
		{name: "body forbidden on transfer", action: "transfer-apdu", body: `{"apdu":"00"}`},
		{name: "body forbidden on completion", action: "complete", body: `{}`},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/provisioning-sessions/"+session.ID+"/"+test.action, strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer owner-token")
			response := httptest.NewRecorder()
			h.Routes().ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("invalid contract input status/body = %d %s, want 400", response.Code, response.Body.String())
			}
		})
	}
}

func TestFailureStageRequiresStableCodeAndPersistsOnlyValidCode(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
		want int
	}{
		{name: "missing code", body: `{}`, want: http.StatusBadRequest},
		{name: "legacy code property rejected", body: `{"code":"USER_CANCELLED"}`, want: http.StatusBadRequest},
		{name: "lowercase rejected", body: `{"failure_code":"provider failure"}`, want: http.StatusBadRequest},
		{name: "unknown JSON field rejected", body: `{"failure_code":"USER_CANCELLED","detail":"sensitive"}`, want: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newTestHandler(testVerifier{"owner-token": "owner-1"})
			session := createSessionForTest(t, h, "owner-token", "failure-validation-"+strings.ReplaceAll(test.name, " ", "-"))
			request := httptest.NewRequest(http.MethodPost, "/v1/provisioning-sessions/"+session.ID+"/fail", strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer owner-token")
			response := httptest.NewRecorder()
			h.Routes().ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("invalid failure input returned %d, want %d: %s", response.Code, test.want, response.Body.String())
			}
			current, err := h.provisioning.Get(context.Background(), session.ID)
			if err != nil {
				t.Fatal(err)
			}
			if current.State != domain.StateCreated {
				t.Fatalf("invalid failure input changed state to %s", current.State)
			}
		})
	}

	h := newTestHandler(testVerifier{"owner-token": "owner-1"})
	session := createSessionForTest(t, h, "owner-token", "valid-failure-stage")
	request := httptest.NewRequest(http.MethodPost, "/v1/provisioning-sessions/"+session.ID+"/fail", strings.NewReader(`{"failure_code":"USER_CANCELLED"}`))
	request.Header.Set("Authorization", "Bearer owner-token")
	response := httptest.NewRecorder()
	h.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("valid failure action returned %d: %s", response.Code, response.Body.String())
	}
	current, err := h.provisioning.Get(context.Background(), session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.State != domain.StateFailed || current.FailureCode != "USER_CANCELLED" {
		t.Fatalf("valid failure action state/code = %s/%s", current.State, current.FailureCode)
	}
}

func TestStageErrorsNeverExposeUnderlyingProviderOrHardwareDetails(t *testing.T) {
	response := httptest.NewRecorder()
	writeProvisioningStageError(response, errors.New("provider secret key and raw APDU response"))
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unclassified stage failure status = %d, want 422", response.Code)
	}
	if strings.Contains(response.Body.String(), "provider secret") || strings.Contains(response.Body.String(), "APDU response") {
		t.Fatalf("stage error disclosed internal cause: %s", response.Body.String())
	}
}

func TestOpenAPIDocumentDeclaresImplementedStageRoutes(t *testing.T) {
	document, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI contract: %v", err)
	}
	text := string(document)
	if !strings.Contains(text, "openapi: 3.1.0") {
		t.Fatal("OpenAPI document must declare version 3.1.0")
	}
	for _, action := range []string{"authenticate", "token-request", "wrap-payload", "transfer-apdu", "verify-device", "complete", "fail"} {
		path := "/v1/provisioning-sessions/{session_id}/" + action + ":"
		if !strings.Contains(text, path) {
			t.Errorf("OpenAPI document does not declare implemented route %s", path[:len(path)-1])
		}
	}
}
