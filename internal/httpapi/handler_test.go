package httpapi

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/paagoduura/provisioning/internal/adapters/memory"
	"github.com/paagoduura/provisioning/internal/adapters/mock"
	"github.com/paagoduura/provisioning/internal/service"
)

func TestRoutes(t *testing.T) {
	log := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	h := New(log, service.New(memory.NewSessionRepository(), mock.CryptoService{}, mock.InterswitchAdapter{}, nil), 1<<20)
	ts := httptest.NewServer(h.Routes())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}
