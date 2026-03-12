package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeJSONBodyRejectsOversizedPayload(t *testing.T) {
	oversized := strings.Repeat("a", maxBodyBytes+1)
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"subject":{"user_id":"`+oversized+`"}}`))
	req.Header.Set("Content-Type", "application/json")

	var payload map[string]any
	if err := decodeJSONBody(req, &payload); err == nil {
		t.Fatal("expected oversized payload to be rejected")
	}
}
