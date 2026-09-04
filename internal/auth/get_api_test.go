package auth

import (
	"errors"
	"net/http"
	"testing"
)

// TestGetAPIKey_MissingAuthorizationHeader verifies that GetAPIKey returns
// ErrNoAuthHeaderIncluded when the request has no Authorization header set.
func TestGetAPIKey_MissingAuthorizationHeader(t *testing.T) {
	headers := http.Header{}

	returnedKey, returnedError := GetAPIKey(headers)

	if !errors.Is(returnedError, ErrNoAuthHeaderIncluded) {
		t.Errorf("expected error %q, got %q", ErrNoAuthHeaderIncluded, returnedError)
	}

	if returnedKey != "" {
		t.Errorf("expected empty API key, got %q", returnedKey)
	}
}

// TestGetAPIKey_MalformedAuthorizationHeader verifies that GetAPIKey returns
// a malformed header error when the Authorization header does not follow
// the "ApiKey <key>" format.
func TestGetAPIKey_MalformedAuthorizationHeader(t *testing.T) {
	malformedHeaderValues := []string{
		"ApiKey",
		"Bearer somekey123",
		"justarandomvalue",
	}

	for _, headerValue := range malformedHeaderValues {
		headers := http.Header{}
		headers.Set("Authorization", headerValue)

		returnedKey, returnedError := GetAPIKey(headers)

		if returnedError == nil {
			t.Errorf("expected an error for header value %q, got nil", headerValue)
		}

		if returnedKey != "" {
			t.Errorf("expected empty API key for header value %q, got %q", headerValue, returnedKey)
		}
	}
}

// TestGetAPIKey_ValidAuthorizationHeader verifies that GetAPIKey correctly
// extracts the API key from a well-formed "ApiKey <key>" Authorization header.
func TestGetAPIKey_ValidAuthorizationHeader(t *testing.T) {
	expectedKey := "test-api-key-123"

	headers := http.Header{}
	headers.Set("Authorization", "ApiKey "+expectedKey)

	returnedKey, returnedError := GetAPIKey(headers)

	if returnedError != nil {
		t.Errorf("expected no error, got %q", returnedError)
	}

	if returnedKey != expectedKey {
		t.Errorf("expected API key %q, got %q", expectedKey, returnedKey)
	}
}
