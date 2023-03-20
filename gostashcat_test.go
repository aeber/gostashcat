package gostashcat

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRequestOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello world")
	}))
	defer srv.Close()

	config := ClientConfig{
		APIURL:   srv.URL,
		Email:    "email",
		Password: "password",
		AppName:  "RequestOK",
	}

	c := &Client{
		config:     config,
		httpclient: &http.Client{},
		deviceID:   strings.ReplaceAll(uuid.NewString(), "-", ""),
		log:        log.New(os.Stderr, "gostashcat ", log.LstdFlags|log.Lshortfile|log.Lmsgprefix),
	}
	_, err := c.postRequest(context.Background(), "/", url.Values{})
	if err != nil {
		t.Errorf("Expected err to be nil, got %v", err)
	}
}

func TestRequestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		fmt.Fprintf(w, "hello world")
	}))
	defer srv.Close()

	config := ClientConfig{
		APIURL:   srv.URL,
		Email:    "email",
		Password: "password",
		AppName:  "TimeoutTest",
	}

	c := &Client{
		config:     config,
		httpclient: &http.Client{},
		deviceID:   strings.ReplaceAll(uuid.NewString(), "-", ""),
		log:        log.New(os.Stderr, "gostashcat ", log.LstdFlags|log.Lshortfile|log.Lmsgprefix),
	}
	ctx, cncl := context.WithTimeout(context.Background(), 1*time.Second)
	defer cncl()
	_, err := c.postRequest(ctx, "/", url.Values{})
	if err == nil {
		t.Fatal("Expected err to be non nil")
	}

	switch v := err.(type) {
	case *url.Error:
		if err.(*url.Error).Timeout() != true {
			t.Fatalf("Expected request to have timed out, got %v", err)
		}
	default:
		t.Fatalf("Expected to get url.Error, got %v - %v", v, err)
	}
}

func TestAuthExpired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "{\"status\":{\"value\":\"FAILED\", \"short_message\":\"auth_invalid\", \"message\":\"\"}, \"payload\": {\"success\": false}, \"signature\": \"asdf\"}")
	}))
	defer srv.Close()

	config := ClientConfig{
		APIURL:   srv.URL,
		Email:    "email",
		Password: "password",
		AppName:  "AuthExpired",
	}

	c := &Client{
		config:     config,
		httpclient: &http.Client{},
		deviceID:   strings.ReplaceAll(uuid.NewString(), "-", ""),
		log:        log.New(os.Stderr, "gostashcat ", log.LstdFlags|log.Lshortfile|log.Lmsgprefix),
	}
	resp, err := c.postRequest(context.Background(), "/", url.Values{})
	if err != nil {
		t.Errorf("Expected post err to be nil, got %v", err)
		return
	}
	_, authExpired, err := c.unmarshalStatus(resp)
	if err != nil {
		t.Errorf("Expected status unmarshal err to be nil, got %v", err)
		return
	}
	if authExpired != true {
		t.Errorf("Expected status to be evaluated as expired authentication")
	}
}

func TestRequestWithValues(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Fatalf("Expected POST method, got %s", r.Method)
		}
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/x-www-form-urlencoded" {
			t.Fatalf("Expected 'application/x-www-form-urlencoded' content type, got '%s'", contentType)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("Could not parse formadata, %v", err)
		}
		firstField := r.Form.Get("first")
		if firstField != "YES" {
			t.Fatalf("Expected form field 'first'='YES', got '%s'", firstField)
		}
		secondField := r.Form.Get("second")
		if secondField != "NO" {
			t.Fatalf("Expected form field 'second'='NO', got '%s'", secondField)
		}
	}))
	defer srv.Close()

	config := ClientConfig{
		APIURL:   srv.URL,
		Email:    "email",
		Password: "password",
		AppName:  "RequestWithValues",
	}

	c := &Client{
		config:     config,
		httpclient: &http.Client{},
		deviceID:   strings.ReplaceAll(uuid.NewString(), "-", ""),
		log:        log.New(os.Stderr, "gostashcat ", log.LstdFlags|log.Lshortfile|log.Lmsgprefix),
	}
	v := url.Values{}
	v.Set("first", "YES")
	v.Set("second", "NO")
	_, err := c.postRequest(context.Background(), "/", v)
	if err != nil {
		t.Errorf("Expected post err to be nil, got %v", err)
		return
	}
}
