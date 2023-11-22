package gostashcat

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"golang.org/x/crypto/pbkdf2"
)

type ClientConfig struct {
	Email              string
	Password           string
	AppName            string
	APIURL             string
	CacheClientKeyPath string
	DeviceID           string
}

// Client for the stashcat API
type Client struct {
	config     ClientConfig
	clientKey  string
	privateKey rsa.PrivateKey
	deviceID   string
	debug      bool
	httpclient *http.Client
	UserInfo   User
	log        *log.Logger
}

type Status struct {
	Value        string          `json:"value"`
	ShortMessage json.RawMessage `json:"short_message"` // on some endpoints these are bool(false) instead of an empty string
	Message      json.RawMessage `json:"message"`
}

type StatusTyped struct {
	Value        string `json:"value"`
	ShortMessage string `json:"short_message"`
	Message      string `json:"message"`
}

type LoginResponsePayload struct {
	ClientKey string `json:"client_key"`
	UserInfo  User   `json:"userinfo"`
}

type LoginResponse struct {
	Status    Status               `json:"status"`
	Payload   LoginResponsePayload `json:"payload"`
	Signature string               `json:"signature"`
}

type Keys struct {
	UserID     string `json:"user_id"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_Key"`
}

type PrivateKeyResponsePayload struct {
	Keys Keys `json:"keys"`
}

type PrivateKeyResponse struct {
	Status    Status                    `json:"status"`
	Payload   PrivateKeyResponsePayload `json:"payload"`
	Signature string                    `json:"signature"`
}

type StatusResponse struct {
	Status json.RawMessage `json:"status"`
}

// CheckResponsePayload is the structure returned in the payload of a call to /auth/check
type CheckResponsePayload struct {
	Success bool `json:"success"`
}

// CheckResponse is the structure returned by a call to /auth/check
type CheckResponse struct {
	Status    Status               `json:"status"`
	Payload   CheckResponsePayload `json:"payload"`
	Signature string               `json:"signature"`
}

func New(cc ClientConfig) *Client {
	s := &Client{
		config:     cc,
		httpclient: &http.Client{},
		log:        log.New(os.Stderr, "gostashcat ", log.LstdFlags|log.Lshortfile|log.Lmsgprefix),
	}
	if s.config.DeviceID == "" {
		s.deviceID = strings.ReplaceAll(uuid.NewString(), "-", "")
	} else {
		s.deviceID = s.config.DeviceID
	}

	var err error

	if s.config.CacheClientKeyPath != "" {
		err = s.GetFromCache()
	} else {
		err = s.Login()
	}
	if err != nil {
		log.Fatalf("Unable to setup client: %v", err)
	}

	return s
}

func (api *Client) SetLogger(logger *log.Logger) {
	api.log = logger
}

// Debugf print a formatted debug line
func (api *Client) Debugf(format string, v ...interface{}) {
	if api.debug {
		api.log.Printf(format, v...)
	}
}

// Debugln print a debug line
func (api *Client) Debugln(v ...interface{}) {
	if api.debug {
		api.log.Println(v...)
	}
}

// SetDebug enables debug mode
func (api *Client) SetDebug() {
	api.debug = true
}

// GetFromCache retrieves the client_key from a cache file, validates it and
// does a login if validation does not succeed
func (api *Client) GetFromCache() error {
	data, err := os.ReadFile(api.config.CacheClientKeyPath)
	if err != nil {
		log.Printf("Unable to read clientKey from file %s due to %v", api.config.CacheClientKeyPath, err)
		return api.Login()
	}

	api.clientKey = string(data)
	valid, err := api.Check()
	if err != nil {
		return err
	}
	if valid {
		userMe, err := api.GetUserMe()
		api.UserInfo = userMe
		return err
	}

	api.Debugln("Cached client key was invalid or expired, relogin.")

	return api.Login()
}

// Login authenticates with the stashcat api
func (api *Client) Login() error {
	v := url.Values{}
	v.Set("email", api.config.Email)
	v.Set("password", api.config.Password)
	v.Set("device_id", api.deviceID)
	v.Set("app_name", api.config.AppName)
	v.Set("encrypted", strconv.FormatBool(true))
	v.Set("callable", strconv.FormatBool(false))
	v.Set("key_transfer_support", strconv.FormatBool(false))

	response := LoginResponse{}

	err := api.doPostRequest("auth/login", v, &response, false)
	if err != nil {
		return err
	}

	api.Debugln("Successfully logged in")

	api.clientKey = response.Payload.ClientKey
	api.UserInfo = response.Payload.UserInfo

	if api.config.CacheClientKeyPath != "" {
		err := os.WriteFile(api.config.CacheClientKeyPath, []byte(api.clientKey), 0600)
		if err != nil {
			return err
		}
		api.Debugf("Saved client key to cachefile: %s\n", api.config.CacheClientKeyPath)
	}

	return nil
}

// Check validates if the current client_key is still valid
func (api *Client) Check() (bool, error) {
	v := url.Values{}
	v.Set("client_key", api.clientKey)
	v.Set("device_id", api.deviceID)
	v.Set("app_name", api.config.AppName)
	v.Set("encrypted", strconv.FormatBool(true))
	v.Set("callable", strconv.FormatBool(false))
	v.Set("key_transfer_support", strconv.FormatBool(false))

	response := CheckResponse{}

	err := api.postMethod("auth/check", v, &response)
	if err != nil {
		return false, err
	}

	return response.Payload.Success, nil
}

type KeyDerivationProperties struct {
	Iterations int    `json:"iterations"`
	Prf        string `json:"prf"`
	Salt       string `json:"salt"`
}

type NestedKey struct {
	Ciphertext string                  `json:"ciphertext"`
	IV         string                  `json:"iv"`
	KDP        KeyDerivationProperties `json:"key_derivation_properties"`
}

// LoadPrivateKey retrieves the encrypted private key and decrypts it
func (api *Client) LoadPrivateKey(encryptionPassword string) error {
	v := url.Values{}
	v.Set("client_key", api.clientKey)
	v.Set("device_id", api.deviceID)
	v.Set("format", "jwk")
	v.Set("type", "encryption")

	response := PrivateKeyResponse{}
	err := api.postMethod("security/get_private_key", v, &response)
	if err != nil {
		api.Debugln("Request to get private key failed")
		return err
	}

	nestedKey := NestedKey{}
	err = json.Unmarshal([]byte(response.Payload.Keys.PrivateKey), &nestedKey)
	if err != nil {
		api.Debugf("Unmarshalling of private key object failed: %s", response.Payload.Keys.PrivateKey)
		return err
	}

	salt, err := base64.StdEncoding.DecodeString(nestedKey.KDP.Salt)
	if err != nil {
		api.Debugln("Decoding of salt from base64 failed")
		return err
	}

	derivedKey := pbkdf2.Key([]byte(encryptionPassword), salt, nestedKey.KDP.Iterations, 32, sha256.New)

	iv, err := base64.StdEncoding.DecodeString(nestedKey.IV)
	if err != nil {
		api.Debugln("Decoding of private key iv from base64 failed")
		return err
	}

	decodedCiphertext, err := base64.StdEncoding.DecodeString(nestedKey.Ciphertext)
	if err != nil {
		api.Debugln("Decoding of ciphertext from base64 failed")
		return err
	}

	cipherJWK, err := decryptAES(decodedCiphertext, iv, derivedKey)
	if err != nil {
		api.Debugln("Decryption of private key failed")
		return err
	}

	privkey, err := jwk.ParseKey([]byte(cipherJWK))
	if err != nil {
		api.Debugln("Decoding of jwk failed")
		return err
	}

	err = privkey.Raw(&api.privateKey)
	if err != nil {
		api.Debugln("Converting of JWK to rsa.PrivateKey failed")
		return err
	}
	return nil
}

func (api *Client) postRequest(ctx context.Context, path string, values url.Values) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, "POST", api.config.APIURL+path, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := api.httpclient.Do(request)
	if err != nil {
		return nil, err
	}
	// resp.Body gets closed in unmarshalStatus

	return resp, nil
}

func (api *Client) postRequestMultipart(ctx context.Context, path, boundary string, body io.Reader) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, "POST", api.config.APIURL+path, body)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Content-Type", fmt.Sprintf("multipart/form-data; boundary=%s", boundary))

	resp, err := api.httpclient.Do(request)
	if err != nil {
		return nil, err
	}
	// resp.Body gets closed in unmarshalStatus

	return resp, nil
}

func (api *Client) unmarshalStatus(resp *http.Response) ([]byte, bool, error) {
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, err
	}

	// Not all status objects have the same data types so it's needed to do some careful parsing here
	statusResponse := StatusResponse{}
	err = json.Unmarshal(body, &statusResponse)
	if err != nil {
		api.Debugf("Unmarshalling of response status failed: %s", string(body))
		return nil, false, err
	}

	statusValue := Status{}
	err = json.Unmarshal(statusResponse.Status, &statusValue)
	if err != nil {
		api.Debugf("Unmarshalling of response status value failed: %s", string(body))
		return nil, false, err
	}

	if statusValue.Value != "OK" {
		// ShortMessage and Message are only reliably a string if Value != "OK"
		statusTyped := StatusTyped{}
		err = json.Unmarshal(statusResponse.Status, &statusTyped)
		if err != nil {
			return nil, false, fmt.Errorf("Request to %s failed - decoding of status objects short_message and message failed as well: %s", resp.Request.URL.Path, err)
		}

		if statusTyped.ShortMessage == "auth_invalid" {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("Request to %s failed: %s - %s", resp.Request.URL.Path, statusTyped.ShortMessage, statusTyped.Message)
	}

	return body, false, nil
}

func (api *Client) unmarshalBody(body []byte, intf interface{}) error {
	bodyReader := strings.NewReader(string(body))

	err := json.NewDecoder(bodyReader).Decode(intf)
	if err != nil {
		api.Debugf("Unmarshalling of response body failed: %s", string(body))
		return err
	}
	return nil
}

func (api *Client) doPostRequest(path string, values url.Values, intf interface{}, retry bool) error {
	// TODO: expose timeout as parameter
	ctx, cncl := context.WithTimeout(context.Background(), 1*time.Second)
	defer cncl()

	resp, err := api.postRequest(ctx, path, values)
	if err != nil {
		return err
	}
	body, authExpired, err := api.unmarshalStatus(resp)
	if err != nil {
		return err
	}
	if authExpired && retry {
		api.Debugln("Login expired, retrying")
		// if authentication expired, relogin and retry the request once
		err = api.Login()
		if err != nil {
			return err
		}
		values.Set("client_key", api.clientKey)

		// if this keeps failing, dont retry as something is possibly wrong with the given credentials
		return api.doPostRequest(path, values, intf, false)
	}
	return api.unmarshalBody(body, intf)
}

// postMethod is a wrapper for querrying an API endpoint and unmarshalling the response to the given response object
func (api *Client) postMethod(path string, values url.Values, intf interface{}) error {
	return api.doPostRequest(path, values, intf, true)
}
