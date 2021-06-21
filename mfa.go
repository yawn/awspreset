package awspreset

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"

	"github.com/pkg/errors"
)

const (
	errFailedToExtractConsoleCSRF = "failed to extract CSRF token from console HTML body"
	errFailedToEncodeRequest      = "failed to encode JSON request"
	errFailedToDecodeResponse     = "failed to decode JSON response"
)

type MFA struct {
	client *http.Client
	csrf   string
}

type CreateMFAResponse struct {
	Base32StringSeed string `json:"base32StringSeed"`
	SerialNumber     string `json:"serialNumber"`
}

type deactivateMFARequest struct {
	SerialNumber string `json:"serialNumber"`
	Username     string `json:"userName"`
}

type enableMFARequest struct {
	AuthenticationCode1 string `json:"authenticationCode1"`
	AuthenticationCode2 string `json:"authenticationCode2"`
	SerialNumber        string `json:"serialNumber"`
	UserName            string `json:"userName"`
}

func NewMFA(s *Session) (*MFA, error) {

	m := &MFA{
		client: s.client,
	}

	res, err := m.client.Get("https://console.aws.amazon.com/iam/home?region=eu-central-1&state=hashArgs%23%2Fsecurity_credentials")

	if err != nil {
		return nil, errors.Wrapf(err, errFailedRequest)
	}

	defer res.Body.Close()

	csrf, err := m.extractCSRFToken(res.Body)

	if err != nil {
		return nil, err
	}

	m.csrf = csrf

	return m, nil

}

func (m *MFA) DisableMFA(serialNumber string) error {

	var (
		buf = new(bytes.Buffer)
		enc = json.NewEncoder(buf)
	)

	if err := enc.Encode(&deactivateMFARequest{
		SerialNumber: serialNumber,
		Username:     "",
	}); err != nil {
		return errors.Wrapf(err, errFailedToEncodeRequest)
	}

	req, err := http.NewRequest("POST", "https://console.aws.amazon.com/iam/api/mfa/deactivateMfaDevice", buf)

	if err != nil {
		return errors.Wrapf(err, errFailedRequest)
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-CSRF-token", m.csrf)

	_, err = m.client.Do(req)

	if err != nil {
		return errors.Wrapf(err, errFailedRequest)
	}

	return nil

}

func (m *MFA) EnableMFA() (*CreateMFAResponse, error) {

	res, err := m.doCreateMFA()

	if err != nil {
		return nil, err
	}

	if err := m.doEnableMFA(res); err != nil {
		return res, err
	}

	return res, nil

}

func (m *MFA) doCreateMFA() (*CreateMFAResponse, error) {

	type createVirtualMFA struct {
		Path                 string `json:"path"`
		VirtualMFADeviceName string `json:"virtualMFADeviceName"`
	}

	var (
		buf      = new(bytes.Buffer)
		enc      = json.NewEncoder(buf)
		response CreateMFAResponse
	)

	if err := enc.Encode(&createVirtualMFA{
		Path:                 "/",
		VirtualMFADeviceName: "root-account-mfa-device",
	}); err != nil {
		return nil, errors.Wrapf(err, errFailedToEncodeRequest)
	}

	req, err := http.NewRequest("POST", "https://console.aws.amazon.com/iam/api/mfa/createVirtualMfa", buf)

	if err != nil {
		return nil, errors.Wrapf(err, errFailedRequest)
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-CSRF-token", m.csrf)

	res, err := m.client.Do(req)

	if err != nil {
		return nil, errors.Wrapf(err, errFailedRequest)
	}

	dec := json.NewDecoder(res.Body)

	if err := dec.Decode(&response); err != nil {
		return nil, errors.Wrapf(err, errFailedToDecodeResponse)
	}

	return &response, nil

}

func (m *MFA) doEnableMFA(c *CreateMFAResponse) error {

	var (
		buf      = new(bytes.Buffer)
		enc      = json.NewEncoder(buf)
		response CreateMFAResponse
	)

	codes, err := TOTP(c.Base32StringSeed)

	if err != nil {
		return err
	}

	if err := enc.Encode(&enableMFARequest{
		AuthenticationCode1: codes[0],
		AuthenticationCode2: codes[1],
		SerialNumber:        c.SerialNumber,
	}); err != nil {
		return errors.Wrapf(err, errFailedToEncodeRequest)
	}

	req, err := http.NewRequest("POST", "https://console.aws.amazon.com/iam/api/mfa/enableMfaDevice", buf)

	if err != nil {
		return errors.Wrapf(err, errFailedRequest)
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-CSRF-token", m.csrf)

	res, err := m.client.Do(req)

	if err != nil {
		return errors.Wrapf(err, errFailedRequest)
	}

	dec := json.NewDecoder(res.Body)

	if err := dec.Decode(&response); err != nil {
		return errors.Wrapf(err, errFailedToDecodeResponse)
	}

	return nil

}

func (m *MFA) extractCSRFToken(body io.Reader) (string, error) {

	var (
		buf = new(bytes.Buffer)
		exp = regexp.MustCompile(`<meta data-token='(.+)' id='xsrf-token'>`)
		r   = io.TeeReader(body, buf)
	)

	res, err := ioutil.ReadAll(r)

	if err != nil {
		return "", errors.Wrapf(err, errFailedToExtractConsoleCSRF)
	}

	token := exp.FindAllStringSubmatch(string(res), -1)[0][1]

	return token, nil

}
