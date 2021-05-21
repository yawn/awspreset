package awspreset

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	"github.com/pkg/errors"
)

const (
	errFailedRequest                      = "failed request to sign-in API"
	errFailedToCreateCookieJar            = "failed to create cookie jar"
	errFailedToExecuteCaptchaSolver       = "failed to execute captcha solver"
	errFailedToExtractCSRFTokenFromCookie = "failed to extract CSFR token from cookie"
	errFailedToParseResponse              = "failed to parse response from sign-in API"
	errFailedToStartResetSequence         = "failed to initiate reset sequence"
	errFailedToStartSignInSequence        = "failed to initiate sign-in sequence"
	errPartialResponse                    = "failed to proceed after only receiving partial response from sign-in API: at least %q is missing from %q"
	errFailedToParseResetURL              = "failed to parse password reset url"
	errFailedToResetPassword              = "unexpected response to password reset: %q"
)

const (
	pathSignIn        = "signin"
	pathResetPassword = "resetpassword"
)

// Session identifies a password reset request / response session
type Session struct {
	client    *http.Client
	csrfToken func(string) (string, error)
}

type params map[string]string

type response struct {
	Properties map[string]interface{} `json:"properties"`
	State      string                 `json:"state"`
}

// New generates a new password reset request / response session
func New() (*Session, error) {

	cookies, err := cookiejar.New(nil)

	if err != nil {
		return nil, errors.Wrapf(err, errFailedToCreateCookieJar)
	}

	session := &Session{
		client: &http.Client{
			Jar:     cookies,
			Timeout: time.Second * 5,
		},
	}

	// the csrf token and a session id (that is used by sign in via the console
	// but can be omitted) are both also availble in the document body as the
	// meta tags with names of csrf_token and session_id respectivly.

	session.csrfToken = func(path string) (string, error) {

		for _, cookie := range cookies.Cookies(&url.URL{
			Scheme: "https",
			Host:   "signin.aws.amazon.com",
			Path:   fmt.Sprintf("/%s", path),
		}) {

			if cookie.Name == "aws-signin-csrf" {
				return cookie.Value, nil
			}

		}

		return "", fmt.Errorf(errFailedToExtractCSRFTokenFromCookie)

	}

	return session, nil

}

// ResetResponse receives a password reset url and a new password to perform
// the actual password reset.
func (s *Session) ResetResponse(resetURL, newPassword string) error {

	parsed, err := url.Parse(resetURL)

	if err != nil {
		return errors.Wrapf(err, errFailedToParseResetURL)
	}

	var (
		key   = parsed.Query().Get("key")
		token = parsed.Query().Get("token")
	)

	_, err = s.client.Get(resetURL)

	if err != nil {
		return errors.Wrapf(err, errFailedToStartResetSequence)
	}

	res, err := s.request(pathResetPassword, params{
		"action":          "resetPasswordSubmitForm",
		"confirmpassword": newPassword,
		"key":             key,
		"newpassword":     newPassword,
		"token":           token,
		"type":            "RootUser",
	})

	if err != nil {
		return err
	}

	if res.State != "SUCCESS" {
		return fmt.Errorf(errFailedToResetPassword, res)
	}

	return nil

}

// ResetRequest receives a root email and a captcha solver to perform the
// request of the password reset url.
func (s *Session) ResetRequest(email string, solver CaptchaSolver) error {

	if err := s.doLoginWithEmail(email, solver); err != nil {
		return err
	}

	if err := s.doResetPassword(email, solver); err != nil {
		return err
	}

	return nil

}

func (s *Session) captcha(initial *response, params params, solver CaptchaSolver) error {

	var response = initial

	for i := 0; true; i++ {

		for _, e := range []string{
			"captchaObfuscationToken",
			"CaptchaURL",
			"CES",
		} {

			if _, ok := response.Properties[e]; !ok {
				return fmt.Errorf(errPartialResponse, e, response)
			}

		}

		var (
			captchaURL       = response.Properties["CaptchaURL"].(string)
			obfuscationToken = response.Properties["captchaObfuscationToken"].(string)
			token            = response.Properties["CES"].(string)
		)

		guess, err := solver(i, captchaURL)

		if err != nil {
			return errors.Wrapf(err, errFailedToExecuteCaptchaSolver)
		}

		params["captcha_guess"] = guess
		params["captcha_token"] = token
		params["captchaObfuscationToken"] = obfuscationToken

		response, err = s.request(pathSignIn, params)

		if err != nil {
			return err
		}

		if response.State == "SUCCESS" {
			break
		}

	}

	return nil

}

func (s *Session) doLoginWithEmail(email string, solver CaptchaSolver) error {

	// implicitly this redirects to /oauth and /signin

	_, err := s.client.Get(`https://console.aws.amazon.com/console/home?hashArgs=%23a`)

	if err != nil {
		return errors.Wrapf(err, errFailedToStartSignInSequence)
	}

	p := params{
		"action": "resolveAccountType",
		"email":  email,
	}

	res, err := s.request(pathSignIn, p)

	if err != nil {
		return err
	}

	return s.captcha(res, p, solver)

}

func (s *Session) doResetPassword(email string, solver CaptchaSolver) error {

	res, err := s.request(pathSignIn, params{
		"action":         "captcha",
		"forgotpassword": "true",
	})

	if err != nil {
		return err
	}

	return s.captcha(res, params{
		"action": "getResetPasswordToken",
		"email":  email,
	}, solver)

}

func (s *Session) request(path string, params map[string]string) (*response, error) {

	var response response

	csrf, err := s.csrfToken(path)

	if err != nil {
		return nil, err
	}

	// even though sessionId is used as part of the signin API it's not required

	form := url.Values{
		"csrf": {csrf},
	}

	for k, v := range params {
		form.Add(k, v)
	}

	res, err := s.client.PostForm(fmt.Sprintf("https://signin.aws.amazon.com/%s", path), form)

	if err != nil {
		return nil, errors.Wrapf(err, errFailedRequest)
	}

	dec := json.NewDecoder(res.Body)

	if err := dec.Decode(&response); err != nil {
		return nil, errors.Wrapf(err, errFailedToParseResponse)
	}

	return &response, nil

}
