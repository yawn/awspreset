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
	errFailedToLoginWithPassword          = "failed to login with password"
	errFailedToParseRefererForOIDCState   = "failed to extract OIDC state from referer"
	errFailedToParseResetURL              = "failed to parse password reset url"
	errFailedToParseResponse              = "failed to parse response from sign-in API"
	errFailedToResetPassword              = "unexpected response to password reset: %q"
	errFailedToStartResetSequence         = "failed to initiate reset sequence"
	errFailedToStartSignInSequence        = "failed to initiate sign-in sequence"
	errPartialResponse                    = "failed to proceed after only receiving partial response from sign-in API: at least %q is missing from %q"
)

const (
	pathSignIn        = "signin"
	pathResetPassword = "resetpassword"
)

type oidcState struct {
	clientID            string
	codeChallengeMethod string
	codeChallenge       string
	redirectURL         string
}

// Session identifies a password reset request / response session
type Session struct {
	client    *http.Client
	oidcState *oidcState
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
			Timeout: time.Second * 10,
		},
	}

	return session, nil

}

func (s *Session) Login(email, password string, solver CaptchaSolver, otp func() string) error {

	res, err := s.doLoginWithEmail(email, solver)

	if err != nil {
		return err
	}

	captchaStatusToken := res.Properties["captchaStatusToken"].(string)

	if err := s.doLoginWithPassword(email, password, captchaStatusToken, otp); err != nil {
		return err
	}

	return nil

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

	// rebuild URL from scratch to avoid surprises
	resetURL = fmt.Sprintf("https://signin.aws.amazon.com/resetpassword?key=%s&token=%s", key, token)

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

	if _, err := s.doLoginWithEmail(email, solver); err != nil {
		return err
	}

	if err := s.doResetPassword(email, solver); err != nil {
		return err
	}

	return nil

}

func (s *Session) captcha(initial *response, params params, solver CaptchaSolver) (*response, error) {

	var response = initial

	for i := 0; true; i++ {

		for _, e := range []string{
			"captchaObfuscationToken",
			"CaptchaURL",
			"CES",
		} {

			if _, ok := response.Properties[e]; !ok {
				return nil, fmt.Errorf(errPartialResponse, e, response)
			}

		}

		var (
			captchaURL       = response.Properties["CaptchaURL"].(string)
			obfuscationToken = response.Properties["captchaObfuscationToken"].(string)
			token            = response.Properties["CES"].(string)
		)

		guess, err := solver(i, captchaURL)

		if err != nil {
			return nil, errors.Wrapf(err, errFailedToExecuteCaptchaSolver)
		}

		params["captcha_guess"] = guess
		params["captcha_token"] = token
		params["captchaObfuscationToken"] = obfuscationToken

		response, err = s.request(pathSignIn, params)

		if err != nil {
			return nil, err
		}

		if response.State == "SUCCESS" {
			return response, nil
		}

	}

	panic("should not be reached")

}

func (s *Session) extractCSRFToken(path string) (string, error) {

	// the csrf token and a session id (that is used by sign in via the console
	// but can be omitted) are both also availble in the document body as the
	// meta tags with names of csrf_token and session_id respectivly.

	for _, cookie := range s.client.Jar.Cookies(&url.URL{
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

func (s *Session) doLoginWithEmail(email string, solver CaptchaSolver) (*response, error) {

	logger("> log in with email %q", email)

	// implicitly this redirects to /oauth and /signin

	r, err := s.client.Get(`https://console.aws.amazon.com/console/home?hashArgs=%23a`)

	if err != nil {
		return nil, errors.Wrapf(err, errFailedToStartSignInSequence)
	}

	// extract OIDC state from implicit redirects and store it for usage in the actual login

	referer, err := url.Parse(r.Request.Referer())

	if err != nil {
		return nil, errors.Wrapf(err, errFailedToParseRefererForOIDCState)
	}

	query := referer.Query()

	s.oidcState = &oidcState{
		clientID:            query.Get("client_id"),
		codeChallenge:       query.Get("code_challenge"),
		codeChallengeMethod: query.Get("code_challenge_method"),
		redirectURL:         query.Get("redirect_uri"),
	}

	p := params{
		"action": "resolveAccountType",
		"email":  email,
	}

	res, err := s.request(pathSignIn, p)

	if err != nil {
		return nil, err
	}

	return s.captcha(res, p, solver)

}

func (s *Session) doLoginWithPassword(email, password, captchaStatusToken string, otp func() string) error {

	logger("> log in with password %x (otp %v)", password, otp)

	p := params{
		"action":                "authenticateRoot",
		"captcha_status_token":  captchaStatusToken,
		"client_id":             s.oidcState.clientID,
		"code_challenge_method": s.oidcState.codeChallengeMethod,
		"code_challenge":        s.oidcState.codeChallenge,
		"email":                 email,
		"mfaSerial":             "undefined",
		"password":              password,
		"redirect_uri":          s.oidcState.redirectURL,
	}

	// if no OTP is passed but required, the authentication will fail with a message "Your authentication information is incorrect. Please try again." - there is an MFA API available that will return the information that an MFA is registered / the type of the MFA but this is currently not implemented here

	if otp != nil {
		p["mfaType"] = "SW"
		p["mfa1"] = otp()
	}

	res, err := s.request(pathSignIn, p)

	if err != nil {
		return err
	}

	if res.State == "SUCCESS" {
		logger("< success %v", res)
		return nil
	}

	logger("< error %v", res)

	return fmt.Errorf(errFailedToLoginWithPassword)

}
func (s *Session) doResetPassword(email string, solver CaptchaSolver) error {

	res, err := s.request(pathSignIn, params{
		"action":         "captcha",
		"forgotpassword": "true",
	})

	if err != nil {
		return err
	}

	_, err = s.captcha(res, params{
		"action": "getResetPasswordToken",
		"email":  email,
	}, solver)

	return err
}

func (s *Session) request(path string, params map[string]string) (*response, error) {

	var response response

	csrf, err := s.extractCSRFToken(path)

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
