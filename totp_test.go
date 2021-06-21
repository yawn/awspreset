package awspreset

import (
	"encoding/base32"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTOTP(t *testing.T) {

	// test vectors from https://datatracker.ietf.org/doc/html/rfc6238#appendix-B

	assert := assert.New(t)

	for k, v := range map[string][]string{
		"1970-01-01 00:00:59": []string{"287082"},
		"2005-03-18 01:58:29": []string{"081804", "050471"},
		"2009-02-13 23:31:30": []string{"005924"},
		"2033-05-18 03:33:20": []string{"279037"},
		"2603-10-11 11:33:20": []string{"353130"},
	} {

		now = func() (n time.Time) {
			n, _ = time.Parse("2006-01-02 15:04:05", k)
			return
		}

		secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

		codes, err := TOTP(secret)

		assert.NoError(err)
		assert.Len(codes, 2)

		assert.Equal(v[0], codes[0])

		if len(v) > 1 {
			assert.Equal(v[1], codes[1])
		}

		assert.NotEqual(codes[0], codes[1])

	}

}
