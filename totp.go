package awspreset

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"github.com/pkg/errors"
)

var now = time.Now

const (
	digits   = 6
	timestep = 30
	values   = 2
)

const (
	errFailedToParseSecret = "failed to parse base32 encoded secret"
	errFailedToWriteHMAC   = "failed to write HMAC"
)

// TOTP generates OTPs suitable for usage in a virtual AWS root MFA device
func TOTP(secret string) ([]string, error) {

	k, err := base32.StdEncoding.DecodeString(secret)

	if err != nil {
		return nil, errors.Wrapf(err, errFailedToParseSecret)
	}

	var (
		codes []string
		t     = uint64(math.Floor(float64(now().Unix())) / timestep)
	)

	for i := uint64(0); i < values; i++ {

		h := hmac.New(sha1.New, k)

		if err := binary.Write(h, binary.BigEndian, t+i); err != nil {
			return nil, errors.Wrapf(err, errFailedToWriteHMAC)
		}

		var (
			result = h.Sum(nil)
			offset = result[len(result)-1] & 0xf
			code   = int64(
				((int(result[offset]) & 0x7f) << 24) |
					((int(result[offset+1] & 0xff)) << 16) |
					((int(result[offset+2] & 0xff)) << 8) |
					(int(result[offset+3]) & 0xff))
			mod = int32(code % int64(math.Pow10(digits)))
		)

		codes = append(codes, fmt.Sprintf(fmt.Sprintf("%%0%dd", digits), mod))

	}

	return codes, nil

}
