package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"log"
	"math"
	"net/url"
	"strings"
	"time"
)

// Algorithm to be used for hashing
type Algorithm int

const (
	//SHA1 algorithm to used for hashing
	SHA1 Algorithm = 1 + iota
	//SHA256 algorithm will be used for hashing
	SHA256
	//SHA512 algorithm will be used for hashing
	SHA512
)

// Totp will be generated time based onetime passwords
type Totp struct {
	secret    string
	digits    int
	period    int
	algorithm Algorithm
}

// Create will create a otp for a given time
func (o *Totp) Create(t time.Time) (string, error) {
	return o.generate(int(t.Unix()) / o.period)
}

// Validate the otp for a given time with the given leniency
func (o *Totp) Validate(token string, t time.Time, leniency time.Duration) bool {
	times := sequence(t.Add(-leniency), t.Add(leniency), time.Second*time.Duration(o.period))
	for _, t := range times {
		if vtok, _ := o.generate(int(t.Unix()) / o.period); vtok == token {
			return true
		}
	}
	return false
}

func (o *Totp) generate(inputValue int) (string, error) {
	if inputValue < 0 {
		return "", errors.New("Invalid input")
	}
	key, err := base32.StdEncoding.DecodeString(o.secret)
	if err != nil {
		log.Println("generate : unable to decode secret", err)
		return "", err
	}
	var hash hash.Hash
	if o.algorithm == SHA1 {
		hash = hmac.New(sha1.New, key)
	} else if o.algorithm == SHA256 {
		hash = hmac.New(sha256.New, key)
	} else if o.algorithm == SHA512 {
		hash = hmac.New(sha512.New, key)
	}

	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, uint64(inputValue))
	hash.Write(bs)
	hmacHash := hash.Sum(nil)

	offset := int(hmacHash[len(hmacHash)-1] & 0xf)
	code := ((int(hmacHash[offset]) & 0x7f) << 24) |
		((int(hmacHash[offset+1] & 0xff)) << 16) |
		((int(hmacHash[offset+2] & 0xff)) << 8) |
		(int(hmacHash[offset+3]) & 0xff)

	code = code % int(math.Pow10(o.digits))
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", o.digits), code), nil
}

// URI returns the URI for QR code generation
func (o *Totp) URI(accountName, issuerName string) string {

	params := make([]string, 0)
	// GoogleAuthenticator is not friendly to padding. So removing the = padding from secret
	params = append(params, "secret="+strings.Replace(o.secret, "=", "", -1))

	label := url.QueryEscape(accountName)
	if issuerName != "" {
		issuerNameEscape := url.QueryEscape(issuerName)
		params = append(params, "issuer="+issuerNameEscape)
	}

	if o.algorithm == SHA1 {
		params = append(params, "algorithm=SHA1")
	} else if o.algorithm == SHA256 {
		params = append(params, "algorithm=SHA256")
	} else if o.algorithm == SHA512 {
		params = append(params, "algorithm=SHA512")
	}
	if o.digits != 0 && o.digits != 6 {
		params = append(params, fmt.Sprintf("digits=%d", o.digits))
	}
	if o.period != 0 && o.period != 30 {
		params = append(params, fmt.Sprintf("period=%d", o.period))
	}
	return fmt.Sprintf("otpauth://%s/%s?%s", "totp", label, strings.Join(params, "&"))
}

// NewTOTP will return the pointer to Otp object
// For now we only support sha512.
func NewTOTP(secret string, digits, period int, algorithm Algorithm) *Totp {
	return &Totp{secret: base32.StdEncoding.EncodeToString([]byte(secret)), digits: digits, period: period, algorithm: algorithm}
}
