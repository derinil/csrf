// csrf implements the CSRF prevention system.
package csrf

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// HandlerImpl handles CSRF cookie/token generation/validation.
type (
	Handler interface {
		CreateCookie() (string, error)
		CreateToken(cookie string) (string, error)
		ValidateCookie(cookie string) (bool, error)
		ValidateToken(token, cookie string) (bool, error)
		ValidateCookieToken(token, cookie string) (bool, error)
	}

	HandlerImpl struct {
		key []byte
	}
)

var Lifetime = 6 * time.Hour

var _ Handler = (*HandlerImpl)(nil)

// NewHandler panics if key is empty.
func NewHandler(key []byte) *HandlerImpl {
	if len(key) == 0 {
		panic("empty csrf key")
	}

	return &HandlerImpl{key: key}
}

// CreateCookie creates a cookie by combining a random hex string
// and the current UTC timestamp.
func (s *HandlerImpl) CreateCookie() (string, error) {
	hs, err := readHex(18)
	if err != nil {
		return "", fmt.Errorf("failed to read hex string: %w", err)
	}

	seconds := strconv.FormatInt(time.Now().Unix(), 10)

	h, err := s.calculateHMAC(seconds, hs)
	if err != nil {
		return "", fmt.Errorf("failed to calculate hmac: %w", err)
	}

	return fmt.Sprintf("%s:%s:%s", hex.EncodeToString(h), seconds, hs), nil
}

// CreateToken creates a token by combining the cookie and the current
// UTC timestamp.
func (s *HandlerImpl) CreateToken(cookie string) (string, error) {
	seconds := strconv.FormatInt(time.Now().Unix(), 10)

	h, err := s.calculateHMAC(seconds, cookie)
	if err != nil {
		return "", fmt.Errorf("failed to calculate hmac: %w", err)
	}

	return fmt.Sprintf("%s:%s", hex.EncodeToString(h), seconds), nil
}

// ValidateCookie validates a cookie based on the timestamp and
// random hex string stored in the cookie.
func (s *HandlerImpl) ValidateCookie(cookie string) (bool, error) {
	if cookie == "" {
		return false, nil
	}

	args := strings.Split(cookie, ":")
	if len(args) != 3 {
		return false, nil
	}

	var (
		hh      = args[0]
		seconds = args[1]
		hs      = args[2]
	)

	nh, err := s.calculateHMAC(seconds, hs)
	if err != nil {
		return false, fmt.Errorf("failed to calculate hmac: %w", err)
	}

	h, err := hex.DecodeString(hh)
	if err != nil {
		return false, nil
	}

	ss, err := strconv.ParseInt(seconds, 10, 64)
	if err != nil {
		return false, nil
	}

	t := time.Unix(ss, 0)

	if !hmac.Equal(h, nh) {
		return false, nil
	}

	return t.After(time.Now().Add(-Lifetime)), nil
}

// ValidateToken validates a token based on the given cookie and the
// timestamp stored in the token.
func (s *HandlerImpl) ValidateToken(token, cookie string) (bool, error) {
	if token == "" || cookie == "" {
		return false, nil
	}

	args := strings.Split(token, ":")
	if len(args) != 2 {
		return false, nil
	}

	var (
		hh      = args[0]
		seconds = args[1]
	)

	nh, err := s.calculateHMAC(seconds, cookie)
	if err != nil {
		return false, fmt.Errorf("failed to calculate hmac: %w", err)
	}

	h, err := hex.DecodeString(hh)
	if err != nil {
		return false, nil
	}

	ss, err := strconv.ParseInt(seconds, 10, 64)
	if err != nil {
		return false, nil
	}

	t := time.Unix(ss, 0)

	if !hmac.Equal(h, nh) {
		return false, nil
	}

	return t.After(time.Now().Add(-Lifetime)), nil
}

// ValidateCookieToken validates both cookie and token in the same function.
// This calls the ValidateCookie and ValidateToken functions, and only exists
// as a helper.
func (s *HandlerImpl) ValidateCookieToken(cookie, token string) (bool, error) {
	if cookie == "" || token == "" {
		return false, nil
	}

	ok, err := s.ValidateCookie(cookie)
	if err != nil {
		return false, err
	}

	if !ok {
		return false, nil
	}

	ok, err = s.ValidateToken(token, cookie)
	if err != nil {
		return false, err
	}

	return ok, nil
}

func (s *HandlerImpl) calculateHMAC(args ...string) ([]byte, error) {
	h := hmac.New(sha256.New, s.key)

	for _, a := range args {
		if _, err := fmt.Fprint(h, a); err != nil {
			return nil, fmt.Errorf("failed to write arg: %w", err)
		}
	}

	return h.Sum(nil), nil
}

func readHex(n int) (string, error) {
	buf := make([]byte, n)
	if rn, err := rand.Read(buf); err != nil {
		return "", err
	} else if rn != n {
		return "", fmt.Errorf("read incorrect number of bytes: %d", rn)
	}

	return hex.EncodeToString(buf), nil
}
