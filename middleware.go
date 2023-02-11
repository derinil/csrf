package csrf

import (
	"context"
	"net/http"
)

type (
	CtxKey string
	// CookieFunc should return a HTTP cookie that holds the cookie value.
	CookieFunc func(cookie string) *http.Cookie
)

var (
	// CookieName is the name of the session cookie. You can override this.
	CookieName string = "csrf"
	// FormName is the name of the token field in the HTTP form. You can override this.
	FormName string = "csrf_token"
	// TokenKey is the key for the token in the request context. You can override this.
	TokenKey CtxKey = "csrf_token"
)

// ValidateCSRF validates the CSRF token passed in the request form data
// along with the CSRF cookie. Upon failure, it calls the fail http.Handler.
func ValidateCSRF(csrfHandler Handler, fail http.Handler) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie(CookieName)
			if err != nil {
				fail.ServeHTTP(w, r)
				return
			}

			var (
				cookie = c.Value
				token  = r.FormValue(FormName)
			)

			if ok, err := csrfHandler.ValidateCookieToken(cookie, token); err != nil || !ok {
				fail.ServeHTTP(w, r)
				return
			}

			h.ServeHTTP(w, r)
		})
	}
}

// InjectCSRF injects a CSRF token into the request context, and sets
// the CSRF cookie if it does not already exist.
// Keep in mind that if generating token fails, this will ignore it and
// serve the request without injecting the token into the context.
func InjectCSRF(csrfHandler Handler, cookieFunc CookieFunc) func(http.Handler) http.Handler {
	if cookieFunc == nil {
		cookieFunc = func(cookie string) *http.Cookie {
			return &http.Cookie{
				Name:  CookieName,
				Value: cookie,
			}
		}
	}

	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var cookie string

			if c, err := r.Cookie(CookieName); err != nil || c == nil {
				cookie = c.Value

				if ok, err := csrfHandler.ValidateCookie(cookie); err != nil || !ok{
					cookie = ""
				}
			}
			
			if cookie == "" {
				cookie, err := csrfHandler.CreateCookie()
				if err != nil {
					h.ServeHTTP(w, r)
					return
				}

				http.SetCookie(w, cookieFunc(cookie))
			}
			
			token, err := csrfHandler.CreateToken(cookie)
			if err != nil {
				h.ServeHTTP(w, r)
				return
			}

			r = r.WithContext(context.WithValue(r.Context(), TokenKey, token))

			h.ServeHTTP(w, r)
		})
	}
}
