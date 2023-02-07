package csrf_test

import (
	"strings"
	"testing"

	"github.com/derinil/csrf"
)

func must(s string, err error) string {
	if err != nil {
		panic(err)
	}

	return s
}

func TestValidate(t *testing.T) {
	csrf := csrf.NewHandler([]byte("kolizeykalibri"))

	var (
		c1 = must(csrf.CreateCookie())
		t1 = must(csrf.CreateToken(c1))
		c2 = must(csrf.CreateCookie())
		t2 = must(csrf.CreateToken(c2))
	)

	testCases := []struct {
		name   string
		cookie string
		token  string
		err    string
		pass   bool
	}{
		{
			name:   "valid cookie and token",
			cookie: c1,
			token:  t1,
			pass:   true,
		},
		{
			name:   "another valid cookie and token",
			cookie: c2,
			token:  t2,
			pass:   true,
		},
		{
			name:   "mismatched cookie and token",
			cookie: c1,
			token:  t2,
		},
		{
			name:   "another mismatched cookie and token",
			cookie: c2,
			token:  t1,
		},
		{
			name:   "fake cookie",
			cookie: "oj1n2bodfu1hcw0ih8jq0in310fni1w3f:1675120950:5a04839a344f621b694b674bb577456948a9",
			token:  t1,
		},
		{
			name:   "another fake cookie",
			cookie: "987a7edff1a43258cc8273d35ad7f85e4eaf401c4b5d706ab23139fca34245df:1n1o21ido1io2:5a04839a344f621b694b674bb577456948a9",
			token:  t1,
		},
		{
			name:   "cookie with too many separators",
			cookie: "sadasdasd:987a7edff1a43258cc8273d35ad7f85e4eaf401c4b5d706ab23139fca34245df:1n1o21ido1io2:5a04839a344f621b694b674bb577456948a9",
			token:  t1,
		},
		{
			name:   "cookie with insufficient separators",
			cookie: "1n1o21ido1io2:5a04839a344f621b694b674bb577456948a9",
			token:  t1,
		},
		{
			name:   "fake token",
			cookie: c1,
			token:  "o1n3 ofun1o3uhdf10o3iudfh103d:1675120950",
		},
		{
			name:   "another fake token",
			cookie: c1,
			token:  "b3f6373bfdf879ca247eb1951e9ca526ad314b14d399d53acecc15321e087807:1odunb1o3udn1",
		},
		{
			name:   "token with too many separators",
			cookie: c1,
			token:  "b3f6373bfdf879ca247eb1951e9ca526ad314b14d399d53acecc15321e087807:1675120950:b3f6373bfdf879ca247eb1951e9ca526ad314b14d399d53acecc15321e087807",
		},
		{
			name:   "token with insufficient separators",
			cookie: c1,
			token:  "1675120950",
		},
		{
			name:   "token with completely wrong format",
			cookie: c2,
			token:  "hello there!",
		},
		{
			name:   "empty token",
			cookie: c2,
			token:  "",
		},
		{
			name:   "cookie with completely wrong format",
			cookie: "tutankhamun",
			token:  t2,
		},
		{
			name:   "empty cookie",
			cookie: "",
			token:  t2,
		},
		{
			name:   "empty cookie and token",
			cookie: "",
			token:  "",
		},
	}

	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			ok, err := csrf.ValidateCookieToken(c.cookie, c.token)
			if err != nil || c.err != "" {
				if err != nil && c.err == "" {
					t.Fatal(err, "error is empty")
				}
				if !strings.Contains(err.Error(), c.err) {
					t.FailNow()
				}
			}
			if c.pass != ok {
				t.Fatal("pass != ok")
			}
		})
	}
}
