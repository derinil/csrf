# CSRF prevention library
This package provides a CSRF prevention system. It implements the double submit cookie pattern.

## The system works like so:
  - Create a session cookie via calculating the HMAC of current timestamp
    and a random hex string. Cookie will look like this: <hmac:timestamp:hex>
  - Then for each form, we generate a token using this cookie by calculating
    the HMAC of the cookie and timestamp, and inject the token into the 
    request context to be inserted in the HTML templates.
  - When validating the cookie, we first check if the timestamp and hex string
    match the HMAC, then we check if the cookie has not expired.
  - When validating a token, we follow the same protocol, but instead of
    a hex string we use the cookie.
