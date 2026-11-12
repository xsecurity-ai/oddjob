"""What a task's credentials become in its arguments.

Pure function of the credential rows: no server, no database, no port.
The matching rule (which credentials belong to which target) is tested
against the API by apitest; this is the folding itself — the part that
decides what actually goes on the wire, and where a wrong kind mapping
means a bearer token sent as basic auth or a cookie line split in two.
"""
import pathlib as _pathlib
import sys as _sys

_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))

from app.credauth import build_from_credentials, host_of  # noqa: E402

passed = failed = 0


def check(label, cond, got=None):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS  {label}" + (f" {got}" if got is not None else ""))
    else:
        failed += 1
        print(f"  FAIL  {label}" + (f" {got}" if got is not None else ""))


class C:
    """A credential row, for the parts `build_from_credentials` reads."""

    def __init__(self, kind="password", username=None, secret=None):
        self.kind = kind
        self.username = username
        self.secret = secret


print("== kind to argument mapping ==")

a = build_from_credentials([C("password", "admin", "s3cret")])
args = a.as_args()
check("password -> basic auth header",
      args.get("headers") == ["Authorization: Basic YWRtaW46czNjcmV0"],
      args.get("headers"))
check("password -> username for gobuster", args.get("username") == "admin")
check("password -> password for gobuster", args.get("password") == "s3cret")

a = build_from_credentials([C("token", None, "abc123")])
check("token -> bearer header",
      a.as_args().get("headers") == ["Authorization: Bearer abc123"])

a = build_from_credentials([C("key", None, "sk_live_9")])
check("key -> bearer header",
      a.as_args().get("headers") == ["Authorization: Bearer sk_live_9"])

a = build_from_credentials([C("cookie", None, "session=xyz; path=/")])
check("cookie -> cookies string",
      a.as_args().get("cookies") == "session=xyz; path=/")

a = build_from_credentials([C("cookie", "PHPSESSID", "deadbeef")])
check("cookie with username -> name=value",
      a.as_args().get("cookies") == "PHPSESSID=deadbeef")

a = build_from_credentials([C("other", None, "X-Api-Key: 42")])
check("other -> raw header line",
      a.as_args().get("headers") == ["X-Api-Key: 42"])

a = build_from_credentials([C("other", None, "no-colon-here")])
check("other without colon is skipped, not guessed", a.as_args() == {})

a = build_from_credentials([C("hash", "user", "5f4dcc3b5aa7")])
# Presented as basic auth: the server asks for it over HTTP and this is
# what katana can send. A hash that needs cracking is not sent anywhere.
check("hash -> presented as basic auth",
      a.as_args().get("username") == "user"
      and a.as_args().get("headers") == ["Authorization: Basic dXNlcjo1ZjRkY2MzYjVhYTc="],
      a.as_args())

a = build_from_credentials([C("password", None, "orphan-secret")])
check("password without username sends nothing (no invented account)",
      a.as_args() == {})

print("\n== folding several credentials ==")

a = build_from_credentials([
    C("password", "admin", "s3cret"),
    C("token", None, "tok1"),
    C("cookie", None, "sid=9"),
])
args = a.as_args()
check("two headers both present",
      args.get("headers") == ["Authorization: Basic YWRtaW46czNjcmV0",
                              "Authorization: Bearer tok1"],
      args.get("headers"))
check("cookie appended separately", args.get("cookies") == "sid=9")
check("username/password survive the fold",
      args.get("username") == "admin" and args.get("password") == "s3cret")

a = build_from_credentials([C("cookie", None, "a=1"), C("cookie", None, "b=2")])
check("two cookies both sent", a.as_args().get("cookies") == "a=1; b=2")

print("\n== host_of ==")
check("plain name", host_of("api.acme.example") == "api.acme.example")
check("url -> host", host_of("https://api.acme.example:8443/x") == "api.acme.example")
check("uppercased input lowercased", host_of("API.ACME.EXAMPLE") == "api.acme.example")
check("userinfo stripped", host_of("http://u:p@api.acme.example/") == "api.acme.example")
check("port stripped", host_of("api.acme.example:8080") == "api.acme.example")
check("empty -> None", host_of("") is None)
check("garbage -> None or short", host_of("   ") is None)

print(f"\n{passed} passed, {failed} failed")
_sys.exit(1 if failed else 0)
