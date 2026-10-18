"""Declarative site-configuration spec.

The API serves this to the UI, which renders the form from it. Adding a
setting means adding one entry here — no new endpoint, no new form field, no
migration.
"""
from __future__ import annotations

SPEC = [
    # ---------------------------------------------------------------- site
    {"key": "site.name", "group": "Site", "label": "Site name",
     "type": "text", "default": "Oddjob"},
    {"key": "site.base_url", "group": "Site", "label": "Base URL",
     "type": "text", "default": "http://127.0.0.1:8000",
     "help": "The canonical address of this deployment, e.g. "
             "https://oddjob.corp.example. Links in emails are built from "
             "it — a wrong value makes magic-link sign-in unusable, because "
             "the link goes somewhere the recipient cannot reach. It also "
             "drives the security headers: serving it over https turns on "
             "HSTS and marks cookies Secure."},
    {"key": "site.extra_origins", "group": "Site",
     "label": "Additional allowed origins", "type": "text", "default": "",
     "help": "Comma separated. Only needed when a browser loads the UI from "
             "somewhere other than the base URL — a separate dev server, or "
             "a second hostname. Each one is permitted to send credentialed "
             "requests, so keep the list short."},
    {"key": "site.hsts_days", "group": "Site",
     "label": "HSTS max-age (days)", "type": "number", "default": 365,
     "help": "Only sent when the base URL is https. 0 disables it. A browser "
             "that has seen this header refuses to talk to the host over "
             "http for that long, which is the point and also why it is not "
             "something to switch on casually behind a proxy you do not "
             "control."},
    {"key": "site.frame_ancestors", "group": "Site",
     "label": "Allow framing by", "type": "text", "default": "",
     "help": "Empty means nothing may frame this app, which is the right "
             "answer unless you are embedding it. Set an origin to permit "
             "one."},
    {"key": "vulnfeed.enabled", "group": "Site",
     "label": "Keep exploit and CVE data current", "type": "bool",
     "default": False,
     "help": "Syncs Exploit-DB and NVD into this database daily, so a "
             "version can be matched against public exploits WITHOUT "
             "sending that version to anybody. Off by default because the "
             "first NVD sync fetches about 290,000 records and some "
             "deployments have no outbound internet at all."},
    {"key": "vulnfeed.nvd_api_key", "group": "Site",
     "label": "NVD API key", "type": "secret",
     "help": "Optional, and free from nvd.nist.gov. Without one NVD allows "
             "5 requests per 30 seconds, which makes a first sync take "
             "hours; with one it allows 50."},
    # --------------------------------------------------------- geoip
    {"key": "geoip.enabled", "group": "Site",
     "label": "Geolocate addresses (MaxMind GeoLite2)", "type": "bool",
     "default": False,
     "help": "Looks up which country, city and network an address belongs "
             "to, using databases this installation downloads with your own "
             "MaxMind licence key. Lookups are LOCAL — no address from the "
             "engagement is ever sent to MaxMind. The only outbound request "
             "is for the database files themselves, which carry no addresses "
             "with them. Needs a free GeoLite2 account."},
    {"key": "geoip.account_id", "group": "Site",
     "label": "MaxMind account ID", "type": "text", "default": "",
     "help": "The numeric account id from your MaxMind account page, e.g. "
             "123456. Used with the licence key as HTTP basic auth on the "
             "download."},
    {"key": "geoip.license_key", "group": "Site",
     "label": "MaxMind licence key", "type": "secret",
     "help": "From your MaxMind account. Stored here rather than in a file "
             "on the host, and never written to a log or an audit entry."},
    {"key": "geoip.editions", "group": "Site",
     "label": "GeoLite2 editions", "type": "text",
     "default": "GeoLite2-ASN GeoLite2-City GeoLite2-Country",
     "help": "Space or comma separated, matching the EditionIDs line in "
             "MaxMind's own GeoIP.conf. City answers country too and is "
             "27 MB against Country's 3 MB, so an installation that only "
             "wants a country code can drop it."},
    # ------------------------------------------------- socks proxy
    # The only listener in this product that carries somebody else's
    # traffic. Off, bound to loopback, and saying so where it is
    # switched on rather than in a docstring nobody opens.
    {"key": "proxy.enabled", "group": "Site",
     "label": "SOCKS5 proxy through ghosts", "type": "bool",
     "default": False,
     "help": "Lets an operator point a browser at Oddjob and have the "
             "requests come out of a Ghost — inside the estate, from the "
             "address the client already sees. READ THIS BEFORE ENABLING: "
             "this is a proxy INTO a client's network. Every connection "
             "needs a per-ghost credential, is ruled on by the scope gate "
             "and is recorded, and each ghost must be switched on "
             "separately — but if a credential leaks, whoever has it "
             "reaches whatever that ghost reaches. Off until somebody "
             "decides otherwise."},
    {"key": "proxy.bind", "group": "Site",
     "label": "Proxy listen address", "type": "text",
     "default": "0.0.0.0",
     "help": "Which interface the listener binds INSIDE the container — "
             "not on the host. That distinction is the whole of this "
             "setting and it reads backwards: 127.0.0.1 here is the "
             "CONTAINER's loopback, and Docker forwards a published port "
             "to the container's bridge address, so a published 8443 "
             "finds nothing listening and every connection is reset. "
             "That is exactly what happened: the port looked open on the "
             "host, `ss` showed it LISTEN, and nothing answered. "
             "0.0.0.0 is therefore the default for a containerised "
             "deployment, and it does NOT publish anything — what the "
             "outside can reach is decided by the ports mapping in "
             "docker-compose.yml, which binds the host's 127.0.0.1 "
             "unless PROXY_BIND_ADDRESS says otherwise. Running Oddjob "
             "directly on a host rather than in a container is the case "
             "where 127.0.0.1 here means what it looks like it means."},
    {"key": "proxy.port", "group": "Site",
     "label": "Proxy port", "type": "number", "default": 8443,
     "help": "Not 443. A browser pointed at a SOCKS proxy speaks raw "
             "SOCKS5 — no TLS, no SNI — and nginx routes 443 by SNI, so "
             "there is nothing for it to match on and the two cannot "
             "share a port without a demuxer nginx does not have. This "
             "port carries both SOCKS5 and CONNECT-over-TLS: Oddjob "
             "demuxes them on the first byte, which nginx cannot do."},
    {"key": "proxy.tls_cert", "group": "Site",
     "label": "Proxy TLS certificate", "type": "text", "default": "",
     "help": "Path, inside the container, to a certificate for this "
             "host. Setting it turns on CONNECT-over-TLS on the same "
             "port, which is what lets a browser be pointed straight at "
             "Oddjob instead of through an SSH tunnel: the credential "
             "then travels inside TLS instead of in clear, which is "
             "what SOCKS5 cannot offer. It must be a certificate the "
             "browser already trusts — there is no click-through for a "
             "proxy the way there is for a page. Empty means SOCKS "
             "only, reachable through a tunnel."},
    {"key": "proxy.tls_key", "group": "Site",
     "label": "Proxy TLS key", "type": "text", "default": "",
     "help": "Path, inside the container, to the private key for the "
             "certificate above. Both must be set or neither does "
             "anything."},
    # ----------------------------------------- certificate transparency
    # The one source here that SENDS something. Everything else in
    # this file either stays local (geoip looks up a database this
    # host downloaded) or fetches a feed that carries no engagement
    # data with it (NVD). A CT query names the client.
    #
    # So the help text says what leaves, where it goes, and who has
    # to agree first -- in the place somebody turns it on, not in a
    # module docstring they will never open.
    {"key": "ct.enabled", "group": "Site",
     "label": "Certificate Transparency lookups", "type": "bool",
     "default": False,
     "help": "Finds hostnames from public certificate logs — including "
             "hosts that never resolved publicly and long-dead hosts whose "
             "infrastructure is still up, which nothing else here can see. "
             "READ THIS BEFORE ENABLING: unlike every other source in "
             "Oddjob, a lookup SENDS THE CLIENT'S DOMAIN NAME to a third "
             "party, which logs it. That is customer data leaving for an "
             "external service, so it needs the same approval any other "
             "vendor would — an engagement signoff covers testing the "
             "client, not onboarding a supplier. Off until somebody "
             "decides otherwise."},
    {"key": "ct.source", "group": "Site",
     "label": "Certificate Transparency source", "type": "text",
     "default": "",
     "help": "Which third party the domain is sent to. Deliberately has no "
             "default: choosing it IS the decision. Currently supported: "
             "crt.sh. Names found are reported for a person to rule on and "
             "are never turned into targets on their own — a shared or "
             "wildcard certificate names other people's hosts, and a name "
             "in a log is not evidence anybody agreed to be scanned."},
    {"key": "audit.retain_days", "group": "Site",
     "label": "Audit retention (days)", "type": "number", "default": 7,
     "help": "How long /audit/<type>/<format> keeps entries, where type is "
             "ui, backend, middleware or ghost. This table grows with "
             "traffic rather than with the engagement, so it is swept at "
             "startup and once a day. 0 or less is treated as the default "
             "rather than as 'keep nothing' — a window of zero would "
             "delete the entry recording the change that set it."},

    # ------------------------------------------------------------ identity
    {"key": "auth.allow_self_registration", "group": "Identity",
     "label": "Allow self-registration", "type": "bool", "default": False,
     "help": "Off: only an administrator creates accounts. Google sign-in is "
             "governed separately below."},
    {"key": "auth.google_enabled", "group": "Identity", "label": "Google SSO enabled",
     "type": "bool", "default": False,
     "help": "Cannot be switched on until Test passes — otherwise the sign-in "
             "button appears for everyone and fails for everyone."},
    {"key": "auth.google_client_id", "group": "Identity", "label": "OAuth client ID",
     "type": "text", "default": "",
     "help": "From the Google Cloud console. Falls back to "
             "ODDJOB_GOOGLE_CLIENT_ID when left empty."},
    {"key": "auth.google_client_secret", "group": "Identity",
     "label": "OAuth client secret", "type": "secret",
     "help": "Falls back to ODDJOB_GOOGLE_CLIENT_SECRET when never set."},
    {"key": "auth.google_domains", "group": "Identity",
     "label": "Allowed email domains", "type": "text", "default": "",
     "help": "Comma separated, e.g. acme.example. EMPTY MEANS ANY GOOGLE "
             "ACCOUNT CAN REGISTER — they join no groups and see nothing, but "
             "they do get an account."},
    {"key": "auth.google_redirect_uri", "group": "Identity",
     "label": "OAuth redirect URI", "type": "text",
     "default": "http://127.0.0.1:8000/api/auth/google/callback",
     "help": "Must match exactly what is registered in the Google console."},

    # ---------------------------------------------------------------- smtp
    {"key": "smtp.host", "group": "Email (SMTP)", "label": "Host", "type": "text", "default": ""},
    {"key": "smtp.port", "group": "Email (SMTP)", "label": "Port", "type": "number",
     "default": 587},
    {"key": "smtp.security", "group": "Email (SMTP)", "label": "Security", "type": "select",
     "options": ["starttls", "tls", "none"], "default": "starttls"},
    {"key": "smtp.username", "group": "Email (SMTP)", "label": "Username",
     "type": "text", "default": ""},
    {"key": "smtp.password", "group": "Email (SMTP)", "label": "Password", "type": "secret"},
    {"key": "smtp.from_address", "group": "Email (SMTP)", "label": "From address",
     "type": "text", "default": "", "help": "Used for invitations and magic sign-in links."},

    # ------------------------------------------------------------- database
    {"key": "db.external_url", "group": "Database",
     "label": "Customer Postgres connection string", "type": "dsn",
     "help": "postgresql://user:password@host:5432/dbname — or the libpq "
             "keyword form. The password is masked everywhere it is shown; "
             "the host, user and database stay visible so you can see what "
             "you are pointed at. Test must pass before it can be saved."},
    {"key": "db.external_note", "group": "Database", "label": "Note",
     "type": "text", "default": "",
     "help": "Free text — whose database this is, who to ask, ticket number."},

    # ---------------------------------------------------------------- agent
    {"key": "agent.provider", "group": "Agent", "label": "Provider",
     "type": "select", "options": ["anthropic", "openai", "local"],
     "default": "anthropic",
     "help": "Only the selected provider's settings are shown. 'local' is "
             "any server speaking the OpenAI chat-completions API — Ollama, "
             "LM Studio, llama.cpp, vLLM, LocalAI."},

    {"key": "agent.anthropic_token", "group": "Agent",
     "label": "Anthropic API key or OAuth token", "type": "secret",
     "show_if": {"agent.provider": "anthropic"},
     "help": "An sk-ant-… API key, or an sk-ant-oat…/OAuth token from "
             "`claude setup-token`. The token type is detected from its "
             "prefix and the right auth header is used — they are not "
             "interchangeable."},
    {"key": "agent.anthropic_model", "group": "Agent", "label": "Anthropic model",
     "type": "text", "default": "claude-sonnet-5-5",
     "show_if": {"agent.provider": "anthropic"}},

    {"key": "agent.openai_token", "group": "Agent", "label": "OpenAI API key",
     "type": "secret", "show_if": {"agent.provider": "openai"},
     "help": "sk-… from platform.openai.com."},
    {"key": "agent.openai_model", "group": "Agent", "label": "OpenAI model",
     "type": "text", "default": "gpt-4o",
     "show_if": {"agent.provider": "openai"}},

    {"key": "agent.local_base_url", "group": "Agent", "label": "Local server URL",
     "type": "text", "default": "http://localhost:11434/v1",
     "show_if": {"agent.provider": "local"},
     "help": "Ollama http://localhost:11434/v1 · LM Studio "
             "http://localhost:1234/v1 · llama.cpp http://localhost:8080/v1 · "
             "vLLM http://localhost:8000/v1. The server reaches this, not "
             "your browser, so it must be reachable from wherever Oddjob runs."},
    {"key": "agent.local_model", "group": "Agent", "label": "Local model",
     "type": "text", "default": "qwen3",
     "show_if": {"agent.provider": "local"},
     "help": "The name the server knows it by — `ollama list` shows yours. "
             "Pick one with tool-calling support, or the agent can answer "
             "but never look anything up."},
    {"key": "agent.local_token", "group": "Agent",
     "label": "API key (optional)", "type": "secret",
     "show_if": {"agent.provider": "local"},
     "help": "Most local servers need none. Set it if yours is behind a "
             "proxy that wants a bearer token."},
    {"key": "agent.max_steps", "group": "Agent",
     "label": "Maximum tool calls per message", "type": "number", "default": 12,
     "help": "A hard stop on the agent's tool loop. Without one a confused "
             "model can spend an afternoon and a lot of money going in circles."},
    {"key": "agent.auto_remediation", "group": "Agent",
     "label": "Write remediation for findings that have none", "type": "bool",
     "default": True,
     "help": "One finding at a time, worst first, in the background. Does "
             "nothing until an agent is configured. Existing remediation "
             "from a scanner is never overwritten."},
    {"key": "agent.remediation_min_severity", "group": "Agent",
     "label": "Lowest severity to write remediation for", "type": "select",
     "options": ["critical", "high", "medium", "low", "info"], "default": "low",
     "help": "Informational entries are usually coverage records — writing "
             "remediation for \u201cswept this /24\u201d is nonsense, and on a "
             "real estate they are most of the backlog."},
    {"key": "agent.remediation_delay", "group": "Agent",
     "label": "Seconds between findings", "type": "number", "default": 2,
     "help": "A deliberate pause so a long backlog does not saturate a "
             "shared model server or a rate-limited API."},

    {"key": "agent.allow_writes", "group": "Agent",
     "label": "Let the agent change data", "type": "bool", "default": False,
     "help": "Off: the agent can read the project and answer questions but "
             "cannot create, edit or delete anything. Turn it on only when "
             "you want it filing findings and adding targets on your behalf."},

    # --------------------------------------------------------------- slack
    {"key": "slack.bot_token", "group": "Slack", "label": "Bot token", "type": "secret",
     "help": "xoxb-… Used to create a channel per engagement."},
    {"key": "slack.channel_prefix", "group": "Slack", "label": "Channel prefix",
     "type": "text", "default": "eng-",
     "help": "A new project FALCON-1 would get #eng-falcon-1."},
    {"key": "slack.default_private", "group": "Slack",
     "label": "New channels are private by default", "type": "bool", "default": True,
     "help": "Engagement channels carry findings and credentials, so the safe "
             "default is private. A project may override this individually."},
    {"key": "slack.auto_create_channel", "group": "Slack",
     "label": "Create a channel per new project", "type": "bool", "default": False},
    {"key": "slack.app_token", "group": "Slack", "label": "App-level token",
     "type": "secret",
     "help": "xapp-… with connections:write. Only needed to ANSWER questions: "
             "the bot opens a websocket to Slack, so nothing has to be "
             "exposed to the internet."},
    {"key": "slack.answer_questions", "group": "Slack",
     "label": "Answer questions when mentioned", "type": "bool", "default": False,
     "help": "The bot replies in-thread when someone @-mentions it, using the "
             "agent and only the data of the engagement that channel belongs "
             "to. Mentions only — reading every message would send the "
             "channel's whole conversation to a model. The sender must be a "
             "Slack account linked to an Oddjob user with access to that "
             "engagement; anyone else is told to link their account and "
             "nothing runs for them."},
    {"key": "slack.chat_follow_threads", "group": "Slack",
     "label": "Follow up in threads it is already in", "type": "bool",
     "default": True,
     "help": "In a thread the bot was @-mentioned into, a reply needs no "
             "second mention — which is how a conversation reads. Still "
             "mentions only everywhere else, and still silent when the reply "
             "@-mentions somebody other than the bot. Off makes every single "
             "message require a mention."},
    {"key": "slack.chat_write_projects", "group": "Slack",
     "label": "Engagements the bot may change data on, from Slack",
     "type": "text", "default": "",
     "help": "Project codes, comma separated. EMPTY MEANS NONE, which is the "
             "intended state. Adding a target from a chat message is a scope "
             "decision with packets at the end of it, and filing a finding "
             "writes the record a client reads — so those stay off per "
             "engagement until somebody names it here, even with "
             "“Let the agent change data” on. Managing who is ON an "
             "engagement is governed separately: it follows that switch, and "
             "changing anyone's role additionally requires the person who "
             "sent the message to hold admin on that engagement."},
]

for _s in SPEC:
    # Which Test button, if any, governs this field. Drives the UI grouping
    # and is the single place the gate and the form agree on.
    if _s["key"].startswith("smtp."):
        _s.setdefault("gate", "smtp")
    elif _s["key"] == "db.external_url":
        _s.setdefault("gate", "postgres")
    elif _s["key"].startswith("agent."):
        pass          # no live test: a model call costs money, so it is
                      # exercised by the chat itself, not by a save gate
    elif _s["key"] in ("auth.google_client_id", "auth.google_client_secret",
                       "auth.google_redirect_uri", "auth.google_enabled"):
        _s.setdefault("gate", "google")

BY_KEY = {s["key"]: s for s in SPEC}
SECRET_KEYS = {s["key"] for s in SPEC if s["type"] == "secret"}
GROUPS = list(dict.fromkeys(s["group"] for s in SPEC))
