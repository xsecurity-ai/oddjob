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
    {"key": "audit.retain_days", "group": "Site",
     "label": "Audit retention (days)", "type": "number", "default": 7,
     "help": "How long /audit/<type>/<format> keeps entries, where type is "
             "ui, backend, middleware or drone. This table grows with "
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
