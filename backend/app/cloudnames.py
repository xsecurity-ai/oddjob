"""Telling a cloud provider's own naming apart from the client's estate.

A reverse lookup across a cloud provider's ranges does not find the
client's assets. It finds the provider's PTR template, once per
address, and on this engagement that is **86% of the target list**:
5,943 `*.bc.googleusercontent.com` and 1,401 `*.compute.amazonaws.com`
against 1,234 actually-named hosts. Of the 7,344, fifty-one have an
open port and the rest have never answered anything.

Those are not 7,344 assets. They are two facts -- "this range is GCP
compute", "this range is EC2" -- written out one address at a time,
and a Targets view that lists them row by row is a view where the
engagement's real estate is a rounding error.

**What this does NOT do.** It does not delete anything, hide anything
with evidence behind it, or decide that a host is uninteresting. A
`*.bc.googleusercontent.com` name with an open port is a finding and
stays one; the ephemeral PTR is just not the *name* of the thing. All
this answers is "is this string the provider's template or somebody's
chosen name", and the UI uses that to group rather than to filter.

**Why it is a derived field and not a column.** It is a pure function
of the hostname. Storing it would mean a migration, a backfill, and a
second copy that goes stale the day a provider adds a suffix -- for an
answer that costs a string comparison.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Family:
    """One provider naming template."""
    #: Stable id, used by the UI to group. Not shown to anyone.
    key: str
    #: The provider, as a person would say it.
    provider: str
    #: What this particular template names.
    label: str
    #: Matched against the lowercased hostname with any trailing dot
    #: stripped.
    pattern: re.Pattern[str]
    #: True when the name is assigned per-address by the provider and
    #: carries no information about who is using it. These are the
    #: ones worth condensing; a name somebody CHOSE is not, even
    #: inside a cloud.
    ephemeral: bool = True


#: Ordered: first match wins, so the more specific template goes
#: above the more general one it would otherwise be swallowed by.
FAMILIES: tuple[Family, ...] = (
    # Every GCP VM with an ephemeral external address gets this, and
    # the label is the reversed address. 5,943 of them here.
    Family("gcp-compute", "Google Cloud", "ephemeral compute",
           re.compile(r"\.bc\.googleusercontent\.com$")),
    Family("gcp-appengine", "Google Cloud", "App Engine",
           re.compile(r"\.gae\.googleusercontent\.com$")),
    Family("gcp-other", "Google Cloud", "user content",
           re.compile(r"\.googleusercontent\.com$")),
    # ec2-203-0-113-5.eu-west-1.compute.amazonaws.com, and the older
    # ec2-203-0-113-5.compute-1.amazonaws.com for us-east-1.
    Family("aws-ec2", "AWS", "EC2 public DNS",
           re.compile(r"\.compute(-\d+)?\.amazonaws\.com$")),
    Family("aws-elb", "AWS", "load balancer",
           re.compile(r"\.elb\.amazonaws\.com$")),
    Family("azure-vm", "Azure", "virtual machine",
           re.compile(r"\.cloudapp\.(azure\.com|net)$")),
    Family("do-droplet", "DigitalOcean", "droplet",
           re.compile(r"\.droplet\.digitalocean\.com$")),
    Family("oracle-vm", "Oracle Cloud", "compute",
           re.compile(r"\.oraclevcn\.com$")),
    # Named by whoever created it, inside a cloud. Recognised so the
    # UI can say which cloud, NOT condensed: `payments-api` is a name
    # somebody chose and belongs beside the rest of the estate.
    Family("azure-websites", "Azure", "App Service",
           re.compile(r"\.azurewebsites\.net$"), ephemeral=False),
    Family("aws-s3", "AWS", "S3 bucket",
           re.compile(r"\.s3[.-][a-z0-9-]*\.?amazonaws\.com$"), ephemeral=False),
)


def family_for(host: str | None) -> Family | None:
    """Which provider template a hostname matches, or None.

    None is the common and correct answer: a name the client chose is
    not a cloud template, and neither is a bare address.
    """
    h = (host or "").strip().lower().rstrip(".")
    if not h or "." not in h:
        return None
    for f in FAMILIES:
        if f.pattern.search(h):
            return f
    return None


def classify(host: str | None) -> tuple[str | None, str | None, bool]:
    """-> (family key, provider, is-ephemeral). All None/False if not cloud."""
    f = family_for(host)
    if f is None:
        return None, None, False
    return f.key, f.provider, f.ephemeral
