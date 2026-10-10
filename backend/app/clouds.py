"""Cloud providers: which are authorised, and why none may be enumerated.

Two jobs that look related and are not.

# Authorising a provider

An engagement is routinely allowed to touch the client's own estate
inside a cloud and nothing else there. Putting `amazonaws.com` on the
in-scope list says "AWS is approved for this operation" -- it does
NOT say every bucket on the internet is fair game, because the scope
gate still matches the specific names the engagement listed.

# Never enumerating one

`amazonaws.com` has millions of names under it and none of them
belong to the client. Running amass against a provider's own zone
produces an enormous list of other people's infrastructure, burns
hours, and -- if any of it were acted on -- means touching hosts
nobody authorised. There is no engagement on which it is the right
thing to do, so it is refused rather than left to an operator to
remember.

That refusal is independent of whether the provider is approved. A
project may be authorised to work inside AWS and still must never
walk AWS's zone, which is why these are separate functions and not
one flag.

# The list

Twenty providers by worldwide usage, with the domains their customer
workloads actually land on rather than their marketing sites --
`amazonaws.com` matters here, `aws.amazon.com` does not. CDN and
edge domains are included because a client's application is reached
through them and a crawl will meet them.

This list is deliberately not exhaustive. It covers what turns up,
and `is_cloud_domain` matches suffixes, so a provider's subdomains
are covered without listing each.
"""
from __future__ import annotations

#: provider key -> (display name, domains)
#:
#: Ordered roughly by worldwide share, because the UI renders them in
#: this order and the first few are what most engagements need.
PROVIDERS: dict[str, tuple[str, tuple[str, ...]]] = {
    "aws": ("Amazon Web Services", (
        "amazonaws.com", "amazonaws.com.cn", "cloudfront.net",
        "elasticbeanstalk.com", "awsapps.com", "awsstatic.com")),
    "azure": ("Microsoft Azure", (
        "azure.com", "azurewebsites.net", "windows.net", "azureedge.net",
        "cloudapp.azure.com", "cloudapp.net", "trafficmanager.net",
        "azure-api.net", "azurecontainer.io")),
    "gcp": ("Google Cloud", (
        "googleapis.com", "googleusercontent.com", "appspot.com",
        "cloudfunctions.net", "run.app", "firebaseapp.com", "web.app",
        "withgoogle.com")),
    "alibaba": ("Alibaba Cloud", ("aliyuncs.com", "alicdn.com")),
    "oracle": ("Oracle Cloud", ("oraclecloud.com", "oraclecloudapps.com")),
    "ibm": ("IBM Cloud", ("cloud.ibm.com", "appdomain.cloud", "bluemix.net")),
    "tencent": ("Tencent Cloud", ("myqcloud.com", "tencentcloudapi.com")),
    "huawei": ("Huawei Cloud", ("myhuaweicloud.com", "hwclouds.com")),
    "digitalocean": ("DigitalOcean", (
        "digitaloceanspaces.com", "ondigitalocean.app")),
    "cloudflare": ("Cloudflare", (
        "cloudflare.com", "workers.dev", "pages.dev", "r2.dev",
        "cfargotunnel.com", "cdn.cloudflare.net")),
    "akamai": ("Akamai / Linode", (
        "akamai.net", "akamaiedge.net", "akamaized.net", "edgekey.net",
        "edgesuite.net", "linode.com", "linodeobjects.com")),
    "fastly": ("Fastly", ("fastly.net", "fastlylb.net", "fastly-edge.com")),
    "ovh": ("OVHcloud", ("ovh.net", "ovh.com", "ovhcloud.com")),
    "hetzner": ("Hetzner", ("hetzner.com", "hetzner.cloud", "your-server.de")),
    "vultr": ("Vultr", ("vultr.com", "vultrobjects.com")),
    "heroku": ("Heroku", ("herokuapp.com", "herokudns.com")),
    "vercel": ("Vercel", ("vercel.app", "vercel.com", "now.sh")),
    "netlify": ("Netlify", ("netlify.app", "netlify.com")),
    "salesforce": ("Salesforce", (
        "salesforce.com", "force.com", "lightning.force.com",
        "documentforce.com", "sfdcstatic.com")),
    "rackspace": ("Rackspace", ("rackspacecloud.com", "raxcdn.com")),
}

#: Every domain in the table, for the suffix match below.
ALL_DOMAINS: frozenset[str] = frozenset(
    d for _, domains in PROVIDERS.values() for d in domains)


def domains_for(keys: list[str] | tuple[str, ...] | None) -> list[str]:
    """Domains for the chosen providers, deduplicated and sorted.

    An unknown key is ignored rather than refused: the list here moves
    over time, and a project that stored `scaleway` before it was
    added should not fail to load because of it.
    """
    out: set[str] = set()
    for k in keys or ():
        entry = PROVIDERS.get(str(k).strip().lower())
        if entry:
            out.update(entry[1])
    return sorted(out)


def is_cloud_domain(name: str | None) -> bool:
    """Is this a cloud provider's own zone, rather than a client's?

    Suffix-matched on a LABEL boundary, so `amazonaws.com` and
    `s3.amazonaws.com` both match while `notamazonaws.com` does not --
    the same mistake the scope index is careful about, for the same
    reason: a look-alike domain is somebody else's, and treating it as
    the provider's would quietly exclude a real target from
    enumeration.
    """
    n = (name or "").strip().rstrip(".").lower()
    if not n:
        return False
    return any(n == d or n.endswith("." + d) for d in ALL_DOMAINS)


def listing() -> list[dict]:
    """The providers, for the UI's multiselect."""
    return [{"key": k, "name": name, "domains": list(domains)}
            for k, (name, domains) in PROVIDERS.items()]
