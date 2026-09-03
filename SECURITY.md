# Security and privacy

<p align="center"><img src="docs/assets/pantheon/doc-security.png" alt="A bolted white marble door standing closed, three blue streams stopping at its foot, and the sealed evidence chest beside it" width="100%"></p>

Lynceuz fetches public web pages and writes evidence to your disk. This page says
exactly what it touches, what it refuses, and how to report a problem.

## Reporting a vulnerability

Open a [GitHub security advisory](https://github.com/zarubinvibe/lynceuz/security/advisories/new)
on this repository. Please do not open a public issue for something exploitable.
Include the command you ran, the target, and what you expected instead.

Expect a first reply within seven days. If a fix changes behaviour that other
people depend on, the release notes say so.

## What it can reach

| Surface | What Lynceuz does |
|---|---|
| Network | Outbound HTTP(S) to the public address you pass, plus `robots.txt` and sitemaps on that host. |
| Private ranges | Refused. Loopback, link-local, and RFC 1918 targets never resolve into a fetch. |
| Search engines | Never scraped. Google, Bing and their neighbours are out of scope by design. |
| Files | Reads its own repository. Writes only under the data root you choose. |
| Shell | Spawns Node, and Python plus a browser only on the rendered path. |
| Money | The budget is `0`. There is no flag that quietly turns a paid route on. |
| Telemetry | None. Nothing is sent anywhere about your runs. |

## Robots and rate limits

`robots.txt` is read whole, not only its `Disallow` lines. A `Disallow` is never
worked around — not directly, not through the browser as a subresource. Sitemaps
and `Clean-param` are treated as the site inviting a crawler, which is what they
are. Concurrency and page counts stay bounded.

## The browser path

Most work never opens a browser. When a page is only reachable the way a person
reaches it, the rendered path runs under a dedicated unprivileged account, not
your own. On macOS a packet-filter rule scoped to that account's UID blocks every
outbound connection except the single loopback port the local proxy listens on.

That rule is installed once by you, with a script you can read, and it is bound to
a reboot: a rule that dies on restart is not containment, and Lynceuz refuses to
call it one. Before the browser is trusted, a canary probe checks the proxy port
and three leak channels — direct TCP, UDP and QUIC — and demands a real answer
from each, not a successful `send()`. If the canary cannot run, the browser stays
closed and the run reports why.

## Secrets

Lynceuz needs no API key, no token and no account. It reads none of yours. If you
point it at a URL that carries a credential in the query string, that URL lands in
the manifest, because the manifest records what was actually fetched — so do not
put secrets in the address.

## Rollback

Every run writes a content artifact and a JSON manifest holding the engine, the
attempts, the timestamp, a SHA-256 and the cost. Delete the data root and nothing
of the run remains. No daemon is installed, no login item, no background service.

The macOS containment installer is the one thing that changes your system, and it
ships its own `--rollback` that removes the account, the anchor and the rule it
added.

## Honest limits

- Containment is proven on macOS today. On other systems the browser path stays
  closed rather than pretending.
- A site that blocks you will keep blocking you. Lynceuz reports the closed door
  instead of inventing what was behind it.
- Nothing here defeats a captcha. A challenge is detected, the run slows down or
  stops, and a person decides what happens next.
