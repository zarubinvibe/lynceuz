# Lynceuz

Collects information from open websites on its own, for free. When it cannot, it says so instead of making something up.

[Русский](README.ru.md) · [中文](README.zh.md)

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Stars](https://img.shields.io/github/stars/zarubinvibe/lynceuz?style=flat&color=C9A87A)](https://github.com/zarubinvibe/lynceuz/stargazers) [![Status](https://img.shields.io/badge/status-v0.1%20early-brightgreen.svg)](https://github.com/zarubinvibe/lynceuz) [![Olympuz](https://img.shields.io/badge/olympuz-family-B8D6EA.svg)](https://github.com/zarubinvibe/athena#olympuz-family)

<p align="center"><img src="docs/assets/pantheon/hero.png" alt="Lynceus the lookout beside a white marble column, watching a bright ivory horizon" width="100%"></p>

<!-- owner-welcome:start -->

> I kept needing a lot of information on my own queries. Not one page, hundreds. By hand that is days of work. The services that do it for you charge money, and they never show you where the text came from.
>
> I wanted something that would gather it by itself, spend nothing, and leave a trail: here is the address, here is the time, here is the fingerprint of the file. So a month later you can check instead of taking somebody's word.
>
> Built it. It works.
>
> — Filipp Zarubin

<!-- owner-welcome:end -->

## Contents

- [What This Is](#what-this-is)
- [Why It Helps](#why-it-helps)
- [The Main Advantage](#the-main-advantage)
- [How It Works](#how-it-works)
- [Quickstart](#quickstart)
- [Simple Comparison](#simple-comparison)
- [Simple Words](#simple-words)
- [Safety And Privacy](#safety-and-privacy)
- [Limits](#limits)
- [Star And Contribute](#star-and-contribute)

<!-- beginner-readme:start -->

## What This Is

Lynceuz is a command-line program. You give it an address, it brings back the page and saves a small card beside it: where it came from, when, and a fingerprint of the file. The fingerprint is there so you can later prove nobody swapped the text. The name comes from Lynceus, the lookout on the Argo, who could see through earth and water and reported exactly what he saw.

## Why It Helps

Collecting by hand is slow. Paid services charge you and hand back a page with nothing attached: where it came from, at what hour, whether it is still the same text. Nothing to check.

Lynceuz keeps the receipt for every run. A month later you can show which route answered and when, and prove the page has not changed.

## The Main Advantage

**Main advantage:** it invents nothing: it brings back what it actually reached, and says plainly what it could not.

**Why this is better:** When a door is shut, Lynceuz names the door. It does not fill the gap with a guess, and it does not reach for a paid workaround to make the report look better. The trade is honest: fewer results, and every one of them you can stand behind.

## How It Works

Five steps, always in this order. Each one either hands the work to the next or stops with a reason.

<!-- workflow-diagram:start -->

```text
  ┌──────────┐   ┌──────────┐   ┌──────────┐
  │ Address  │ ▶ │ Ladder   │ ▶ │ Browser  │
  └──────────┘   └──────────┘   └──────────┘
        ▼
  ┌──────────┐   ┌──────────┐
  │ Evidence │ ▶ │ Stop     │
  └──────────┘   └──────────┘
```

<!-- workflow-diagram:end -->

| Stage | What happens |
|---|---|
| 1. Address | The address is checked before anything is fetched. |
| 2. Ladder | Free routes are tried in order, cheapest first. |
| 3. Browser | A browser opens only when a person's route is the only route. |
| 4. Evidence | Every run leaves something another person can check. |
| 5. Stop | When the safe routes run out, it says so and stops. |

### Step 1: Check the address

Lynceuz reads the URL first. Private ranges, loopback, link-local and metadata addresses are refused outright, and so is every redirect that tries to land on one. Then it reads the whole `robots.txt`, not only the lines that say no.

**You get:** a target that is public, or a refusal before a single byte moved.

### Step 2: Walk the free ladder

A plain request comes first. If the page is drawn by JavaScript, Lynceuz looks for the doors the site left open: the sitemap named in `robots.txt`, the document pages themselves, an RSS feed, a print version. Each rung is recorded whether it worked or not.

**You get:** the content from the first rung that actually answered.

### Step 3: Open the contained browser

Most pages never need one. When a site answers only the way it answers a human, the browser runs as a separate unprivileged account whose outbound traffic is blocked by a packet-filter rule, except one loopback port. A canary probes that rule before the page loads.

**You get:** a rendered page, or a closed door that says which rule stopped it.

### Step 4: Write the evidence

Lynceuz writes the bytes it received and a JSON manifest beside them: the engine that won, every rung it tried, the URL, the timestamp, a SHA-256 of the content, the cost, and any warning it raised. The cost line reads zero because the budget is zero.

**You get:** an artifact and a manifest you can hand to somebody else.

### Step 5: Stop honestly

A blocked run returns a typed refusal with the reason and the list of rungs already tried. Nothing is guessed, nothing is filled in from memory, and no paid route quietly opens to rescue the number. A refusal you can read beats a result you cannot trust.

**You get:** a named reason, and the exact point where the road ended.

## Quickstart

Node 20 or newer is the only thing you need. Nothing is downloaded on install, because there is nothing to download.

```bash
node --version
git clone https://github.com/zarubinvibe/lynceuz.git
cd lynceuz
node scripts/onboard.mjs
node src/lynceuz.mjs health
node src/lynceuz.mjs url 'https://example.org/' --json
```

Prefer not to clone? `npx github:zarubinvibe/lynceuz health` runs it straight from GitHub, and the [ZIP archive](https://github.com/zarubinvibe/lynceuz/archive/refs/heads/main.zip) works offline once it is unpacked. First install of any kind goes easier as a conversation: run `/lynceuz-setup` in Claude Code and it walks you through, asking before it touches anything.

Never done this before? [The onboarding](docs/ONBOARDING.md) walks the whole first run step by step and says what you see after every command.

**You get:** a table showing which routes are open and which are closed, and your first saved result card.

## Simple Comparison

| Choice | Best when | What you get | Trade-off |
|---|---|---|---|
| Lynceuz | You need many pages, and later you will have to show where they came from | The content, a card with the source and a fingerprint, and every route it tried | Fewer pages: closed doors stay closed |
| A paid collection service | You need a great many pages fast and the bill is fine | Volume and somebody else’s access channels | A monthly charge, and their word for where the text came from |
| A script you wrote yourself | The job is one site you know well | Full control of the page | You maintain it, and it usually leaves no trail |
| Copying by hand | One page, one time | Exactly what you saw | Nothing to re-check later, and it falls apart at a hundred pages |

## Simple Words

| Word | Simple meaning |
|---|---|
| Repository | The project folder that Git stores and versions |
| Terminal | The window where you type commands |
| Command | One instruction you give the computer |
| Branch | A separate line of changes that does not touch `main` |
| Pull Request | A request to review your change and accept it |
| Manifest | The small JSON file saved next to the content saying where it came from |
| SHA-256 | A fingerprint of a file: change one byte and the fingerprint changes |
| robots.txt | A file where a site tells crawlers what is welcome and what is not |
| Containment | An operating-system rule that stops a program from talking to the network |

## Safety And Privacy

- Public targets only. Loopback, private ranges and cloud metadata addresses are refused, redirects included.
- `robots.txt` is read whole. A `Disallow` is never worked around, not even through the browser.
- Search engine results are never scraped. Google, Bing and their neighbours are out of scope.
- The money budget is zero, and no flag quietly turns a paid route on.
- No telemetry. Nothing about your runs leaves your machine.
- The browser path runs as a separate unprivileged account with its outbound traffic blocked at the packet filter.

The full model, including how the containment rule is installed and rolled back, lives in [SECURITY.md](SECURITY.md).

## Limits

Early. The core, the ladder and the evidence trail are done and covered by tests that run without the internet. Browser containment is proven on macOS and stays closed elsewhere rather than pretending. Expect the command surface to still move.

- Containment is proven on macOS today. On other systems the browser path refuses instead of guessing.
- A site that blocks you keeps blocking you. Lynceuz reports the closed door; it does not open it.
- Captchas are detected, never solved. The run slows or stops and a person decides.
- There is no hosted service and no account. It runs on your machine or not at all.

Deeper reading: [the onboarding](docs/ONBOARDING.md) for the first run, [the discovery ladder](docs/discovery-ladder.md) for how routes are ordered, [the access policy](docs/access-policy.md) for where the line is drawn, and [the containment proof](docs/wave2-containment-proof.md) for how the browser rule was measured.

## Star And Contribute

Useful? Give Lynceuz a star: [https://github.com/zarubinvibe/lynceuz](https://github.com/zarubinvibe/lynceuz). It takes a second and it decides whether other people ever find the project.

Want to change something? The path is short: fork the repository, create a branch, commit your change, push the branch, then open a Pull Request. Do not push directly to `main`; the release gate rejects it.

Found a problem instead? Open an issue at [https://github.com/zarubinvibe/lynceuz/issues](https://github.com/zarubinvibe/lynceuz/issues) and say what you ran and what happened.

<!-- beginner-readme:end -->

<!-- pantheon-family:start -->
## Olympuz family

This is one of the public [Olympuz projects](https://github.com/zarubinvibe/athena#olympuz-family). Each row opens the repository or downloads its source as a ZIP.

| Type | Name | What it does | Source |
|---|---|---|---|
| project | Athena | Portable agent OS that restores a complete Claude and Codex setup on a new Mac. | [Repository](https://github.com/zarubinvibe/athena) · [ZIP](https://github.com/zarubinvibe/athena/archive/refs/heads/main.zip) |
| project | Helioz | 24/7 agent work conveyor with verified completion markers and goal-based overnight decisions. | [Repository](https://github.com/zarubinvibe/helioz) · [ZIP](https://github.com/zarubinvibe/helioz/archive/refs/heads/main.zip) |
| project | Mnemazine | Local-first memory system that turns raw inputs into verified reusable knowledge. | [Repository](https://github.com/zarubinvibe/mnemazine) · [ZIP](https://github.com/zarubinvibe/mnemazine/archive/refs/heads/main.zip) |
| project | Themis | Multi-agent assistant for Russian litigation with local OCR and review by a five-jurist council. | [Repository](https://github.com/zarubinvibe/themis) · [ZIP](https://github.com/zarubinvibe/themis/archive/refs/heads/main.zip) |
| project | Zeuz | Factory that turns an idea into a governed multi-agent workflow with gates, observability, and replay. | [Repository](https://github.com/zarubinvibe/zeuz) · [ZIP](https://github.com/zarubinvibe/zeuz/archive/refs/heads/main.zip) |
| project | Lynceuz | Collects public web evidence at zero cost and stops with an honest reason when the safe routes end. | [Repository](https://github.com/zarubinvibe/lynceuz) · [ZIP](https://github.com/zarubinvibe/lynceuz/archive/refs/heads/main.zip) |
<!-- pantheon-family:end -->

## License

MIT. See [LICENSE](LICENSE).
