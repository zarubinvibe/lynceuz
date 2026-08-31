# Contributing

Thank you for looking. Lynceuz is small on purpose, so the bar for new code is
mostly about evidence: a change should be provable, and it should not widen what
the tool is allowed to reach.

## Before you write code

Read [AGENTS.md](AGENTS.md). It holds the invariants, and a pull request that
breaks one of them will be closed however good the code is. The short version:
zero monetary cost, public targets only, no new runtime dependency, and an honest
refusal instead of an invented result.

## Development

```bash
git clone https://github.com/zarubinvibe/lynceuz.git
cd lynceuz
node scripts/onboard.mjs --selftest   # the tool checks itself
npm test                              # the full suite, no internet needed
npm run check                         # syntax across src/
```

`npm test` must finish with zero failures and zero skipped tests. A skipped test
is treated as a failing one: it proves nothing and it hides why.

## What a good pull request looks like

- One change, described in plain words in the body.
- A test that fails before your change and passes after it. New network
  behaviour without a hostile test is not accepted.
- No new dependency in `package.json`. If you believe one is unavoidable, open an
  issue first and say what it buys.
- Existing tests left alone. If one is wrong, say why in the pull request instead
  of quietly rewriting it.

## The path

```text
fork -> branch -> commit -> push -> Pull Request
```

Commit messages use `type: description` — `feat`, `fix`, `refactor`, `docs`,
`test`, `chore`.

## Reporting a problem

Bugs and questions go to [Issues](https://github.com/zarubinvibe/lynceuz/issues).
Anything exploitable goes through [SECURITY.md](SECURITY.md) instead, not a public
issue.
