<!-- Languages: English (this file) · [Русский](ONBOARDING.ru.md) · [简体中文](ONBOARDING.zh.md) -->

# Onboarding — your first hour with Lynceuz

<p align="center"><img src="assets/pantheon/doc-onboarding.png" alt="Lynceus the lookout shading his gaze beside the sealed evidence chest, with the free ladder and the blank address stone standing ready" width="100%"></p>

This walks a first-time user from an empty folder to a proven fetch. You type a
command, read what shows up, then move to the next step. Nothing here installs a
package or touches system settings. If a step comes back red, stop there and fix
it before going on — a red check that you skip only hides later.

Other languages: [Русский](ONBOARDING.ru.md) · [简体中文](ONBOARDING.zh.md).

1. **Check your Node version.** Lynceuz needs Node 20 or newer and ships zero
   runtime dependencies, so this is the only thing you truly have to have.

   ```bash
   node --version
   ```

   You should see something like `v24.15.0`. If the number is below 20, or the
   shell says `command not found`, install Node 20+ first and come back.

2. **Get the code.** Clone the repository into a folder of your choice.

   ```bash
   git clone https://github.com/zarubinvibe/lynceuz.git
   ```

   Git prints its progress and finishes with `done.`. Swap `OWNER` for the
   account that hosts your copy.

3. **Step into the folder.** Every later command assumes you are inside it.

   ```bash
   cd lynceuz
   ```

   The prompt now ends in `lynceuz`. You will not leave this directory again.

4. **Skip the install — on purpose.** There are no runtime dependencies, so
   there is nothing to download. If you run `npm install` out of habit it simply
   reports `up to date` and adds nothing. That empty result is the promise, not a
   mistake.

5. **Run the readiness probe.** This is the honest snapshot of what your machine
   can do right now.

   ```bash
   node scripts/onboard.mjs
   ```

   You get a short report: your Node version, the platform, `0 runtime
   dependencies`, how many source modules parsed, and which capabilities are
   ready or closed. The last line reads `Ready: mandatory checks are green.` when
   everything a human needs is in place.

6. **Read the same snapshot as data.** When you want the machine-readable form —
   for a script, a log, or a bug report — ask for JSON.

   ```bash
   node scripts/onboard.mjs --json
   ```

   It prints an object with `"kind": "lynceuz_onboarding"` and
   `"runtime_dependencies": 0`. The command exits non-zero if any mandatory check
   is red, so it is safe to gate a pipeline on it.

7. **Let the script check itself.** Before trusting the probe, have it run its
   own assertions.

   ```bash
   node scripts/onboard.mjs --selftest
   ```

   A healthy copy answers `onboard selftest: ok` and exits `0`.

8. **Confirm the sources parse.** This is the project's own check: Node reads
   every core module without running any network work.

   ```bash
   npm run check
   ```

   No output and a clean exit means all sources are intact. A named file with an
   error means a damaged or incompatible clone.

9. **Ask Lynceuz which routes are live.** The health snapshot lists every engine
   and whether it is `ready`, `disabled`, or held behind the security gate.

   ```bash
   node src/lynceuz.mjs health --json
   ```

   Expect `native` to be `ready` and the browser engines to sit at
   `unavailable_security_gate`. That is the normal fresh state, not a failure.

10. **Fetch your first real page.** Use a public URL that shows its text without
    JavaScript. Pass it as a single quoted argument.

    ```bash
    node src/lynceuz.mjs url 'https://example.org/' --json
    ```

    On success you get a result path, a manifest, and a SHA-256. If the site
    refuses, you get a typed `blocked` with the exact reason — never invented
    text.

11. **Find the proof on disk.** Every run writes its artifact and manifest under
    `.lynceuz/`, which stays out of git.

    ```bash
    ls .lynceuz
    ```

    The manifest records the engine, the attempts, the URL, the time, the hash,
    and any warnings — that is the evidence you can show later.

12. **Keep it current with `lynceuz-update`.** When you want the newest version,
    run the `lynceuz-update` skill. It shows you the diff first, accepts only a
    fast-forward, re-runs the checks, and never touches your `.lynceuz/` results
    or local settings.

## Browser path (optional, macOS only)

The browser engines run untrusted page code, so they stay closed until the
machine owner installs containment by hand. On macOS you can review and run
`ops/macos/install-containment.sh` yourself; on Linux and Windows there is no
supported browser path yet — use the native route or a public export instead.
`node scripts/onboard.mjs --json` lists exactly what the browser path requires.

## Star it, then send a change back

If Lynceuz saved you time, please [star the repository](https://github.com/zarubinvibe/lynceuz) — it helps other people
find an honest, zero-cost scraper.

Already installed and want the current version? Run `/lynceuz-update` in Claude Code.
It shows what changed before it touches anything, pulls fast-forward only, leaves your
settings and saved results alone, and re-runs the project's own check afterwards.

And if you improve something, the path is short:

**fork -> branch -> commit -> push -> Pull Request.**

```bash
# fork on GitHub, then:
git checkout -b my-improvement
git commit -am "docs: sharpen the onboarding wording"
git push -u origin my-improvement
# open the Pull Request from your fork on GitHub
```

Keep changes small and describe what you saw before and after. Clear, specific
Pull Requests get merged fastest.
