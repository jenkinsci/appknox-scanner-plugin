# Appknox Jenkins Plugin — QA / Regression Test Plan

A practical checklist for testing config-form and build-logic changes to
`AppknoxScanner` before release. Written after manually regression-testing the
Exploit Likelihood Threshold addition (2026-10-09), which surfaced a real bug
this plan is specifically designed to catch next time.

## 1. Spin up a local test Jenkins

```bash
cd ~/Documents/projects/appknox-jenkins-plugin
mvn -o package -DskipTests        # build the current .hpi
mvn -o hpi:run -Dport=8090        # NOT -Djetty.port -- that property is ignored by this plugin version
```

Browse to `http://localhost:8090/jenkins/`. Runs in `DEVELOPMENT` install
state — no setup wizard, but **CSRF crumb protection is still ON**, so:
- UI form submissions work fine through a real browser click.
- Scripted/API calls (`curl`, `fetch`) need a crumb fetched with a shared
  cookie jar first, or they 403 with "No valid crumb was included":
  ```bash
  CRUMB_JSON=$(curl -s -c cookies.txt 'http://localhost:8090/jenkins/crumbIssuer/api/json')
  FIELD=$(echo "$CRUMB_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin)['crumbRequestField'])")
  VALUE=$(echo "$CRUMB_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin)['crumb'])")
  curl -s -b cookies.txt -X POST "<url>" -H "$FIELD: $VALUE" ...
  ```

After any **Java** code change: kill (`pkill -f "hpi:run"`) and restart —
Java classes need a real reload. After a **resource-only** change (`.jelly`,
`.properties`): just `mvn -o compile` (copies the resource into
`target/classes`) and reload the browser page — no restart needed, hpi:run
serves resources live.

## 2. Known test repo with a real findings catalog

`https://github.com/ginilpg/mfva` (branch `master`) ships a prebuilt
`app/app-debug.apk` — no build step needed, just Git SCM pointed at it.
Known findings as of 2026-10-09 (re-verify if the repo changes): mostly
Medium/High risk, nothing Critical. One finding
(`External data in raw SQL queries`, vuln ID 93) reliably comes back from
KnoxIQ as **needs review** — useful for verifying the exclusion logic without
depending on exact scan output. `StrandHogg Vulnerability` (ID 118) reliably
comes back Medium risk / High exploit likelihood — useful for verifying risk
and likelihood are checked independently.

## 3. The bug this plan exists to catch: config-form state on page LOAD, not just on change

**What happened:** the Exploit Likelihood dropdown correctly showed/hid rows
and disabled the KnoxIQ checkbox when a user *changed* the Threshold Type
dropdown live — tested, looked perfect. But on a plain page **refresh** of an
already-saved config, it silently fell back to showing the Risk row with the
checkbox enabled, regardless of what was actually saved. Root cause: the
page-load JS used `document.querySelectorAll('select[name="thresholdType"]')`
— but Jenkins actually names the field `_.thresholdType` (its internal
structured-form convention), so the selector never matched anything and the
fallback branch always ran.

**The lesson, as a standing test case:** any config.jelly conditional-visibility
JS must be tested two ways, not one:
1. Change the controlling dropdown live and observe the reaction (what we did
   first, and what passed).
2. **Save, then reload the page from scratch** (`navigate`, not just inspect
   current DOM) and confirm the *same* correct state appears with zero
   interaction. This is the one that actually catches the bug class above.

Check this specifically with real JS inspection, not just a screenshot:
```js
document.querySelector('select[name="_.thresholdType"]').value  // not 'thresholdType'
```

## 4. Threshold Type regression matrix

Run each of these as a real build against the test repo above. For each:
confirm the **Active gates** line matches what was configured, confirm the
specific pass/fail reason text makes sense for that gate type, and confirm
the final build result (SUCCESS/FAILURE) is correct.

| Threshold Type | Value to use | Expected against mfva | What to check |
|---|---|---|---|
| Risk | `CRITICAL` | **SUCCESS** (no Critical findings) | `Active gates: risk >= Critical`, "No vulnerabilities found breaching..." |
| Risk | `LOW` | **FAILURE** (plenty of Low+ findings) | Correct count in "Found N vulnerabilities with risk >= Low" |
| Health Score | `70` | **FAILURE** (mfva's score is well below 70) | "Health score N is below the threshold 70." — NOT a generic/wrong message |
| Exploit Likelihood | `HIGH` | **FAILURE** (StrandHogg is High likelihood) | `Active gates: exploit likelihood >= High`, count = 1 |
| Exploit Likelihood | `MEDIUM` | **FAILURE**, different count | Confirms threshold value actually changes the result, not just the label |

For every row, also confirm:
- **KnoxIQ triage status: Started / In progress / Completed** appears in the
  console (triage actually ran) whenever `triggerKnoxiq` is true OR
  Threshold Type is Exploit Likelihood (which must force it regardless of the
  checkbox's stored value).
- The needs-review table appears and excludes vuln ID 93 (SQL queries) from
  the count, regardless of which gate is active.
- CSV and PDF+password files are archived as build artifacts.
- The final `ERROR: ...` message (on failure) is accurate for that gate type
  — don't let a generic "Vulnerabilities detected" message survive for a
  Health Score failure, which isn't about a vulnerability count at all.

## 5. UI checks specific to Exploit Likelihood

With a Freestyle job's build step config open:
- [ ] Selecting "Exploit Likelihood Threshold" shows its own sub-dropdown
      (Low/Medium/High) and hides Risk/Health Score rows.
- [ ] Selecting it **checks and visibly disables** "Trigger KnoxIQ", and the
      help text below it changes to explain why.
- [ ] Switching back to Risk or Health Score **re-enables** the checkbox
      (don't leave it permanently stuck disabled) and restores the original
      help text.
- [ ] **Reload the page** (not just inspect current state) after saving each
      of the three Threshold Type values — confirm the correct row/state
      appears immediately, per section 3 above.
- [ ] Regardless of what the checkbox visually shows, confirm via console
      output that `--knoxiq` was actually passed on upload whenever
      Threshold Type is Exploit Likelihood — the UI is cosmetic, the Java
      code's own forced check (`triggerKnoxiq || "EXPLOIT_LIKELIHOOD".equals(thresholdType)`)
      is the real guarantee and should be verified independently of the UI.

## 6. Before merging / releasing

- [ ] `mvn -o test` — all tests pass (currently 63; update this number as
      tests are added).
- [ ] All 5 rows of the regression matrix (section 4) run as real builds
      against a real Appknox backend, not just unit-tested.
- [ ] README.md's Inputs table and examples match whatever actually changed.
