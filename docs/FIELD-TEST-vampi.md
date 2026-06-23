# Field test — bacscan vs VAmPI

Real-world validation against [VAmPI](https://github.com/erev0s/VAmPI), a deliberately
vulnerable REST API, run locally **without Docker** (Flask under a venv, in WSL Debian).
Goal: measure real true/false positives and surface what breaks on a live target.

## Setup
- Two accounts (`attacker`, `victim`), seeded DB, one secret book per user.
- **Ground truth measured directly** (independent of bacscan):
  - `GET /users/v1/_debug` → all users **with passwords, without authentication** (HTTP 200) = real exposure.
  - cross-user book read → HTTP 401 (VAmPI enforces ownership here; my initial BOLA assumption was wrong — reality corrected it).
- Gotcha: VAmPI pins `sqlalchemy==2.0.2`, which **breaks on Python 3.13** → bump to `sqlalchemy>=2.0.31`.

## Results (5 captured requests)
| Finding | Verdict | Assessment |
|---|---|---|
| anonymous-access `GET /users/v1/_debug` | confirmed (HIGH) | **True positive** — the headline VAmPI leak (passwords, no auth) |
| anonymous-access `/users/v1`, `/users/v1/{u}`, `/books/v1` | confirmed (HIGH) | **True positive** — broken authentication (vuln mode) |
| idor `GET /users/v1/victim` | **false_positive** (benign) | **correctly triaged**: endpoint is public → not an authorization bypass |

- **Audit log**: 43 timestamped events written (`output.audit_log`).
- **Redaction on real PII**: `_debug` passwords/emails stored as `[REDACTED]` / `[REDACTED-EMAIL]`; the real sample password `pass1` is absent from output.

## What worked
- Caught the main exposure via the **anonymous-access oracle**.
- **Triage filtered a genuine false positive** (public resource) with a logged reason — validated on real data, not a mock.
- Network hardening / redaction / audit ran clean, no crash.

## What broke / gaps (false negatives) → drives the backlog
1. **No excessive-data-exposure probe.** `_debug` was caught only because it was *anonymous*. An authenticated-but-leaky endpoint (passwords returned to a low-priv user) would be missed. → add a response-content probe for sensitive fields (it must run *before* redaction).
2. **ID heuristics too narrow.** `idor_dynamic` found nothing: business keys like `book_title` aren't matched by the `*id` / `*_id` patterns, and VAmPI's shapes didn't fit the list→detail-with-owner model. → richer id detection + per-target hints.
3. **No dedup/grouping** on broken-auth targets (the anonymous row lights up everywhere).

## Honest verdict
On a live target, bacscan found the real vulnerability **and** correctly filtered a real false
positive, with working audit + PII redaction. It is **field-usable under supervision**. Reaching
*comprehensive* coverage needs an excessive-data probe and deeper IDOR heuristics (see backlog).

## v4 re-run (after the improvements)
Re-ran against VAmPI with the v4 probes:
- **excessive-data-exposure** now flags `/users/v1/_debug` (passwords) and `/users/v1` (emails)
  as a **HIGH** finding — the false-negative gap from the first run is closed.
- **grouping** condensed 4 broken-auth hits into a single finding (less noise on a fully-open API).
- the lab itself surfaced a real bug — grouped findings took the *first* element's severity instead
  of the **max** — **found, fixed, and locked by a regression test**.
- triage still correctly filtered the public-resource false positive.
