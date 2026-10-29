# Mini SOC — AI-Powered Threat Detection & Automated Response

A lab Security Operations Center: collects host logs, detects attacks with rules + machine learning, scores and groups alerts into incidents, and responds automatically in a safe simulated environment.

**Status:** Phase 8 complete (ingestion, simulator, dashboard, 11 MITRE-mapped rules, Isolation Forest + Random Forest, incident correlation + risk scoring, automated response with playbooks + guardrails, Attack Simulator + real-time WebSockets, sign-in with roles, CI)

| Service | URL |
|---|---|
| Dashboard | http://localhost:5173 (sign in as `admin` / `Admin@123`, `analyst` / `Analyst@123` or `viewer` / `Viewer@123`) |
| API docs | http://localhost:8000/docs |
| Database | `localhost:5433` (user `soc`, db `socdb`) |

## Architecture

```
simulator.py ──POST /api/ingest──┐
Attack Simulator page ──/api/lab─┤
                                 ▼
                         FastAPI backend ──────────────▶ PostgreSQL
                                 │                        events, alerts, incidents,
     detection: 11 rules + ML-001 (Isolation Forest + Random Forest)    containments,
     correlation: alerts → incidents, risk score 0-100                  audit log
     response: playbooks → simulated firewall / EDR (block, quarantine, isolate)
                                 │
            REST /api/*  ◀───────┤───────▶  WebSocket /ws  (pushes "something changed")
                                 ▼
                React dashboard (Vite + Tailwind + Recharts)
```

## Project layout

```
mini-soc/
├── docker-compose.yml        # Postgres + backend + frontend, one command to start
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py           # FastAPI app entry point
│       ├── database.py       # DB connection + session per request
│       ├── models.py         # All tables (events, alerts, incidents, ...)
│       ├── schemas.py        # Request/response validation
│       ├── migrate.py        # Adds new columns to existing tables (keeps your data)
│       ├── utils.py          # Timezone + IP helpers
│       ├── assets.py         # Asset inventory: what each host is and how critical
│       ├── realtime.py       # WebSocket hub: pushes live updates to every open dashboard
│       ├── auth/
│       │   ├── security.py   # PBKDF2 password hashing + signed tokens (JWT, HS256), stdlib only
│       │   ├── permissions.py # Who may do what: the whole access policy in one table
│       │   └── deps.py       # Checks the token and the role on every request
│       ├── lab/
│       │   ├── scenarios.py  # The 7 launchable attacks (catalog + "ends now" time shifting)
│       │   └── live.py       # Background live-traffic generator (start/stop from the browser)
│       ├── detection/
│       │   ├── rules.py      # The 11 detection rules + ML-001 + MITRE mapping + sliding-window logic
│       │   ├── engine.py     # Runs rules, creates/merges alerts, scoring
│       │   └── correlation.py # Groups alerts into incidents (union-find), risk score, kill chain
│       ├── response/
│       │   ├── actions.py    # Block / quarantine / isolate + guardrails + the simulated firewall
│       │   ├── playbooks.py  # 5 automated response playbooks (auto or approval)
│       │   └── audit.py      # One helper that writes every action to the audit log
│       ├── ml/
│       │   ├── features.py   # Logs → per-minute windows → 14 numeric features
│       │   ├── dataset.py    # Training scenarios from the simulator (with weakened attack variants)
│       │   ├── train.py      # Trains + evaluates both models, compares against the rules
│       │   ├── detector.py   # Live scoring, explanations ("why the model flagged this")
│       │   └── storage.py    # Saves/loads models in backend/models/
│       └── routers/
│           ├── ingest.py     # POST /api/ingest (runs detection on every batch)
│           ├── events.py     # GET /api/events (filters, search), /api/events/filters
│           ├── stats.py      # GET /api/stats/overview (dashboard numbers + charts)
│           ├── alerts.py     # GET/PATCH /api/alerts, /api/alerts/summary
│           ├── detection.py  # GET/PATCH /api/rules, POST /api/detection/run
│           ├── ml.py         # GET /api/ml/status, POST /api/ml/train
│           ├── incidents.py  # GET/PATCH /api/incidents, /api/incidents/summary, /api/assets
│           ├── response.py   # containments, manual actions, approvals, playbooks, summary
│           ├── audit.py      # GET /api/audit
│           ├── lab.py        # Attack Simulator: launch, full demo, live traffic, lab reset
│           └── auth.py       # Sign-in, lockout, change password, user management
│   ├── models/               # Trained models (created automatically on first start)
│   └── tests/
│       ├── test_detection.py # 9 rule tests: each attack detected, zero false positives, dedup...
│       ├── test_ml.py        # 6 ML tests: stealthy attacks caught, false-alarm budget on busy traffic...
│       ├── test_incidents.py # 8 correlation tests: one attack = one incident, kill chain, scoring...
│       ├── test_response.py  # 15 response tests: auto-block, quarantine, approvals, guardrails, expiry...
│       ├── test_lab.py       # 8 lab tests: launch, replay blocked, reset, WebSocket pushes, live traffic
│       └── test_auth.py      # 15 auth tests: login, lockout, forged/expired tokens, roles, API key...
├── frontend/
│   ├── package.json
│   ├── vite.config.js
│   └── src/
│       ├── App.jsx           # Routes
│       ├── index.css         # Design tokens (colors, fonts)
│       ├── lib/              # api client, realtime (WebSocket) client, data hook, formatters
│       ├── components/       # Layout (sidebar/topbar), shared UI pieces
│       ├── components/AlertDrawer.jsx  # The alert investigation panel
│       ├── components/Toasts.jsx       # Live pop-ups: new incident, auto-response, approval needed
│       └── pages/            # Overview, LiveEvents, Alerts, Rules, Models, Incidents, IncidentDetail,
│                             # Response, Audit, Simulator, Login, Users
├── simulator/
│   └── simulator.py          # Generates normal traffic + 7 attack scenarios
├── scripts/
│   └── smoke_test.py         # End-to-end check of a running stack (also used by CI)
└── .github/workflows/
    └── ci.yml                # GitHub Actions: tests, frontend build, end-to-end on Postgres, Docker build
```

---

## Day 1 — Get it running (~3 hrs)

**1. Unzip and open a terminal in the `mini-soc` folder.**

**2. Start Docker Desktop**, then run:

```bash
docker compose up --build
```

Wait until you see `Uvicorn running on http://0.0.0.0:8000`. Leave this terminal open.

> **Note on your existing PostgreSQL:** The Docker database is mapped to port **5433** on your machine, so it won't clash with the PostgreSQL you already installed (which uses 5432). They are two separate databases.

**3. Check it's alive.** Open in your browser:
- http://localhost:8000/health → `{"status":"ok"}`
- http://localhost:8000/docs → interactive API docs (FastAPI generates these for free)

**4. Read the code in this order:** `models.py` → `schemas.py` → `routers/ingest.py` → `main.py`.

**Day 1 checkpoint — can you answer these?**
- Why does every log type (auth, process, network) go into ONE `events` table?
- What happens if someone sends an event with `"source": "banana"`? Try it in `/docs`.
- Why is the Docker database on port 5433 instead of 5432?

---

## Day 2 — Simulate attacks (~3 hrs)

**1. In a second terminal**, go to the `simulator` folder and run:

```bash
python simulator.py --seed 42
```
(On Windows, use `python`; on macOS/Linux you may need `python3`. No pip install needed — standard library only.)

You'll see each attack being injected and the events stored.

**2. Look at what landed:**
- http://localhost:8000/api/events/stats — counts by source, type, and label
- http://localhost:8000/api/events?event_type=login_failed — failed logins
- http://localhost:8000/api/events?src_ip=203.0.113.45 — the brute-force attacker

**3. Peek inside the database directly (optional but good practice):**
```bash
docker exec -it soc-db psql -U soc -d socdb
```
```sql
SELECT label, COUNT(*) FROM events GROUP BY label;
SELECT src_ip, COUNT(*) FROM events WHERE event_type='login_failed' GROUP BY src_ip ORDER BY 2 DESC LIMIT 5;
\q
```
That second query is basically a brute-force detection rule. That's tomorrow's work.

**4. Try the other modes:**
```bash
python simulator.py --attacks none --minutes 60      # clean baseline traffic (ML training on Day 4)
python simulator.py --attacks brute_force            # one attack only
python simulator.py --live                           # continuous stream, Ctrl+C to stop
```

### The 4 simulated attacks

| Attack | What it looks like in logs | MITRE ATT&CK |
|---|---|---|
| Brute force | 25–40 failed logins from `203.0.113.45` in ~1 min, then a successful login | T1110 |
| Port scan | 120 different ports hit from `198.51.100.23` in seconds, tiny packets | T1046 |
| Suspicious process | `xmrig` miner running from `/tmp` at 97% CPU; `nginx` spawning `sh` then `nc` | T1496, T1059 |
| Exfiltration | `db-01` sending 5–50 MB repeatedly to `192.0.2.77:4444` | T1041 |

Attacker IPs come from RFC 5737 documentation ranges, so they can never belong to a real host. Nothing in this project touches your real network.

**Day 2 checkpoint — can you answer these?**
- Normal traffic also has some failed logins (~8%). Why did we deliberately add those?
- What is the `label` field for, and why won't real-world logs have it?
- Why does the simulator send events in batches of 500 instead of one at a time?

---

## Useful commands

| Task | Command |
|---|---|
| Start everything | `docker compose up --build` |
| Stop | `Ctrl+C`, then `docker compose down` |
| Wipe the database and start fresh | `docker compose down -v` |
| See backend logs | `docker logs -f soc-backend` |
| Check the whole stack works | `python scripts\smoke_test.py` (after running the simulator) |
| Run all tests | `docker compose exec backend pytest -v` |

## Troubleshooting

- **`port is already allocated` on 8000 or 5433:** something else uses that port. Change the left number in `docker-compose.yml` (e.g. `"8001:8000"`) and use the new port in URLs and `--url`.
- **Simulator says `Can't reach ...`:** the backend isn't running. Check the first terminal.
- **Windows: `docker` not found:** make sure Docker Desktop is open and fully started (whale icon steady).

---

## Phase 2 — The dashboard

**Start everything** (from the `mini-soc` folder):
```bash
docker compose up
```
The first start installs the dashboard's packages inside Docker, which takes 1–3 minutes. Wait for `soc-frontend | ➜ Local: http://localhost:5173/`, then open **http://localhost:5173**.

**Generate some fresh traffic** in a second terminal so the charts have data:
```bash
python simulator\simulator.py --seed 7
```

**Things to try:**
- **Overview:** the spike in the *Event volume* chart is the port scan. In *Top source IPs*, the brute-force attacker stands out with a red failed-logins bar. Switch the time window (15m / 1h / 4h / 24h).
- **Click an attacker IP** on the Overview → you land on Live Events filtered to that IP. This is "pivoting", the core SOC investigation move.
- **Live Events:** run `python simulator\simulator.py --live` and watch new rows flash in every few seconds. Click any row to expand all its fields. Try searching `xmrig` or `alice`.
- Pages marked **P3–P7** in the sidebar show what they'll do once built.

**How the frontend gets data:** every page calls the FastAPI backend (`src/lib/api.js`) and re-fetches on a timer (`src/lib/usePolling.js`): every 5s on Overview, every 3s on Live Events. Phase 7 replaces polling with WebSockets.

**Phase 2 checkpoint — can you answer these?**
- Why are the filters on Live Events stored in the URL (`/events?src_ip=...`) instead of just in React state?
- The stats are calculated in the backend, not in React. Why not just send all events to the browser and count them there?
- What's the downside of polling every 3 seconds, and what would a WebSocket do differently?

---

## Phase 3 — Detection engine, Alerts and Rules

**This phase changed the backend's Python packages**, so start with `--build` once:
```bash
docker compose up --build
```
Look for `Schema upgraded, added columns: alerts.status, ...` in the backend log. That's `migrate.py` upgrading your existing database without losing your events.

**1. Turn your existing events into alerts.** Open http://localhost:5173/alerts and click **Re-scan last 24h**. Or generate fresh attacks:
```bash
python simulator\simulator.py --seed 11 --attacks brute_force,port_scan,suspicious_process,exfiltration
```
The simulator reports how many alerts were created.

**2. The 11 rules** (all in `backend/app/detection/rules.py`):

| ID | Rule | Logic | MITRE ATT&CK |
|---|---|---|---|
| SOC-001 | SSH brute force | 5+ failed logins from one IP within 60s | T1110 Brute Force |
| SOC-002 | Successful login after brute force | brute-force burst, then a success from same IP within 5 min | T1078 Valid Accounts |
| SOC-003 | Multiple usernames from one IP | 4+ different usernames fail from one IP within 5 min | T1110.003 Password Spraying |
| SOC-004 | Port scan | 20+ distinct ports from one IP within 60s | T1046 Network Service Discovery |
| SOC-005 | Execution from temp/hidden dir | process path in /tmp, /dev/shm, or a hidden folder | T1564.001 Hidden Files |
| SOC-006 | Known malicious tool | process name on a watchlist (xmrig, mimikatz...) | T1496 Resource Hijacking |
| SOC-007 | Web server spawned a shell | nginx/apache parent → sh/bash child | T1505.003 Web Shell |
| SOC-008 | Netcat / socat execution | reverse-shell tools started | T1059.004 Unix Shell |
| SOC-009 | Unusually high CPU process | 90%+ CPU, not allowlisted | T1496 Resource Hijacking |
| SOC-010 | Large outbound transfer | 20+ MB to one external IP within 10 min | T1041 Exfiltration over C2 |
| SOC-011 | Connection on attack-tool port | traffic to 4444, 31337, 6667... | T1571 Non-Standard Port |

**3. Things to try:**
- **Investigate an alert:** click the critical *Successful login after brute force*. The drawer shows the evidence events, an activity chart, the MITRE technique (click it to open the real ATT&CK page), recommended response, and related alerts on the same IP. Click **Investigate**, add a note, then **Resolve**.
- **See dedup in action:** run `python simulator\simulator.py --attacks brute_force` twice within a few minutes. The second run says `updated`, not `new`: the attack merges into the existing alert instead of creating spam.
- **Tune a rule:** on Detection Rules, change SOC-004's `distinct ports` to `500` and save. Run `python simulator\simulator.py --attacks port_scan`: no alert, because the scan only hits 120 ports. Click **Reset to default**.
- **Check the coverage map** at the top of Detection Rules: 9 of 14 ATT&CK tactics covered. The dashed boxes are honest gaps. Interviewers like it when you can name your blind spots.

**4. Run the tests:**
```bash
docker compose exec backend pytest -v
```
8 tests prove: every attack is detected, **2,400 normal events produce zero alerts**, alerts are deduplicated, disabled/tuned rules behave, and triage works.

**Phase 3 checkpoint — can you answer these?**
- Why does the brute-force rule use a 60-second **window** instead of counting all failures ever?
- What's alert **deduplication**, and what would happen to an analyst without it?
- One brute-force attack fires 3 different rules (SOC-001, 002, 003). Is that a problem or a feature? (Hint: Phase 5.)
- What's the trade-off when you lower a threshold, e.g. brute force from 5 failures to 2?
- Why test on normal-only traffic? What's a false positive and why do SOC teams care so much about them?

---

## Phase 4 — Machine learning

**This phase adds Python packages (scikit-learn) and changes the simulator's normal traffic.** Recommended clean start:
```bash
docker compose down -v
docker compose up --build
```
`down -v` wipes the old events and alerts. They were made by the old simulator, whose traffic was less realistic. On first start the backend trains the models by itself (look for `ML models trained in ...s` in the log, about 10–30 seconds).

Then generate traffic with all 6 attacks:
```bash
python simulator\simulator.py --seed 21
```

### What the two models do

**Feature engineering** (`ml/features.py`): models can't read logs, they read numbers. Every **minute** of activity from each IP (or each host, for processes) becomes one row of **14 features**: failed logins, distinct usernames, distinct ports, data sent, "processes never seen before", and so on.

| | Isolation Forest | Random Forest |
|---|---|---|
| Type | Unsupervised (no labels) | Supervised (learns from labels) |
| Question it answers | "Is this minute unlike normal traffic?" | "Which attack does this look like?" |
| Strength | Can flag attacks nobody wrote a rule or label for | Accurate, and names the attack type for the analyst |
| Weakness | Lower recall; needs anomalies to be rare | Only knows attack types it was trained on |

ML-001 raises an alert when the Isolation Forest finds a minute anomalous **or** the Random Forest is ≥ 90% sure it's an attack. It runs inside the same detection engine as the rules, so it gets the same dedup, scoring and triage.

### The two new stealthy attacks

| Attack | How it hides | Rules | ML |
|---|---|---|---|
| `slow_brute_force` | One guess every ~20s at a single account: never 5 in 60s, never 4 usernames | ❌ 0% | ✅ |
| `slow_scan` | One port every ~5s: about 12 ports per minute, under the 20-port threshold | ❌ 0% | ✅ |

Try just those two:
```bash
python simulator\simulator.py --attacks slow_brute_force,slow_scan --seed 3
```
On Alerts, filter to **ML only**: you'll see alerts for `203.0.113.99` and `198.51.100.77`, and **no rule alert for either IP**. Open one and read **Why the model flagged this**.

### Things to try
- **ML Models page:** the "Rules vs machine learning" table is your strongest interview material. Rules alone catch about 36% of attack minutes, rules + ML about 90%, with 0 false alarms on about 5,000 normal minutes of held-out test data.
- **The anomaly score chart:** blue = normal minutes, red = attacks. The dashed threshold is where alerts start.
- **The confusion matrix:** which attacks the Random Forest mixes up (weakened brute force vs. a remote worker who mistyped a password).
- **Retrain** after running the simulator a few times: training also uses labeled events from your database. (Do it once after Phase 5 too, so the models learn the new intrusion scenario.)
- **Tune sensitivity** on Detection Rules → ML-001: `threshold scale` 1.2 means fewer, more confident alerts.
- Run all 15 tests: `docker compose exec backend pytest -v`

### What went wrong while building it (good interview stories)
1. **Isolation Forest first caught only 4% of attacks.** It was trained on normal data only, where features like `unseen_processes` are always 0, and an Isolation Forest can't split on a feature that never varies. Fix: train it the unsupervised way, on all traffic with attacks rare (0.5%).
2. **Random Forest first scored a perfect 100%.** That's a red flag that the data is too easy, not that the model is great. Fix: added realistic noise (remote workers logging in from outside, public web visitors, a nightly 80 MB backup that looks like exfiltration by volume alone). It now scores 99.8% accuracy and 0.98 macro-F1, and macro-F1 is the honest number.
3. **Zero false alarms offline, 23 live.** Stacked simulator runs made traffic 3× busier than anything in training. Fix: train across quiet and busy periods (8–60 events/min), and set the alert threshold so only 1 in 5,000 normal minutes can cross it.
4. **Removing noisy features made the Isolation Forest better** (45% → 70% recall at the same false-alarm rate). Measured across 5 random seeds, not just one lucky run.

**Phase 4 checkpoint — can you answer these?**
- Why does the Isolation Forest need anomalies to be *rare* in its training data?
- Why is "accuracy 99.8%" misleading here, and what does macro-F1 tell you instead?
- Why split train/test by *scenario* instead of by individual minutes? (Hint: leakage.)
- The Random Forest caught the slow attacks too. Why is that less impressive than the Isolation Forest catching them?
- An ML alert says "unclassified anomaly" with no MITRE technique. How would you investigate it?

---

## Phase 5 — Incidents, attack timelines and risk scoring

No new packages this time, so a normal restart picks up the code: **Ctrl + C**, then `docker compose up`. On startup the backend upgrades the `incidents` table and groups your existing alerts into incidents.

Generate traffic with all 7 attacks, including the new full intrusion:
```bash
python simulator\simulator.py --seed 21
```
The output now ends with `INCIDENTS: 8 new`. Then open **Incidents** in the sidebar.

### Why incidents?
One brute force fires 4 alerts (3 rules + ML). The full intrusion fires 11. An analyst shouldn't work 11 tickets for one attacker. **Correlation** groups alerts into one incident per attack. Two alerts are linked when they're within 60 minutes of each other and:

| Link | Example |
|---|---|
| Same entity | SSH brute force + password spraying, both from `203.0.113.45` |
| Same machine of ours | xmrig from `/tmp` + high CPU, both on `web-01` |
| **Compromise pivot** | attacker logs in to `dev-laptop-07` as bob → malware starts on `dev-laptop-07` 1 min later |

Links chain together (A~B and B~C → one incident), computed with **union-find**. Two guards keep it honest:
- Two *different* attackers hitting the same server stay separate.
- Activity that started **before** the attacker logged in is never blamed on them. (A test caught this: an early version merged a miner that ran 4 minutes *before* the login.)

### The new attack: `intrusion`
One attacker (`203.0.113.66`) goes through **8 ATT&CK stages** against `dev-laptop-07` in about 6 minutes: port scan → SSH brute force → login as bob → `curl` downloads a binary → it runs hidden as `/tmp/.cache/kworkerd` at 93% CPU → calls back on port 4444 → uploads ~130 MB. 11 alerts, **one incident**.
```bash
python simulator\simulator.py --attacks intrusion
```

### Risk score (0–100), explained on every incident
| Factor | Points |
|---|---|
| Most severe alert | 70% of its score |
| Attack stages | +5 per extra ATT&CK tactic (max 15) |
| Rules and ML agree | +5 |
| Confirmed access (successful login after brute force, web shell) | +15 (raised from +10 in Phase 6) |
| Asset value: `db-01` critical / web servers high (`app/assets.py`) | +10 / +5 |
| Repeat offender (attacker had an earlier resolved incident) | +5 |

Bands: 85+ critical · 65+ high · 40+ medium · below that low. The 70% weighting matters: without it, every incident with one critical alert scored 100 and the ranking became useless.

### Things to try
- Open the top incident: read the **kill chain**, the **attack timeline** (each bar is one alert), and **Why this risk score**.
- Click **Investigate**, add a case note, then **Resolve**. All of its alerts close too (one decision, not eleven clicks).
- Run `python simulator\simulator.py --attacks port_scan` twice, resolving the incident in between. The second incident gets **+5 repeat offender**.
- On Alerts, every alert now links to its incident (`INC-n`).

### An ML lesson from this phase
Adding the intrusion scenario changed the training data, and the ML false-alarm test started failing about 1 run in 3. The cause: on very busy traffic, one machine with 3 failed logins in a minute scored *just* over the anomaly line. Two fixes:
1. Train on busier traffic too (up to 90 events/min).
2. Grey-zone ML alerts (barely anomalous, classifier unsure) are **low** severity instead of medium.

The test now checks a **false-alarm budget** (at most 1 low-priority alert per 7,200 busy normal events) instead of demanding exactly zero. That's how statistical detectors should be tested.

**Phase 5 checkpoint — can you answer these?**
- Why not just link every alert on the same host into one incident? What would go wrong?
- Why is "compromise pivot" only allowed *after* the login time?
- Two incidents score 72 and 94. Which factors make the difference? (Open them and compare.)
- What's the difference between an alert and an incident, in one sentence each?
- Why test an ML detector with a false-alarm *budget* instead of "zero alerts"?

---

## Phase 6 — Automated response, Response Center and Audit Log

No new packages: **Ctrl + C**, then `docker compose up`. The backend upgrades the audit table and loads 5 playbooks.

> **Recommended:** start from a clean database (`docker compose down -v`, then `docker compose up`). Your trained ML model is kept, since it lives in `backend/models/`, not in the database. With old data, the first new run would immediately block yesterday's attackers, and that's confusing to watch.

```bash
python simulator\simulator.py --seed 21
```
The output now ends with `RESPONSE: 5 automatic, 3 awaiting approval`. Run it again with `--seed 22` and watch `dropped by firewall` climb: the blocked attackers can't get back in.

**Everything is simulated.** "Blocking an IP" adds a row to the `containments` table, and `/api/ingest` then drops matching log events the way a real firewall drops packets. Nothing touches your real network or PC.

### The three actions
| Action | Simulated tool | What it stops |
|---|---|---|
| Block IP | Firewall | Every event to **or** from that IP (inbound attacks and outbound exfiltration) |
| Quarantine process | EDR | That binary starting again on that host |
| Isolate host | EDR | All network and login traffic on that host |

### The 5 playbooks (`response/playbooks.py`)
| ID | When | Do | Mode |
|---|---|---|---|
| PB-01 | Critical incident with an outside attacker | Block attacker 24h | **Auto** |
| PB-02 | High incident with an outside attacker | Block attacker 24h | Approval |
| PB-03 | SOC-005 / SOC-006 (malware binary) | Quarantine it | **Auto** |
| PB-04 | SOC-010 / SOC-011 (exfil / C2 traffic) | Block destination 24h | **Auto** |
| PB-05 | Confirmed access (SOC-002 / SOC-007) | Isolate the host | Approval |

**Design principle:** automate cheap, reversible, high-confidence actions (blocking an outside IP). Require a human for high-impact ones (cutting a server off the network can take a business service down). Toggle any playbook between Auto and Approval in the Response Center.

### Guardrails (apply to automation *and* analysts)
- Internal IPs are never blocked (you'd cut off your own machine). Try blocking `10.0.0.5` in the Response Center.
- Allowlisted services (DNS, Microsoft 365, the CDN) are never blocked. Try `8.8.8.8`.
- Critical assets (`db-01`) are never isolated automatically, even if you switch PB-05 to Auto.
- At most 20 automatic blocks per hour, so a runaway rule can't block half the internet.
- Automatic blocks expire after 24h, because attacker IPs get reassigned and permanent lists rot.

Refused actions are audited too, as "Stopped by guardrail".

### Things to try
- **Response Center:** approve isolating `dev-laptop-07`, then replay `--attacks intrusion` and watch its traffic get dropped.
- **Incident page:** the new **Containment** panel has one-click Block / Quarantine / Isolate buttons, and "What happened, step by step" now shows our response (green) between the attacker's moves.
- **Time to contain:** automatic containment takes under 1 second from detection. Approve something by hand and compare: that gap is the case for automation.
- **Audit Log:** filter by Automation vs Analyst. Every triage, rule change, playbook change and ML retrain is there.
- **Lab reset:** "Release all" in the Response Center lifts every block so you can replay attacks.

### Problems found while building it
1. **A confirmed account takeover scored 84 ("high")** when only rules caught it, so the critical auto-block didn't fire. "Confirmed access" now adds +15 instead of +10. An attacker who's *in* should always be critical.
2. **Stale approval requests.** A brute force was "high" after the first batch of logs (PB-02 asked for approval to block), then "critical" a batch later (PB-01 blocked it automatically). The approval request lingered for something already done. Now any containment closes matching pending requests as "skipped".

**Phase 6 checkpoint — can you answer these?**
- Why is blocking an outside IP automatic, but isolating a host needs approval?
- What could go wrong without the "never block internal IPs" guardrail?
- Why do automatic blocks expire after 24 hours instead of lasting forever?
- What does "time to contain" measure, and why do SOC managers care about it?
- Why is the audit log append-only (never edited or deleted)?

## Phase 7 — Attack Simulator page and real-time updates (WebSockets)

No new packages (`uvicorn[standard]` already includes WebSocket support): **Ctrl + C**, then `docker compose up`. Open **Attack Simulator** in the sidebar. You no longer need the terminal to run attacks.

### What's new
- **Attack Simulator page:** 7 attack cards. Each shows the target, the MITRE techniques, whether rules or only ML can catch it, and what the SOC *should* do. Click **Launch attack** and the result appears on the card: events stored, alerts, incidents, auto-containments.
- **Run full demo:** the same as `python simulator\simulator.py`: 30 minutes of normal traffic with all 7 attacks hidden in it.
- **Live traffic:** a background generator streams normal activity every 5 seconds (10-120 events/min), optionally with a random attack every 20-180 s. The sidebar shows a green **LIVE** tag while it runs.
- **Real-time dashboard:** every page now updates the instant something happens. The top-right badge says **Live** when the WebSocket is connected.
- **Notifications:** a pop-up appears on any page when an incident opens, an attacker is auto-contained, or an action needs your approval. Click it to jump there.
- **Lab reset:** *Release all* lifts every block so attacks can be replayed. *Wipe data* deletes events, alerts and incidents for a clean demo; the audit log is kept (an audit log is never deleted), and the reset itself is logged.

### How the real-time part works
```
browser ── opens ws://localhost:8000/ws ──▶ backend      (one connection per tab)
backend ── {"type":"update","feed":[INC-12 opened, IP blocked, ...]} ──▶ every tab
each page ── re-fetches its own data over REST (the usual /api/... calls)
```
- The server pushes small **"something changed" notices**, not the data itself. Pages re-fetch what they show. One source of truth (the REST API) and a tiny protocol.
- **Only one hook changed:** `usePolling` now re-fetches on every push and slows its timer to 30 s while connected. All 10 existing pages became real-time without being edited.
- **Fallback:** if the WebSocket drops (backend restarting), pages go back to polling every few seconds and the client reconnects with backoff. The badge shows *Online · polling* meanwhile.
- **Thread-safety:** most endpoints run in worker threads, but WebSockets live on the asyncio event loop. `hub.publish()` (in `realtime.py`) hands messages to the loop with `run_coroutine_threadsafe`, so it's safe to call from anywhere, including the live-traffic thread.
- **One pipeline:** the CLI, the Launch buttons and the live generator all go through the same `ingest_events()` function, guarded by a lock so two batches can't both open "the new incident" for the same attacker.

### Things to try
1. Open two browser windows side by side: Attack Simulator and Incidents. Launch **Full intrusion** and watch the incident appear in the other window within a second, without refreshing.
2. Launch **SSH brute force** twice. The second time the card warns that the attacker is blocked, and the replay is dropped by the firewall. Click **Unblock** and launch again.
3. Start **Live traffic** with random attacks every 20 s, then go to **Live Events**: rows flash in as they arrive ("Live · pushed instantly").
4. Launch **Slow port scan**: no rule fires, but ML-001 catches it and an incident opens.
5. Stop the backend (Ctrl + C) with the dashboard open. The badge turns *Backend offline*; start it again and everything reconnects by itself.

### Problems found while building it
1. **Live attacks against already-blocked attackers.** Random attacks kept picking IPs the firewall was blocking, so every event was dropped and nothing happened. The generator now prefers attackers that aren't blocked.
2. **"Wipe data" deleted the audit log.** That contradicted Phase 6's rule that an audit log is append-only. Now the wipe keeps every audit entry, unlinks it from deleted incidents, closes stale approval requests, and records itself as an audit entry.

**Phase 7 checkpoint — can you answer these?**
- What's the difference between polling and WebSockets? When is polling good enough?
- Why does the server push "something changed" notices instead of the full data?
- What happens to the dashboard if the WebSocket connection drops?
- Why does `publish()` need `run_coroutine_threadsafe`? (Hint: threads vs the event loop.)
- Why is there a lock around the ingest pipeline?

## Phase 8 — Sign-in, roles and continuous integration

No new packages. `docker-compose.yml` changed (two new settings), so **Ctrl + C**, then `docker compose up`. Your data is kept: the backend adds a `users` table and creates three demo accounts.

Open http://localhost:5173 and you'll get a sign-in page. Click a demo account to sign in with it.

| Account | Password | Role | Can |
|---|---|---|---|
| `admin` | `Admin@123` | admin | everything, incl. rules, playbooks, ML retraining, wiping the lab, managing users |
| `analyst` | `Analyst@123` | analyst | triage alerts and incidents, contain threats, approve playbook actions, run the lab |
| `viewer` | `Viewer@123` | viewer | read-only (a manager or an auditor) |

The simulator now sends an API key (`X-API-Key: lab-ingest-key`). Machines don't log in like people.

### How it works
- **Passwords** are never stored. The database keeps a PBKDF2-SHA256 hash with a random salt and 600,000 iterations (OWASP's recommendation), so a stolen database is very slow to crack. Python standard library only (`auth/security.py`).
- **Sign-in** returns a **JWT** (JSON Web Token) signed with HMAC-SHA256 and valid for 8 hours (one shift). The browser sends it as `Authorization: Bearer …` on every request. The server needs no session table: it checks the signature and the expiry.
- **Every request is checked** against one permission table (`auth/permissions.py`). Routes that aren't listed need *admin* to change anything: **secure by default**. A test fails if someone adds a write endpoint without deciding who may call it.
- **Role changes apply immediately.** The token says who you are; your role is re-read from the database on every request. Disabling an account locks it out at once, even with a valid token.
- **Brute-force protection:** 5 wrong passwords lock the account for 5 minutes. A wrong password and an unknown username give the same answer, and take the same time, so attackers can't discover which accounts exist.
- **The audit log records *who*:** every action now carries the signed-in username. Sign-ins, failed sign-ins and lockouts appear under the new **Access** filter.
- **The WebSocket needs a token too** (`/ws?token=…`), because browsers can't send headers on WebSockets.
- **The UI follows your role:** buttons you can't use show a lock and say which role they need. That's only for convenience: the API enforces the real rules.
- **API docs:** in http://localhost:8000/docs, call `POST /api/auth/login`, copy `access_token`, click **Authorize** and paste it.

### Things to try
1. Sign in as **viewer** and open Attack Simulator: everything is visible, every button is locked.
2. Sign in as **analyst** and approve an isolation in the Response Center. Then, as **admin**, open the Audit Log: the approval shows `analyst` as the person who did it.
3. Type a wrong password 5 times for `viewer`. The account is locked. As admin, check Audit Log → Access, then unlock it in **Users & Access**.
4. As admin, create an account for yourself in **Users & Access**, then change its role while it's signed in elsewhere. The change applies at once.
5. Run `python scripts\smoke_test.py` after the simulator: 8 end-to-end checks of the running stack.

### Continuous integration (GitHub Actions)
`.github/workflows/ci.yml` runs on every push once the project is on GitHub (Phase 9):

| Job | What it proves |
|---|---|
| Backend tests | all 61 tests pass on Python 3.11 |
| Frontend build | `npm ci` + `vite build` succeed (no broken imports) |
| End-to-end on PostgreSQL | a real Postgres + API, the simulator sends all 7 attacks, `smoke_test.py` checks detection, incidents, response and sign-in |
| Docker image | the backend image still builds |

### Problems found while building it
1. **A missing import that the build didn't catch.** The Users icon in the sidebar wasn't imported, and `vite build` still passed: JavaScript only finds undefined names when the code runs. A screenshot test caught it, and a lint pass now checks the whole frontend for undefined names.
2. **"Analyst" meant two things.** The audit log used "Analyst" for *any* human action, so a viewer's sign-in showed as "Analyst". Humans are now shown as "Person", with the username underneath.

**Phase 8 checkpoint — can you answer these?**
- Authentication vs authorization: which is which, and where does each happen in this project?
- Why hash passwords with a salt and many iterations instead of storing them encrypted?
- What stops someone editing their JWT to say `"role": "admin"`?
- Why re-check the user's role in the database when the token already contains it?
- What does "secure by default" mean for the permission table?
- Why do a wrong password and an unknown username return the same error?

## Roadmap
- [x] Phase 1 — Docker, Postgres, FastAPI, ingestion, attack simulator
- [x] Phase 2 — React dashboard: Overview + Live Events
- [x] Phase 3 — Rule engine (11 MITRE-mapped rules) + Alerts + Detection Rules pages + tests
- [x] Phase 4 — ML detection (Isolation Forest + Random Forest), stealthy attacks, ML Models page
- [x] Phase 5 — Incident correlation, risk scoring, kill chain + attack timelines, full-intrusion scenario
- [x] Phase 6 — Automated response: 5 playbooks, guardrails, simulated firewall/EDR, approvals, Response Center, Audit Log
- [x] Phase 7 — Attack Simulator page, live traffic generator, real-time WebSocket updates + notifications
- [x] Phase 8 — Sign-in with roles (viewer / analyst / admin), lockout, API key for ingest, audit by user, GitHub Actions CI
- [ ] Phase 9 — Polish: screenshots, demo video, GitHub
