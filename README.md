# 🔍 FraudLens — Scam & Fraud Detector for UPI

FraudLens helps ordinary people spot money scams **before** they lose money. It checks three things and explains every verdict in plain words:

| Check | What it catches |
|---|---|
| **Message / SMS** | Fake KYC updates, "enter PIN to receive refund", lottery/prize claims, fake police / "digital arrest" threats, remote-access app requests (AnyDesk…), APK installs, task/job scams, advance-fee loans. Also inspects links: look-alike bank domains (`sbi-kyc-update.xyz`), URL shorteners, raw-IP links, `@` tricks, odd domain endings. |
| **UPI collect request** | A collect request *pulls* money out of your account. Flags unknown handles, "refund/support/SBI"-style UPI IDs, unusually large amounts, and the key red flag: *"I'm about to **receive** money"* (you never approve anything to receive money). |
| **Transactions** | Scans a CSV for outlier amounts, first-time payees, night-time transfers, rapid-fire debits, new devices, impossible travel between cities, mule-style pass-through (money in → out within minutes), duplicates, and scam-text notes. |

Every result has a risk score (Looks safe / Suspicious / Likely scam), the **reasons** behind it, and **what to do next** (e.g. call **1930**, the national cyber-fraud helpline, or report at cybercrime.gov.in).

> ⚠️ Educational project. It uses transparent rules and **synthetic data only**. It can miss scams and can raise false alarms. Never commit real bank details, PAN, passwords or API keys.

## Quick start

Requires **Python 3.9+**. No packages to install.

```bash
git clone https://github.com/<your-username>/fraudlens.git
cd fraudlens

# 1. Web app (opens at http://127.0.0.1:8000)
python3 -m fraudlens serve

# 2. Or use the command line
python3 -m fraudlens demo                                   # run on built-in examples
python3 -m fraudlens message "Your SBI account is blocked. Update KYC: http://sbi-kyc.xyz"
python3 -m fraudlens collect --vpa sbi.refund@okaxis --amount 4999 --note "refund" --expecting
python3 -m fraudlens transactions --sample                  # synthetic data
python3 -m fraudlens transactions data/sample_transactions.csv
```

Run the tests: `python3 -m unittest discover -s tests -v`

### Transactions CSV format

```
id,timestamp,amount,direction,counterparty,note,device_id,city
T001,2026-10-01 09:15,250.00,debit,zomato@ybl,,dev-A1,Pune
```
`direction` is `debit` or `credit`; `timestamp` is ISO format; `id`, `note`, `device_id`, `city` are optional. The "new payee / new device" rules switch on after the first 10 transactions (the history).

## How it works

```
fraudlens/
  detector.py   rules + scoring (message, URL, collect request, transactions)
  samples.py    synthetic messages and a generated 30-day transaction history with 4 injected attacks
  server.py     small standard-library web server + JSON API (/api/message, /api/collect, /api/transactions)
  static/       single-page web UI
  cli.py        command line
tests/          unit tests
```

Each rule produces a **Signal** with a weight (0–1). Signals are combined with a noisy-OR (`risk = 1 − ∏(1 − wᵢ)`), so several weak hints add up but can never exceed 100%. Scores ≥ 65% are *Likely scam*, ≥ 35% *Suspicious*. Warnings like "Do not share your OTP" are removed before matching so genuine bank messages are not flagged. All rules are plain, readable Python in `detector.py`, so they are easy to tune.

## Privacy

The app runs locally, has no database, makes no network calls, and does not log message contents.

## Ideas for next steps

- Add a machine-learning classifier trained on a public SMS-spam dataset and blend it with the rules.
- Support Hindi / Hinglish scam phrases.
- Check URLs against a live phishing blocklist.
- Add a "report this scam" helper that pre-fills the cybercrime.gov.in complaint.

## Helplines (India)

Cyber-fraud helpline **1930** · Report online: **cybercrime.gov.in** · Call your bank immediately to freeze UPI / cards.

## License

MIT — see [LICENSE](LICENSE).
## 🛠️ Tech Stack, APIs & AI Disclosure

* **AI Coding Assistant:** Built with **[Claude](https://claude.ai)** by Anthropic for code generation, rule logic design, and documentation.
* **External APIs:** None — this project makes zero external network calls and requires no third-party API keys.
* **Internal Local API:** Powered by Python's built-in `http.server` (`fraudlens/server.py`), exposing local JSON endpoints (`/api/message`, `/api/collect`, `/api/transactions`, and `/api/samples`) to connect the frontend to the detection engine.
* **Core Technologies:** Python 3.9+ (Standard Library only) and vanilla HTML/CSS/JavaScript.
## 🎥 Demo video
Watch the demo here: [FraudLens demo video](https://youtu.be/gw5yIYvpUYw?si=ehLDWPj0IwZx2V0N)
