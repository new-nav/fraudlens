"""Rule-based scam and fraud detection for UPI-style payments.

Three analysers share one scoring model:

* analyze_message()       - SMS / WhatsApp / email text (phishing, fake KYC, ...)
* analyze_collect_request() - a UPI "collect" (pull) request
* analyze_transactions()  - a list of transactions (anomalies, mule patterns)

Every analyser returns a Verdict made of human-readable Signals, so the user
always sees *why* something was flagged. Standard library only.
"""
from __future__ import annotations

import csv
import io
import re
import statistics
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable
from urllib.parse import urlparse

HIGH_THRESHOLD = 0.65
MEDIUM_THRESHOLD = 0.35

LABELS = {"LOW": "Looks safe", "MEDIUM": "Suspicious", "HIGH": "Likely scam"}


# --------------------------------------------------------------------------
# Scoring model
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Signal:
    code: str
    weight: float  # 0..1, how strongly this alone suggests fraud
    title: str
    detail: str

    def to_dict(self) -> dict:
        return {"code": self.code, "weight": self.weight, "title": self.title, "detail": self.detail}


@dataclass
class Verdict:
    score: float
    level: str
    signals: list[Signal]
    advice: list[str]

    @property
    def label(self) -> str:
        return LABELS[self.level]

    def to_dict(self) -> dict:
        return {
            "score": round(self.score, 2),
            "level": self.level,
            "label": self.label,
            "signals": [s.to_dict() for s in self.signals],
            "advice": self.advice,
        }


def combine(signals: Iterable[Signal]) -> float:
    """Noisy-OR: independent signals add up but never exceed 1.0."""
    p_safe = 1.0
    for s in signals:
        p_safe *= 1.0 - s.weight
    return 1.0 - p_safe


def level_for(score: float) -> str:
    if score >= HIGH_THRESHOLD:
        return "HIGH"
    if score >= MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def _dedupe(signals: Iterable[Signal]) -> list[Signal]:
    best: dict[str, Signal] = {}
    for s in signals:
        if s.code not in best or s.weight > best[s.code].weight:
            best[s.code] = s
    return sorted(best.values(), key=lambda s: -s.weight)


_GENERAL_ADVICE = {
    "HIGH": [
        "Do NOT pay, click, reply or share anything.",
        "Report it: call 1930 or visit cybercrime.gov.in (India's cyber-fraud helpline).",
    ],
    "MEDIUM": [
        "Pause. Verify using the official app or the number printed on your card, not the one in the message.",
    ],
    "LOW": [
        "No common scam patterns found, but no tool is perfect. If money or secrets are involved, verify independently.",
    ],
}


def make_verdict(signals: Iterable[Signal], extra_advice: Iterable[str] = ()) -> Verdict:
    sigs = _dedupe(signals)
    score = combine(sigs)
    level = level_for(score)
    advice: list[str] = []
    for a in list(extra_advice) + _GENERAL_ADVICE[level]:
        if a and a not in advice:
            advice.append(a)
    return Verdict(score, level, sigs, advice[:5])


# --------------------------------------------------------------------------
# 1. Message analysis
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Rule:
    code: str
    weight: float
    title: str
    detail: str
    advice: str = ""
    any_of: tuple[str, ...] = ()  # at least one must match (if non-empty)
    all_of: tuple[str, ...] = ()  # every one must match


MESSAGE_RULES: tuple[Rule, ...] = (
    Rule(
        "PIN_TO_RECEIVE", 0.80,
        "Asks for a PIN to 'receive' money",
        "You never need a UPI PIN to receive money. A PIN is only ever used to send it.",
        "Never enter your UPI PIN to receive money, refund or cashback.",
        any_of=(
            r"\b(enter|put|type|use|share)\b[^.\n]{0,40}\bpin\b[^.\n]{0,40}\b(receive|credit|refund|cashback|get)\b",
            r"\b(receive|credit|refund|cashback)\b[^.\n]{0,60}\b(enter|put|type|use|share)\b[^.\n]{0,30}\bpin\b",
        ),
    ),
    Rule(
        "ASKS_SECRET", 0.50,
        "Asks for OTP / PIN / CVV / password",
        "Banks and genuine companies never ask you to share these, by message or on a call.",
        "Never share OTP, PIN, CVV or passwords with anyone, even 'bank staff'.",
        any_of=(
            r"\b(share|send|enter|tell|provide|confirm|verify|reply with|give|read out)\b[^.\n]{0,40}"
            r"\b(otp|upi pin|mpin|pin|cvv|password|passcode|card number|expiry)\b",
        ),
    ),
    Rule(
        "COLLECT_LURE", 0.35,
        "Mentions approving a payment request",
        "A 'collect request' pulls money OUT of your account when you approve it.",
        "Decline collect requests you did not start yourself.",
        any_of=(
            r"\bcollect (money )?request\b",
            r"\b(approve|accept|authori[sz]e)\b[^.\n]{0,25}\b(request|collect)\b",
            r"\bpayment request\b",
        ),
    ),
    Rule(
        "URGENCY", 0.20,
        "Creates false urgency",
        "Scammers rush you so you don't stop to think.",
        "",
        any_of=(
            r"\b(immediately|urgent(ly)?|today only|last (chance|warning|reminder)|act now|asap|final notice)\b",
            r"\bwithin \d+ ?(hours?|hrs|minutes?|mins)\b",
            r"\bexpires? (today|soon|tonight)\b",
        ),
    ),
    Rule(
        "ACCOUNT_THREAT", 0.30,
        "Threatens to block or close your account",
        "Banks do not threaten account closure through links or phone numbers in an SMS.",
        "Check your account only through the official bank app.",
        any_of=(
            r"\b(account|card|upi|wallet|sim|kyc|pan|aadhaar|aadhar)\b[^.\n]{0,40}"
            r"\b(block(ed)?|suspend(ed)?|deactivat(ed)?|froze[n]?|freez\w*|clos(e|ed|ure)|expire[sd]?)\b",
        ),
    ),
    Rule(
        "KYC_UPDATE", 0.35,
        "Asks you to 'update' KYC / PAN / Aadhaar",
        "KYC update links in SMS are one of the most common phishing lures.",
        "Complete KYC only at your bank branch or in its official app.",
        any_of=(r"\b(update|complete|verify|renew|re-?verify)\b[^.\n]{0,20}\b(kyc|pan|aadhaar|aadhar)\b",),
    ),
    Rule(
        "PRIZE_LOTTERY", 0.40,
        "Prize, lottery or lucky-draw claim",
        "You cannot win a contest you never entered.",
        "",
        any_of=(
            r"\byou('ve| have)? (won|been selected)\b",
            r"\b(lucky (draw|winner)|lottery|jackpot)\b",
            r"\bcongratulations\b[^.\n]{0,40}(rs\.?|₹|prize|reward|gift)",
        ),
    ),
    Rule(
        "REWARD_CLAIM", 0.20,
        "Cashback / reward claim with a deadline",
        "Fake 'reward points expiring' messages lead to phishing pages.",
        "",
        any_of=(r"\b(cashback|reward points?|gift voucher|scratch card)\b[^.\n]{0,40}\b(claim|redeem|expire|click)\b",),
    ),
    Rule(
        "AUTHORITY_THREAT", 0.70,
        "Impersonates police / agency and threatens arrest",
        "Genuine agencies never arrest people or collect money over a call or message ('digital arrest' is a scam).",
        "Hang up. No agency settles cases over UPI or video call.",
        any_of=(r"\b(cbi|police|customs|rbi|income tax|narcotics|trai|cyber ?crime|enforcement directorate)\b",),
        all_of=(r"\b(arrest|legal action|warrant|fir|court|seiz\w*|money laundering|digital arrest|case (has been )?(registered|filed))\b",),
    ),
    Rule(
        "REMOTE_ACCESS_APP", 0.60,
        "Asks you to install a remote-access / screen-share app",
        "AnyDesk, TeamViewer, QuickSupport etc. let a stranger see your screen and OTPs.",
        "Never install apps or share your screen on someone's request.",
        any_of=(r"\b(anydesk|team ?viewer|quick ?support|rustdesk|screen ?shar\w*)\b",),
    ),
    Rule(
        "APK_INSTALL", 0.50,
        "Asks you to install an app outside the Play Store",
        "APK files sent by message often contain malware that reads your SMS and banking apps.",
        "Install apps only from the official Play Store / App Store.",
        any_of=(r"\.apk\b", r"\binstall (this|the) app\b", r"\bdownload\b[^.\n]{0,20}\bapk\b"),
    ),
    Rule(
        "WRONG_TRANSFER_REFUND", 0.40,
        "'Sent by mistake - please return' pattern",
        "Scammers send a small amount, then ask for a bigger 'refund', or use the story to get you to approve a collect request.",
        "Ask your bank to reverse a mistaken credit; never return it yourself.",
        any_of=(
            r"\b(sent|transferred|credited)\b[^.\n]{0,30}\b(by mistake|wrongly|wrong number)\b",
            r"\bplease (return|refund|send back)\b",
        ),
    ),
    Rule(
        "JOB_TASK_SCAM", 0.45,
        "Easy-money job / task offer",
        "'Like videos and earn' or 'work from home' offers are task scams that start small and then demand deposits.",
        "Never pay a deposit or 'unlock fee' to earn money.",
        any_of=(
            r"\b(work from home|part[- ]time job)\b",
            r"\bearn\b[^.\n]{0,15}\d[\d,]*\b[^.\n]{0,10}\b(per|a|/) ?day\b",
            r"\b(like|subscribe)\b[^.\n]{0,20}\b(videos?|channels?)\b",
            r"\btelegram group\b",
        ),
    ),
    Rule(
        "LOAN_UPFRONT_FEE", 0.35,
        "Loan 'approved' but a fee is needed first",
        "Real lenders deduct fees from the loan; they do not ask for money before disbursal.",
        "",
        any_of=(r"\b(loan (approved|sanctioned)|pre-?approved loan)\b",),
        all_of=(r"\b(fee|processing|insurance|advance|deposit)\b",),
    ),
    Rule(
        "UTILITY_DISCONNECT", 0.35,
        "'Your power / gas will be cut tonight' warning",
        "A well-known scam: a mobile number to 'update' an unpaid bill.",
        "Check bills on the utility's official website or app.",
        any_of=(r"\b(electricity|power|gas)\b[^.\n]{0,15}\b(bill|connection)\b[^.\n]{0,40}\b(disconnect\w*|tonight|cut)\b",),
    ),
    Rule(
        "CALL_UNKNOWN_NUMBER", 0.15,
        "Tells you to call/WhatsApp a mobile number",
        "Official numbers are printed on your card or on the bank's site, not in a random message.",
        "",
        any_of=(r"\b(call|contact|whatsapp|text)\b[^.\n]{0,25}\+?\d[\d\s-]{8,}",),
    ),
)

_COMPILED = {r.code: ([re.compile(p, re.I) for p in r.any_of], [re.compile(p, re.I) for p in r.all_of]) for r in MESSAGE_RULES}

# "Do not share your OTP with anyone" is a *warning*, so remove those clauses first.
_NEGATION = re.compile(r"\b(do not|don't|dont|never|not to)\s+(share|disclose|give|reveal|tell)\b[^.\n]*", re.I)

SHORTENERS = {"bit.ly", "tinyurl.com", "cutt.ly", "t.co", "rb.gy", "is.gd", "goo.gl", "shorturl.at", "tiny.cc", "ow.ly", "t.ly", "rebrand.ly"}
SUSPICIOUS_TLDS = {"xyz", "top", "click", "icu", "live", "vip", "cfd", "site", "online", "link", "shop", "cc", "tk", "ml", "ga", "cf", "buzz", "monster"}

# brand keyword -> official domains
OFFICIAL_DOMAINS: dict[str, tuple[str, ...]] = {
    "sbi": ("sbi.co.in", "onlinesbi.sbi", "sbicard.com", "sbi.bank.in"),
    "hdfc": ("hdfcbank.com", "hdfc.com", "hdfcbank.bank.in"),
    "icici": ("icicibank.com", "icici.bank.in"),
    "axis": ("axisbank.com", "axis.bank.in"),
    "kotak": ("kotak.com",),
    "pnb": ("pnbindia.in",),
    "paytm": ("paytm.com",),
    "phonepe": ("phonepe.com",),
    "gpay": ("pay.google.com",),
    "bhim": ("bhimupi.org.in",),
    "npci": ("npci.org.in",),
    "irctc": ("irctc.co.in",),
    "incometax": ("incometax.gov.in",),
    "amazon": ("amazon.in", "amazon.com"),
    "flipkart": ("flipkart.com",),
}

_URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"']+"
    r"|\b(?:[a-z0-9-]+\.)+(?:" + "|".join(sorted(SUSPICIOUS_TLDS)) + r")\b[^\s<>\"']*"
    r"|\b(?:" + "|".join(re.escape(s) for s in SHORTENERS) + r")/[^\s<>\"']*",
    re.I,
)


def extract_urls(text: str) -> list[str]:
    return [u.rstrip(".,);]") for u in _URL_RE.findall(text)]


def _is_ip(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))


def analyze_url(url: str) -> list[Signal]:
    raw = url if re.match(r"https?://", url, re.I) else "http://" + url
    explicit_http = url.lower().startswith("http://")
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    out: list[Signal] = []
    if not host:
        return out
    if "@" in (parsed.netloc or ""):
        out.append(Signal("URL_AT_SIGN", 0.40, "Link hides its real destination with '@'", f"{url}"))
    if host in SHORTENERS:
        out.append(Signal("URL_SHORTENER", 0.30, "Shortened link hides the destination", f"{host} can point anywhere."))
    if _is_ip(host):
        out.append(Signal("URL_IP_HOST", 0.45, "Link goes to a raw IP address", f"{host} is not a real brand website."))
    if "xn--" in host:
        out.append(Signal("URL_PUNYCODE", 0.40, "Look-alike (punycode) domain", f"{host} may imitate a real site with foreign characters."))
    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        out.append(Signal("URL_ODD_TLD", 0.30, f"Unusual domain ending '.{tld}'", f"{host} - banks use .com / .in / .bank.in, not this."))
    tokens = re.split(r"[.\-_]", host)
    for brand, official in OFFICIAL_DOMAINS.items():
        if any(t == brand or t.startswith(brand) for t in tokens):
            if not any(host == d or host.endswith("." + d) for d in official):
                out.append(Signal(
                    "URL_BRAND_LOOKALIKE", 0.55, f"Pretends to be {brand.upper()}",
                    f"{host} is not an official {brand.upper()} domain (official: {', '.join(official)}).",
                ))
                break
    if host.count("-") >= 3 or host.count(".") >= 4:
        out.append(Signal("URL_MESSY_HOST", 0.15, "Long, cluttered domain name", host))
    if explicit_http:
        out.append(Signal("URL_NO_HTTPS", 0.15, "Link is not encrypted (http://)", host))
    return out


def analyze_message(text: str) -> Verdict:
    """Score an SMS / chat / email text for phishing and scam patterns."""
    text = (text or "")[:5000]
    cleaned = _NEGATION.sub(" ", text)
    signals: list[Signal] = []
    advice: list[str] = []
    for rule in MESSAGE_RULES:
        any_res, all_res = _COMPILED[rule.code]
        if any_res and not any(r.search(cleaned) for r in any_res):
            continue
        if not all(r.search(cleaned) for r in all_res):
            continue
        signals.append(Signal(rule.code, rule.weight, rule.title, rule.detail))
        advice.append(rule.advice)
    for url in extract_urls(text):
        signals.extend(analyze_url(url))
    return make_verdict(signals, advice)


# --------------------------------------------------------------------------
# 2. UPI collect-request analysis
# --------------------------------------------------------------------------
KNOWN_HANDLES = {
    "ybl", "ibl", "axl", "okaxis", "oksbi", "okhdfcbank", "okicici", "paytm", "apl", "upi", "sbi",
    "hdfcbank", "icici", "axisbank", "kotak", "pnb", "boi", "cnrb", "fbl", "pthdfc", "ptyes", "ptsbi",
    "yesbank", "idfcbank", "indus", "federal", "unionbank", "barodampay", "waicici", "wahdfcbank",
}
_VPA_RE = re.compile(r"^[a-z0-9][a-z0-9.\-_]{1,255}@[a-z][a-z0-9]{1,63}$", re.I)
_VPA_BAD_WORDS = re.compile(
    r"(sbi|hdfc|icici|axis|paytm|phonepe|gpay|npci|rbi|support|helpdesk|care|refund|customer|official|kyc|reward|cashback|lottery|prize|verify|service)",
    re.I,
)


def analyze_collect_request(
    payee_vpa: str,
    amount: float,
    note: str = "",
    payee_name: str = "",
    expecting_money: bool = False,
    typical_amount: float | None = None,
) -> Verdict:
    """Score an incoming UPI collect (pull) request before you approve it."""
    signals: list[Signal] = [Signal(
        "COLLECT_PULLS_MONEY", 0.30, "This is a collect (pull) request",
        "Approving it with your PIN sends money OUT of your account - it never brings money in.",
    )]
    advice = ["Decline any collect request you did not start yourself."]

    if expecting_money:
        signals.append(Signal(
            "EXPECTING_MONEY", 0.60, "You think you are about to RECEIVE money",
            "Receiving money needs no approval and no PIN. This is the classic fake-refund trick.",
        ))
        advice.insert(0, "If someone says 'approve this to get your money', it is a scam.")

    vpa = (payee_vpa or "").strip()
    if not _VPA_RE.match(vpa):
        signals.append(Signal("VPA_INVALID", 0.40, "Payee UPI ID looks malformed", f"'{vpa}' is not a normal UPI ID (name@bank)."))
    else:
        local, handle = vpa.lower().split("@", 1)
        if handle not in KNOWN_HANDLES:
            signals.append(Signal("VPA_UNKNOWN_HANDLE", 0.20, f"Unfamiliar UPI handle '@{handle}'", "Not one of the common UPI handles."))
        if _VPA_BAD_WORDS.search(local):
            signals.append(Signal(
                "VPA_IMPERSONATION", 0.45, "UPI ID uses bank / support / refund words",
                f"'{local}' sounds official, but anyone can register such an ID.",
            ))

    if amount >= 10000:
        signals.append(Signal("AMOUNT_LARGE", 0.15, "Large amount", f"Rs {amount:,.0f} will leave your account."))
    if typical_amount and amount > 5 * typical_amount:
        signals.append(Signal("AMOUNT_UNUSUAL", 0.20, "Much bigger than your usual payment", f"Rs {amount:,.0f} vs your typical Rs {typical_amount:,.0f}."))

    if note:
        note_verdict = analyze_message(note)
        if note_verdict.score >= MEDIUM_THRESHOLD:
            signals.append(Signal("NOTE_SCAM_TEXT", 0.40, "Request note reads like a scam message", note[:120]))
        elif re.search(r"\b(refund|cashback|prize|reward|receive|claim|verification|kyc)\b", note, re.I):
            signals.append(Signal("NOTE_LURE_WORD", 0.35, "Note promises a refund / reward", note[:120]))
    return make_verdict(signals, advice)


# --------------------------------------------------------------------------
# 3. Transaction analysis
# --------------------------------------------------------------------------
@dataclass
class Transaction:
    id: str
    timestamp: datetime
    amount: float
    direction: str  # "debit" or "credit"
    counterparty: str
    note: str = ""
    device_id: str = ""
    city: str = ""


@dataclass
class TxAlert:
    tx: Transaction
    verdict: Verdict

    def to_dict(self) -> dict:
        t = self.tx
        return {
            "id": t.id, "timestamp": t.timestamp.isoformat(sep=" "), "amount": t.amount,
            "direction": t.direction, "counterparty": t.counterparty, "note": t.note,
            "device_id": t.device_id, "city": t.city, **self.verdict.to_dict(),
        }


CSV_COLUMNS = ["id", "timestamp", "amount", "direction", "counterparty", "note", "device_id", "city"]


def parse_transactions(rows: Iterable[dict]) -> list[Transaction]:
    txns: list[Transaction] = []
    for i, row in enumerate(rows, start=2):  # row 1 is the CSV header
        try:
            direction = (row.get("direction") or "").strip().lower()
            if direction not in ("debit", "credit"):
                raise ValueError("direction must be 'debit' or 'credit'")
            amount = float(row["amount"])
            if amount <= 0:
                raise ValueError("amount must be positive")
            txns.append(Transaction(
                id=(row.get("id") or f"row{i}").strip(),
                timestamp=datetime.fromisoformat(row["timestamp"].strip()),
                amount=amount,
                direction=direction,
                counterparty=(row.get("counterparty") or "").strip().lower(),
                note=(row.get("note") or "").strip(),
                device_id=(row.get("device_id") or "").strip(),
                city=(row.get("city") or "").strip(),
            ))
        except (KeyError, ValueError, AttributeError) as exc:
            raise ValueError(f"CSV line {i}: {exc}") from exc
    return txns


def parse_csv_text(text: str) -> list[Transaction]:
    reader = csv.DictReader(io.StringIO(text))
    missing = {"timestamp", "amount", "direction", "counterparty"} - set(reader.fieldnames or [])
    if missing:
        raise ValueError(f"CSV is missing column(s): {', '.join(sorted(missing))}")
    return parse_transactions(reader)


def analyze_transactions(txns: list[Transaction], min_history: int = 10) -> list[TxAlert]:
    """Score every transaction. Needs some history (min_history) before 'new X' rules apply."""
    txns = sorted(txns, key=lambda t: t.timestamp)
    debit_amounts = [t.amount for t in txns if t.direction == "debit"]
    median = statistics.median(debit_amounts) if debit_amounts else 0.0
    mad = statistics.median([abs(a - median) for a in debit_amounts]) if debit_amounts else 0.0
    big_threshold = max(median * 5, median + 6 * 1.4826 * mad)

    seen_payees: set[str] = set()
    seen_devices: set[str] = set()
    alerts: list[TxAlert] = []

    for i, t in enumerate(txns):
        signals: list[Signal] = []
        has_history = i >= min_history
        is_debit = t.direction == "debit"

        if is_debit:
            if t.amount >= 2000 and t.amount > big_threshold:
                signals.append(Signal("AMOUNT_OUTLIER", 0.35, "Far larger than your usual spending",
                                      f"Rs {t.amount:,.0f} vs typical Rs {median:,.0f}."))
            if has_history and t.counterparty and t.counterparty not in seen_payees:
                weight = 0.30 if t.amount >= max(5000, 2 * median) else 0.10
                signals.append(Signal("NEW_PAYEE", weight, "First payment to this payee",
                                      f"{t.counterparty} has not been paid before."))
            if t.timestamp.hour < 5 and t.amount >= 2000:
                signals.append(Signal("NIGHT_TRANSFER", 0.20, "Large payment in the small hours",
                                      f"At {t.timestamp:%H:%M}."))
            window = [u for u in txns[: i + 1] if u.direction == "debit" and t.timestamp - u.timestamp <= timedelta(minutes=10)]
            if len(window) >= 3:
                signals.append(Signal("RAPID_FIRE", 0.35, "Many payments within 10 minutes",
                                      f"{len(window)} debits back-to-back - a typical account-drain pattern."))
            if has_history and t.device_id and t.device_id not in seen_devices:
                signals.append(Signal("NEW_DEVICE", 0.25, "Payment from a device not seen before", t.device_id))
            for u in reversed(txns[:i]):
                if t.timestamp - u.timestamp > timedelta(minutes=15):
                    break
                if (u.direction == "credit" and t.amount >= 1000 and t.amount >= 0.9 * u.amount
                        and t.counterparty != u.counterparty):
                    signals.append(Signal("PASS_THROUGH", 0.30, "Money moved out right after arriving",
                                          f"Rs {u.amount:,.0f} credited then ~all sent on within 15 minutes (mule pattern)."))
                    break
            prev_debits = [u for u in txns[:i] if u.direction == "debit"]
            if prev_debits:
                p = prev_debits[-1]
                if (p.counterparty == t.counterparty and p.amount == t.amount
                        and t.timestamp - p.timestamp <= timedelta(minutes=3)):
                    signals.append(Signal("DUPLICATE", 0.20, "Same amount to same payee twice in 3 minutes", t.counterparty))
            if t.note and analyze_message(t.note).score >= MEDIUM_THRESHOLD:
                signals.append(Signal("NOTE_SCAM_TEXT", 0.35, "Payment note reads like a scam lure", t.note[:120]))
        if i > 0 and t.city:
            p = txns[i - 1]
            if p.city and p.city != t.city and t.timestamp - p.timestamp < timedelta(hours=2):
                signals.append(Signal("LOCATION_JUMP", 0.45, "Impossible travel",
                                      f"{p.city} -> {t.city} in {int((t.timestamp - p.timestamp).total_seconds() // 60)} min."))

        alerts.append(TxAlert(t, make_verdict(signals, ["Freeze UPI in your bank app and call 1930 if you did not make this payment."] if signals else [])))
        if t.counterparty and is_debit:
            seen_payees.add(t.counterparty)
        if t.device_id:
            seen_devices.add(t.device_id)
    return alerts


def summarize(alerts: list[TxAlert]) -> dict:
    flagged = [a for a in alerts if a.verdict.level != "LOW"]
    return {
        "total": len(alerts),
        "flagged": len(flagged),
        "high": sum(a.verdict.level == "HIGH" for a in alerts),
        "medium": sum(a.verdict.level == "MEDIUM" for a in alerts),
        "amount_at_risk": round(sum(a.tx.amount for a in flagged if a.tx.direction == "debit"), 2),
    }
