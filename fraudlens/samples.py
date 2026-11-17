"""Synthetic demo data. Nothing here is real: names, IDs and amounts are invented."""
from __future__ import annotations

import csv
import io
import random
from datetime import datetime, timedelta

from .detector import CSV_COLUMNS

SAMPLE_MESSAGES = {
    "Fake KYC (SMS)": "Dear customer, your SBI account will be blocked today. Update KYC immediately: http://sbi-kyc-update.xyz/login",
    "Fake refund (collect)": "Congratulations! Cashback of Rs 2,000 is ready. Enter your UPI PIN to receive the money within 30 minutes.",
    "Digital arrest": "This is CBI. A case has been registered against your Aadhaar for money laundering. Avoid arrest, join video call and pay settlement.",
    "Task / job scam": "Part time job! Like YouTube videos and earn Rs 5000 per day. Join our Telegram group now.",
    "Genuine bank alert": "Rs 450.00 debited from A/c XX1234 on 12-Nov via UPI to ZOMATO. If not you, call the number on the back of your card. Do not share OTP with anyone.",
    "Genuine OTP": "482913 is your OTP for payment of Rs 899 at Amazon. Do not share this OTP with anyone.",
}

SAMPLE_COLLECT = {
    "Fake refund": {"vpa": "sbi.refund.help@okaxis", "name": "SBI Refund Desk", "amount": 4999, "note": "refund - approve to receive", "expecting_money": True},
    "Friend splitting dinner": {"vpa": "rahul.sharma@oksbi", "name": "Rahul Sharma", "amount": 650, "note": "dinner split", "expecting_money": False},
}


def generate_sample_transactions(seed: int = 7) -> list[dict]:
    """~60 normal transactions for a made-up user plus four injected attack patterns."""
    rng = random.Random(seed)
    start = datetime(2026, 10, 1, 9, 0)
    regular = ["zomato@ybl", "bigbasket@okaxis", "uber@paytm", "jiomart@ybl", "landlord.m@oksbi", "electricity.board@icici", "chai.point@ybl"]
    rows: list[dict] = []

    def add(ts, amount, direction, who, note="", device="dev-A1", city="Pune"):
        rows.append({"timestamp": ts.isoformat(sep=" "), "amount": round(amount, 2), "direction": direction,
                     "counterparty": who, "note": note, "device_id": device, "city": city})

    for day in range(30):
        base = start + timedelta(days=day)
        for _ in range(rng.choice([1, 2, 2, 3])):
            ts = base + timedelta(hours=rng.randint(0, 11), minutes=rng.randint(0, 59))
            add(ts, rng.choice([80, 120, 250, 350, 480, 650, 900, 1200]) * rng.uniform(0.8, 1.2), "debit", rng.choice(regular))
    add(start + timedelta(days=1, hours=1), 45000, "credit", "employer.payroll@icici", "salary")
    add(start + timedelta(days=15, hours=1), 12000, "credit", "mom@oksbi", "gift")

    # Attack 1: late-night large transfer to a new payee from a new device
    add(datetime(2026, 10, 27, 2, 41), 38000, "debit", "quickprofit.invest@ybl", "task deposit", "dev-X9", "Pune")
    # Attack 2: rapid-fire small debits to different new payees
    t = datetime(2026, 10, 28, 15, 2)
    for i, who in enumerate(["wallet.topup1@ybl", "wallet.topup2@ybl", "wallet.topup3@ybl", "wallet.topup4@ybl"]):
        add(t + timedelta(minutes=2 * i), 4900 + i * 20, "debit", who)
    # Attack 3: impossible travel
    add(datetime(2026, 10, 29, 12, 0), 700, "debit", "zomato@ybl", city="Pune")
    add(datetime(2026, 10, 29, 12, 40), 3200, "debit", "shop.gadgets@paytm", device="dev-A1", city="Kolkata")
    # Attack 4: scam lure in the note + pass-through
    add(datetime(2026, 10, 30, 10, 0), 9500, "credit", "unknown.sender@ybl", "sent by mistake please return")
    add(datetime(2026, 10, 30, 10, 6), 9400, "debit", "refund.helpdesk@okaxis", "return money - wrongly sent")

    rows.sort(key=lambda r: r["timestamp"])
    for i, r in enumerate(rows, start=1):
        r["id"] = f"T{i:03d}"
    return rows


def sample_csv_text(seed: int = 7) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(generate_sample_transactions(seed))
    return buf.getvalue()
