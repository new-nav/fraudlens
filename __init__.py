"""FraudLens - a rule-based scam and fraud detector for UPI payments (demo / educational)."""
from .detector import (  # noqa: F401
    Verdict,
    analyze_collect_request,
    analyze_message,
    analyze_transactions,
    parse_csv_text,
    summarize,
)

__version__ = "1.0.0"
