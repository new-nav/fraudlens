import unittest

from fraudlens.detector import (analyze_collect_request, analyze_message, analyze_transactions,
                                analyze_url, parse_csv_text)
from fraudlens.samples import SAMPLE_MESSAGES, sample_csv_text


class MessageTests(unittest.TestCase):
    def test_fake_kyc_is_high(self):
        v = analyze_message(SAMPLE_MESSAGES["Fake KYC (SMS)"])
        self.assertEqual(v.level, "HIGH")
        codes = {s.code for s in v.signals}
        self.assertIn("KYC_UPDATE", codes)
        self.assertIn("URL_BRAND_LOOKALIKE", codes)

    def test_pin_to_receive_is_high(self):
        v = analyze_message(SAMPLE_MESSAGES["Fake refund (collect)"])
        self.assertEqual(v.level, "HIGH")
        self.assertIn("PIN_TO_RECEIVE", {s.code for s in v.signals})

    def test_digital_arrest(self):
        self.assertEqual(analyze_message(SAMPLE_MESSAGES["Digital arrest"]).level, "HIGH")

    def test_genuine_messages_stay_low(self):
        for name in ("Genuine bank alert", "Genuine OTP"):
            with self.subTest(name):
                self.assertEqual(analyze_message(SAMPLE_MESSAGES[name]).level, "LOW")

    def test_warning_not_to_share_otp_is_not_flagged(self):
        self.assertEqual(analyze_message("Never share your OTP or PIN with anyone.").level, "LOW")

    def test_empty_text(self):
        self.assertEqual(analyze_message("").level, "LOW")


class UrlTests(unittest.TestCase):
    def codes(self, url):
        return {s.code for s in analyze_url(url)}

    def test_official_domain_is_clean(self):
        self.assertEqual(self.codes("https://www.sbi.co.in/web/personal-banking"), set())

    def test_lookalike(self):
        self.assertIn("URL_BRAND_LOOKALIKE", self.codes("https://hdfcbank-secure.top/login"))

    def test_shortener_and_ip(self):
        self.assertIn("URL_SHORTENER", self.codes("https://bit.ly/abc"))
        self.assertIn("URL_IP_HOST", self.codes("http://192.168.4.5/pay"))

    def test_at_sign_trick(self):
        self.assertIn("URL_AT_SIGN", self.codes("https://sbi.co.in@evil.example.com/x"))


class CollectTests(unittest.TestCase):
    def test_expecting_money_is_high(self):
        v = analyze_collect_request("sbi.refund.help@okaxis", 4999, "refund", expecting_money=True)
        self.assertEqual(v.level, "HIGH")

    def test_friend_request_is_not_high_but_still_warned(self):
        v = analyze_collect_request("rahul.sharma@oksbi", 650, "dinner split")
        self.assertNotEqual(v.level, "HIGH")
        self.assertIn("COLLECT_PULLS_MONEY", {s.code for s in v.signals})

    def test_malformed_vpa(self):
        v = analyze_collect_request("not a upi id", 100)
        self.assertIn("VPA_INVALID", {s.code for s in v.signals})


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.alerts = {a.tx.id: a for a in analyze_transactions(parse_csv_text(sample_csv_text()))}

    def flagged_codes(self):
        out = set()
        for a in self.alerts.values():
            if a.verdict.level != "LOW":
                out |= {s.code for s in a.verdict.signals}
        return out

    def test_injected_attacks_are_found(self):
        codes = self.flagged_codes()
        for expected in ("NEW_DEVICE", "RAPID_FIRE", "LOCATION_JUMP", "PASS_THROUGH", "AMOUNT_OUTLIER"):
            self.assertIn(expected, codes)

    def test_most_normal_transactions_are_not_flagged(self):
        flagged = sum(a.verdict.level != "LOW" for a in self.alerts.values())
        self.assertLess(flagged / len(self.alerts), 0.2)

    def test_bad_csv_reports_line(self):
        with self.assertRaises(ValueError) as ctx:
            parse_csv_text("timestamp,amount,direction,counterparty\n2026-10-01 10:00,abc,debit,x@ybl\n")
        self.assertIn("line 2", str(ctx.exception))

    def test_missing_column(self):
        with self.assertRaises(ValueError):
            parse_csv_text("amount,direction\n1,debit\n")


if __name__ == "__main__":
    unittest.main()
