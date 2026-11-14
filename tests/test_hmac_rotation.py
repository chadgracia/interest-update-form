"""HMAC_SECRET rotation on the interest form: current key, legacy key
(HMAC_SECRET_OLD, accepted for every action here), empty key. Fake keys only;
no AWS, Pipeline or email."""
import os
import sys
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
if "boto3" not in sys.modules:
    try:
        import boto3  # noqa: F401
    except ImportError:
        sys.modules["boto3"] = types.SimpleNamespace(client=lambda *a, **k: None)
import lambda_function as lf

NEW, OLD = "test-new-hmac", "test-old-hmac"
FORM_PAGE = {"statusCode": 200, "body": "FORM"}


class Rotation(unittest.TestCase):
    def setUp(self):
        mock.patch.object(lf, "HMAC_SECRET", NEW).start()
        mock.patch.object(lf, "HMAC_SECRET_OLD", OLD).start()
        mock.patch.object(lf, "get_jwt", return_value="jwt").start()
        mock.patch.object(lf, "call_pipeline_api",
                          return_value={"status": 200, "data": {"id": 7}}).start()
        mock.patch.object(lf, "load_security_maps", return_value={}).start()
        self.render = mock.patch.object(lf, "render_form", return_value=FORM_PAGE).start()
        self.stop = mock.patch.object(lf, "stop_daily_updates", return_value={"statusCode": 200, "body": "STOPPED"}).start()
        self.email = mock.patch.object(lf, "send_email").start()
        self.addCleanup(mock.patch.stopall)

    def test_signs_with_current_key_only(self):
        self.assertEqual(lf.make_token(7), lf._sign(NEW, 7))

    def test_current_token_opens_form(self):
        self.assertEqual(lf.handle_get({"person_id": "7", "token": lf._sign(NEW, 7)}), FORM_PAGE)

    def test_legacy_token_opens_form_and_unsubscribe_page(self):
        self.assertEqual(lf.handle_get({"person_id": "7", "token": lf._sign(OLD, 7)}), FORM_PAGE)
        r = lf.handle_get({"action": "unsubscribe", "person_id": "7", "token": lf._sign(OLD, 7)})
        self.assertIn("Stop updates", r["body"])

    def test_legacy_token_saves(self):
        r = lf.handle_post(f"person_id=7&token={lf._sign(OLD, 7)}&submit_action=stop_updates")
        self.assertEqual(r["body"], "STOPPED")
        self.stop.assert_called_once_with(7, "jwt")

    def test_wrong_token_refused(self):
        r = lf.handle_get({"person_id": "7", "token": lf._sign("test-other", 7)})
        self.assertIn("Invalid or expired link.", r["body"])
        self.render.assert_not_called()

    def test_legacy_off_without_old_key(self):
        with mock.patch.object(lf, "HMAC_SECRET_OLD", ""):
            self.assertFalse(lf.verify_token(7, lf._sign(OLD, 7)))

    def test_empty_key_fails_closed(self):
        with mock.patch.object(lf, "HMAC_SECRET", ""):
            self.assertEqual(lf.make_token(7), "")
            for tok in ("", lf._sign("", 7), lf._sign(OLD, 7), lf._sign(NEW, 7)):
                self.assertFalse(lf.verify_token(7, tok))
            r = lf.handle_post(f"person_id=7&token={lf._sign(OLD, 7)}&submit_action=stop_updates")
            self.assertIn("Invalid or expired link.", r["body"])
        self.stop.assert_not_called()
        self.email.assert_not_called()


if __name__ == "__main__":
    unittest.main()
