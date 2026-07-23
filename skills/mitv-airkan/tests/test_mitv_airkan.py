import argparse
import importlib.util
import json
import os
import random
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).parents[1] / "scripts" / "mitv_airkan.py"
SPEC = importlib.util.spec_from_file_location("mitv_airkan", MODULE_PATH)
mitv = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(mitv)


@unittest.skipIf(mitv.CRYPTO_IMPORT_ERROR is not None, "cryptography is unavailable")
class AirkanProtocolTests(unittest.TestCase):
    def test_custom_base64_uses_dollar_padding(self):
        encoded = mitv.custom_b64encode(b"airkan")
        self.assertEqual(encoded, "YWlya2Fu")
        self.assertEqual(mitv.custom_b64encode(b"tv"), "dHY$")
        self.assertEqual(mitv.custom_b64decode("dHY$"), b"tv")

    def test_magic_is_deterministic_and_six_digits(self):
        value = mitv.make_magic(random.Random(7))
        self.assertEqual(value, 220625)
        self.assertGreaterEqual(value, 100000)
        self.assertLessEqual(value, 999999)

    def test_cbc_derivation_matches_frozen_vector(self):
        key, iv = mitv.derive_cbc_material("ABC123suffix")
        self.assertEqual(key, "Ot/fXC1gIlFjswLG")
        self.assertEqual(iv, "h7lQc5AZ8mpMxCEJ")

    def test_raw_rsa_round_trip(self):
        private_key = mitv.rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_text = mitv.custom_b64encode(
            private_key.public_key().public_bytes(
                mitv.serialization.Encoding.DER,
                mitv.serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        plaintext = "airkanserial_num=42"
        encrypted = mitv.custom_b64decode(mitv.raw_rsa_encrypt(plaintext, public_text))
        numbers = private_key.private_numbers()
        decoded = pow(
            int.from_bytes(encrypted, "big"), numbers.d, numbers.public_numbers.n
        ).to_bytes((numbers.public_numbers.n.bit_length() + 7) // 8, "big")
        self.assertTrue(decoded.endswith(plaintext.encode()))
        self.assertEqual(decoded[: -len(plaintext)], bytes(len(decoded) - len(plaintext)))

    def test_auth_complete_builds_private_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            pending_path = mitv.pending_path(state_path)
            identity = mitv.generate_identity()
            tv_private = mitv.rsa.generate_private_key(public_exponent=65537, key_size=2048)
            tv_public_text = mitv.custom_b64encode(
                tv_private.public_key().public_bytes(
                    mitv.serialization.Encoding.DER,
                    mitv.serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            code = "ABC123"
            additional = "offline-vector"
            key, iv = mitv.derive_cbc_material(code + additional)
            plaintext = ("airkan" + "0123456789abcdef" + tv_public_text).encode()
            padder = mitv.PKCS7(128).padder()
            padded = padder.update(plaintext) + padder.finalize()
            encryptor = mitv.Cipher(
                mitv.algorithms.AES(key.encode()), mitv.modes.CBC(iv.encode())
            ).encryptor()
            encrypted_tv_key = mitv.custom_b64encode(
                encryptor.update(padded) + encryptor.finalize()
            )
            mitv.secure_write_json(
                pending_path,
                {
                    **identity,
                    "host": "192.168.1.50",
                    "control_port": 6095,
                    "install_port": 9095,
                    "request_auth": {
                        "device_id": identity["device_id"],
                        "tv_id": "offline-tv",
                        "public_key": encrypted_tv_key,
                        "verify_code_additional": additional,
                    },
                },
            )
            args = argparse.Namespace(
                code=code,
                state=state_path,
                host=None,
                control_port=6095,
                install_port=9095,
                timeout=5,
            )
            with mock.patch.object(
                mitv,
                "json_request",
                return_value=(200, {"code": 60000, "resp_data": {"tv_id": "offline-tv"}}),
            ) as request:
                result = mitv.command_auth_complete(args)
            self.assertEqual(result["status"], "paired")
            self.assertIn("/completeAuth?device_id=", request.call_args.args[2])
            state = mitv.load_json(state_path)
            self.assertEqual(state["tv_public_key"], tv_public_text)
            self.assertEqual(state["serial_num"], 1)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(state_path.stat().st_mode), 0o600)
            self.assertFalse(pending_path.exists())

    def test_serial_sync_advances_after_invalid_responses(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            tv_private = mitv.rsa.generate_private_key(public_exponent=65537, key_size=2048)
            state = {
                "host": "192.168.1.50",
                "install_port": 9095,
                "device_id": "offline-device",
                "tv_public_key": mitv.custom_b64encode(
                    tv_private.public_key().public_bytes(
                        mitv.serialization.Encoding.DER,
                        mitv.serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                ),
                "serial_num": 1,
            }
            mitv.secure_write_json(state_path, state)
            responses = [
                (400, {"code": 60007, "msg": "Error: invalid serial num!"}),
                (400, {"code": 60007, "msg": "Error: invalid serial num!"}),
                (200, {"data_status": 1010}),
            ]
            with mock.patch.object(mitv, "json_request", side_effect=responses):
                result = mitv.sync_serial(state_path, state, start=2, attempts=8, timeout=5)
            self.assertEqual(result["serial_num"], 4)
            self.assertEqual(mitv.load_json(state_path)["serial_num"], 4)


if __name__ == "__main__":
    unittest.main()
