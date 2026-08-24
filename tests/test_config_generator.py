import json
import shutil
import subprocess
import unittest
from pathlib import Path

import yaml

from dlms_enum.config import LlsProfile, SecureProfile, parse_config, resolve_lls_password


ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "tools" / "config-generator.html"
NODE = shutil.which("node")


def element(value="", *, checked=False):
    return {"value": str(value), "checked": checked}


@unittest.skipUnless(NODE, "Node.js is required to exercise the browser generator")
class ConfigGeneratorTests(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        self.fields = {
            "device": element("/dev/ttyUSB0"),
            "baudrate": element("9600"),
            "public-enabled": element(checked=True),
            "public-client": element("16"),
            "lls-enabled": element(),
            "lls-role": element("meter_reader"),
            "lls-client": element("32"),
            "lls-source": element("env"),
            "lls-secret": element("DLMS_LLS_PASSWORD"),
            "hls-enabled": element(),
            "hls-role": element("secure_client"),
            "hls-client": element("4"),
            "hls-source": element("env"),
            "system-title": element("4D41430102030405"),
            "gak": element("DLMS_GAK"),
            "guek": element("DLMS_GUEK"),
            "counter-obis": element("0.0.43.1.12.255"),
            "common-catalogue": element(checked=True),
            "union-test": element(),
            "auth-scan": element(),
            "auth-source": element("env"),
            "auth-secret": element("DLMS_PASSWORD"),
            "scope": element("full"),
            "get-limit": element("100"),
            "batch-size": element("1"),
        }

    def generated_mapping(self):
        html = GENERATOR.read_text(encoding="utf-8")
        script = html.split("<script>", 1)[1].split("</script>", 1)[0]
        definitions = script.split('  ["public-enabled"', 1)[0]
        harness = """
const fields = JSON.parse(process.argv[1]);
globalThis.document = {
  getElementById(id) {
    if (!(id in fields)) throw new Error(`Missing test field: ${id}`);
    return fields[id];
  }
};
""" + definitions + "\nprocess.stdout.write(buildYaml());\n"
        completed = subprocess.run(
            [NODE, "-e", harness, json.dumps(self.fields)],
            check=True,
            capture_output=True,
            text=True,
        )
        return yaml.safe_load(completed.stdout)

    def test_inline_password_whitespace_is_preserved(self):
        self.fields["public-enabled"]["checked"] = False
        self.fields["lls-enabled"]["checked"] = True
        self.fields["lls-source"]["value"] = "inline"
        self.fields["lls-secret"]["value"] = "  reader password  "
        self.fields["auth-scan"]["checked"] = True
        self.fields["auth-source"]["value"] = "inline"
        self.fields["auth-secret"]["value"] = "  scan password  "

        config = parse_config(self.generated_mapping())

        self.assertEqual(resolve_lls_password(config.profile), b"  reader password  ")
        self.assertEqual(
            resolve_lls_password(config.authentication_scan), b"  scan password  "
        )

    def test_hex_password_limit_uses_decoded_byte_length(self):
        self.fields["public-enabled"]["checked"] = False
        self.fields["lls-enabled"]["checked"] = True
        self.fields["lls-source"]["value"] = "inline"
        self.fields["lls-secret"]["value"] = "hex:" + ("AB" * 64)

        config = parse_config(self.generated_mapping())

        self.assertEqual(resolve_lls_password(config.profile), b"\xAB" * 64)

    def test_public_client_address_is_used_by_lls_and_secure_bootstrap(self):
        self.fields["public-client"]["value"] = "37"
        self.fields["lls-enabled"]["checked"] = True
        self.fields["hls-enabled"]["checked"] = True

        config = parse_config(self.generated_mapping())
        lls = next(profile for profile in config.profiles if isinstance(profile, LlsProfile))
        secure = next(
            profile for profile in config.profiles if isinstance(profile, SecureProfile)
        )

        self.assertEqual(config.profiles[0].client_address, 37)
        self.assertEqual(lls.public_client_address, 37)
        self.assertEqual(secure.invocation_counter.public_client_address, 37)


if __name__ == "__main__":
    unittest.main()
