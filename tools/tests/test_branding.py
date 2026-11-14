"""Keep approved PNG bytes, ICO payloads and platform resource wiring aligned."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
ANDROID = ROOT / "android/app/src/main"
ATTR = "{http://schemas.android.com/apk/res/android}"


class BrandingTests(unittest.TestCase):
    def test_all_platform_assets_match_approved_inventory(self):
        manifest = json.loads((ROOT / "resources/branding.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["selection"], "proposal-5")
        for asset in manifest["assets"]:
            with self.subTest(path=asset["path"]):
                data = (ROOT / asset["path"]).read_bytes()
                self.assertEqual(len(data), asset["bytes"])
                self.assertEqual(hashlib.sha256(data).hexdigest(), asset["sha256"])

    def test_ico_frames_are_exact_native_png_payloads(self):
        cases = (("webui/public/favicon.ico", (16, 32, 48)),
                 ("crates/emulebb-daemon/resources/windows/application.ico", (16, 24, 32, 48, 64, 128, 256)))
        for path, sizes in cases:
            data = (ROOT / path).read_bytes()
            self.assertEqual(struct.unpack_from("<HHH", data), (0, 1, len(sizes)))
            for index, size in enumerate(sizes):
                width, height, _, _, _, _, length, offset = struct.unpack_from("<BBBBHHII", data, 6 + 16 * index)
                self.assertEqual((width or 256, height or 256), (size, size))
                self.assertEqual(data[offset:offset + length], (ROOT / f"resources/icons/donkey-{size}.png").read_bytes())

    def test_android_launcher_and_notification_resources_resolve(self):
        application = ET.parse(ANDROID / "AndroidManifest.xml").getroot().find("application")
        self.assertEqual(application.get(ATTR + "icon"), "@mipmap/ic_launcher")
        self.assertEqual(application.get(ATTR + "roundIcon"), "@mipmap/ic_launcher")
        for version in (26, 33):
            icon = ET.parse(ANDROID / f"res/mipmap-anydpi-v{version}/ic_launcher.xml").getroot()
            self.assertEqual(icon.tag, "adaptive-icon")
            self.assertEqual(icon.find("foreground").get(ATTR + "drawable"), "@drawable/ic_launcher_foreground")
            self.assertEqual(icon.find("background").get(ATTR + "drawable"), "@android:color/white")
            self.assertEqual(icon.find("monochrome") is not None, version == 33)
        foreground = ET.parse(ANDROID / "res/drawable/ic_launcher_foreground.xml").getroot()
        self.assertEqual(foreground.get(ATTR + "drawable"), "@drawable/donkey_launcher")
        self.assertEqual(foreground.get(ATTR + "inset"), "16.6667%")
        themed = ET.parse(ANDROID / "res/drawable/ic_launcher_monochrome.xml").getroot()
        self.assertEqual(themed.get(ATTR + "drawable"), "@drawable/ic_notification")
        notification = ET.parse(ANDROID / "res/drawable/ic_notification.xml").getroot()
        self.assertEqual(notification.find("path").get(ATTR + "fillColor"), "#FFFFFFFF")
        self.assertIn(".setSmallIcon(R.drawable.ic_notification)", (ANDROID / "java/org/emulebb/android/DaemonService.kt").read_text())

    def test_webui_uses_supplied_favicon_and_touch_artwork(self):
        index = (ROOT / "webui/index.html").read_text(encoding="utf-8")
        self.assertIn('href="/favicon.ico" sizes="16x16 32x32 48x48"', index)
        self.assertIn('href="/apple-touch-icon.png" sizes="180x180"', index)


if __name__ == "__main__":
    unittest.main()
