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
            self.assertEqual(icon.find("background").get(ATTR + "drawable"), "@android:color/black")
            self.assertEqual(icon.find("monochrome") is not None, version == 33)
        foreground = ET.parse(ANDROID / "res/drawable/ic_launcher_foreground.xml").getroot()
        self.assertEqual(foreground.get(ATTR + "drawable"), "@drawable/donkey_launcher")
        themed = ET.parse(ANDROID / "res/drawable/ic_launcher_monochrome.xml").getroot()
        self.assertEqual(themed.get(ATTR + "drawable"), "@drawable/ic_notification")
        notification = ET.parse(ANDROID / "res/drawable/ic_notification.xml").getroot()
        self.assertEqual(notification.find("path").get(ATTR + "fillColor"), "#FFFFFFFF")
        self.assertIn(".setSmallIcon(R.drawable.ic_notification)", (ANDROID / "java/org/emulebb/android/DaemonService.kt").read_text())

    def test_adaptive_alpha_geometry_fits_round_and_squircle_safe_masks(self):
        # WHY: bind the decoded alpha hull to the immutable supplied PNG so the
        # portable check needs no image dependency or duplicate PNG decoder.
        fixture = json.loads((ROOT / "tools/tests/fixtures/android_launcher_alpha.json").read_text())
        self.assertEqual(hashlib.sha256((ROOT / fixture["source_path"]).read_bytes()).hexdigest(), fixture["sha256"])
        foreground = ET.parse(ANDROID / "res/drawable/ic_launcher_foreground.xml").getroot()
        themed = ET.parse(ANDROID / "res/drawable/ic_launcher_monochrome.xml").getroot()

        def placed(points, width, height, resource):
            inset = resource.get(ATTR + "inset")
            self.assertTrue(inset.endswith("%"))
            fraction = float(inset[:-1]) / 100
            self.assertTrue(0 <= fraction < 0.5)
            side = 108 * (1 - 2 * fraction)
            return [((x / width - 0.5) * side, (y / height - 0.5) * side) for x, y in points]

        donkey = placed(fixture["opaque_pixel_corner_hull"], fixture["width"], fixture["height"], foreground)
        # The notification path is the approved four-block union: an 18/24 square.
        notification = ET.parse(ANDROID / "res/drawable/ic_notification.xml").getroot()
        self.assertEqual(notification.find("path").get(ATTR + "pathData"), "M3,3h18v18h-18z")
        monochrome = placed(((3, 3), (21, 3), (21, 21), (3, 21)),
                            float(notification.get(ATTR + "viewportWidth")),
                            float(notification.get(ATTR + "viewportHeight")), themed)
        for name, corners in (("donkey", donkey), ("monochrome", monochrome)):
            with self.subTest(layer=name):
                # Both masks are convex, so hull-vertex containment proves the
                # full alpha footprint fits, including anti-aliased edge pixels.
                self.assertLessEqual(max(x*x + y*y for x, y in corners), 33**2)
                self.assertLessEqual(max((abs(x)/33)**4 + (abs(y)/33)**4 for x, y in corners), 1)

    def test_webui_uses_supplied_favicon_and_touch_artwork(self):
        index = (ROOT / "webui/index.html").read_text(encoding="utf-8")
        self.assertIn('href="/favicon.ico" sizes="16x16 32x32 48x48"', index)
        self.assertIn('href="/apple-touch-icon.png" sizes="180x180"', index)


if __name__ == "__main__":
    unittest.main()
