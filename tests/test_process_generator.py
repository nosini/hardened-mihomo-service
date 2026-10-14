"""Run with python3 -m unittest discover -s tests -v."""

from contextlib import redirect_stderr
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "mihomo-process-generator"
loader = SourceFileLoader("generator", str(SOURCE))
generator = module_from_spec(spec_from_loader(loader.name, loader))
loader.exec_module(generator)


class GeneratorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "config.yaml"
        self.output = self.root / "generated"

    def generate(self, config):
        self.config.write_text(config)
        errors = StringIO()
        with redirect_stderr(errors):
            status = generator.generate(self.output, self.config)
        contents = (self.output / "mihomo.service.d/50-process-lookup.conf").read_text()
        return status, contents, errors.getvalue()

    def test_bpf_requires_loader_and_maps_without_proc_privileges(self):
        status, unit, errors = self.generate(
            "find-process-mode: always\nfind-process-bpf-only: true\n"
            "find-process-bpf-map: /run/mihomo-bpf/conn_owners\n"
        )
        self.assertEqual(status, 0, errors)
        self.assertIn("Requires=mihomo-sockowner.service", unit)
        self.assertIn("After=mihomo-sockowner.service", unit)
        self.assertIn("BindReadOnlyPaths=/sys/fs/bpf/mihomo/maps:/run/mihomo-bpf", unit)
        self.assertNotIn("SYS_PTRACE", unit)
        self.assertNotIn("ProtectProc=default", unit)
        self.assertIn("ExecStart=/usr/local/bin/mihomo", unit)

    def test_proc_grants_both_capability_sets_without_requiring_loader(self):
        status, unit, errors = self.generate("find-process-bpf-only: false\n")
        self.assertEqual(status, 0, errors)
        self.assertIn("ProtectProc=default", unit)
        for directive in ("CapabilityBoundingSet", "AmbientCapabilities"):
            self.assertIn(f"{directive}=\n{directive}=CAP_NET_ADMIN CAP_NET_BIND_SERVICE "
                          "CAP_SYS_PTRACE CAP_DAC_READ_SEARCH", unit)
        self.assertNotIn("Requires=", unit)
        self.assertIn("Wants=mihomo-sockowner.service", unit)
        self.assertIn("BindReadOnlyPaths=-/sys/fs/bpf/mihomo/maps:/run/mihomo-bpf", unit)

    def test_defaults_match_mihomo(self):
        status, unit, errors = self.generate("mixed-port: 7891\n")
        self.assertEqual(status, 0, errors)
        self.assertIn("ProtectProc=default", unit)

    def test_off_keeps_restricted_base_and_does_not_mount_maps(self):
        for value in ("off", "OFF", "'off'"):
            with self.subTest(value=value):
                status, unit, errors = self.generate(f"find-process-mode: {value}\n")
                self.assertEqual(status, 0, errors)
                self.assertNotIn("SYS_PTRACE", unit)
                self.assertNotIn("BindReadOnlyPaths", unit)
                self.assertNotIn("mihomo-sockowner", unit)

    def test_yaml_comments_nested_settings_aliases_and_merges(self):
        status, unit, errors = self.generate(
            "defaults: &defaults\n  find-process-bpf-only: false\n"
            "<<: *defaults\nfind-process-mode: 'always' # comment\n"
            "find-process-bpf-only: true\n"
            "find-process-bpf-map: '/run/mihomo-bpf/conn_owners'\n"
            "proxies:\n  - name: example\n    find-process-mode: off\n"
        )
        self.assertEqual(status, 0, errors)
        self.assertIn("Requires=mihomo-sockowner.service", unit)

    def test_merges_follow_mihomo_precedence(self):
        bpf = "find-process-bpf-map: /run/mihomo-bpf/conn_owners\n"
        for config, mode in (
            # An anchor that merges another and overrides one of its keys.
            ("base: &base\n  find-process-bpf-only: false\n"
             "settings: &settings\n  <<: *base\n  find-process-bpf-only: true\n"
             "<<: *settings\n" + bpf, "bpf"),
            ("a: &a {find-process-bpf-only: true}\nb: &b {find-process-bpf-only: false}\n"
             "<<: [*b, *a]\n" + bpf, "proc"),
            ("a: &a {find-process-bpf-only: false}\nfind-process-bpf-only: true\n"
             "<<: *a\n" + bpf, "bpf"),
            ("a: &x {find-process-bpf-only: false}\nb: &x {find-process-bpf-only: true}\n"
             "<<: *x\n" + bpf, "bpf"),
            ("find-process-mode: off\n---\nfind-process-mode: always\n", "off"),
            ("extra:\n  a: 1\n  a: 2\nfind-process-mode: off\n", "off"),
        ):
            with self.subTest(config=config):
                self.config.write_text(config)
                self.assertEqual(generator.lookup_mode(self.config), mode)

    def test_scalars_decode_like_mihomo(self):
        bpf = "find-process-bpf-map: /run/mihomo-bpf/conn_owners\n"
        for config, mode in (
            ("find-process-bpf-only: no\n", "proc"),
            ("find-process-bpf-only: Off\n", "proc"),
            ("find-process-bpf-only: FALSE\n", "proc"),
            ("find-process-bpf-only: null\n", "proc"),
            ("find-process-bpf-only: ~\n", "proc"),
            ("find-process-bpf-only:\n", "proc"),
            ("find-process-bpf-only: yes\n" + bpf, "bpf"),
            ("find-process-bpf-only: 'on'\n" + bpf, "bpf"),
            ("find-process-bpf-only: Y\n" + bpf, "bpf"),
            ("find-process-mode: null\n", "proc"),
            ("find-process-mode: !!str Always\n", "proc"),
            ("find-process-mode: off\nfind-process-bpf-map: null\n", "off"),
        ):
            with self.subTest(config=config):
                self.config.write_text(config)
                self.assertEqual(generator.lookup_mode(self.config), mode)

    def test_errors_block_startup_and_do_not_log_credentials(self):
        for config in (
            "password: secret-marker\nfind-process-mode: invalid\n",
            "password: [secret-marker\n",
            "find-process-mode: off\nfind-process-mode: always\n",
            "find-process-mode: [off]\n",
            "find-process-bpf-only: maybe\n",
            "find-process-bpf-only: 'true'\n",
            "find-process-bpf-only: tRue\n",
            "find-process-bpf-only: 1\n",
            "find-process-mode: off\nfind-process-bpf-only: maybe\n",
            "find-process-mode: true\n",
            "a: &a {find-process-mode: off}\nb: &b {find-process-mode: always}\n"
            "<<: *a\n<<: *b\n",
            "a: &a {find-process-mode: off, find-process-mode: always}\n<<: *a\n",
            "a: &a 1\n<<: *a\n",
            "a: &a\n  <<: *a\n<<: *a\n",
            "find-process-bpf-only: true\nfind-process-bpf-map: /wrong/map\n",
            "find-process-bpf-only: true\n",
            "[]\n",
            "",
        ):
            with self.subTest(config=config):
                status, unit, errors = self.generate(config)
                self.assertEqual(status, 1)
                self.assertEqual(unit, generator.DENY)
                self.assertNotIn("secret-marker", unit + errors)
                self.assertIn("startup is blocked", errors)

    def test_missing_file_blocks_startup(self):
        with redirect_stderr(StringIO()):
            self.assertEqual(generator.generate(self.output, self.config), 1)
        self.assertEqual((self.output / "mihomo.service.d/50-process-lookup.conf").read_text(),
                         generator.DENY)

    def test_missing_pyyaml_blocks_startup(self):
        with patch.dict("sys.modules", {"yaml": None}):
            status, unit, errors = self.generate("find-process-mode: off\n")
        self.assertEqual(status, 1)
        self.assertEqual(unit, generator.DENY)
        self.assertIn("PyYAML", errors)

    def test_switching_modes_removes_generated_proc_permissions(self):
        self.generate("find-process-bpf-only: false\n")
        status, unit, errors = self.generate("find-process-mode: off\n")
        self.assertEqual(status, 0, errors)
        self.assertNotIn("SYS_PTRACE", unit)
        self.assertNotIn("ProtectProc=default", unit)


if __name__ == "__main__":
    unittest.main()
