import unittest
import test_process_generator as existing


class HostnameGeneratorTests(unittest.TestCase):
    setUp = existing.GeneratorTests.setUp
    generate = existing.GeneratorTests.generate

    def test_independent_process_modes(self):
        for process in (
            'find-process-mode: off\n',
            'find-process-mode: always\nfind-process-bpf-only: false\n',
            'find-process-mode: always\nfind-process-bpf-only: true\n'
            'find-process-bpf-map: /run/mihomo-bpf/conn_owners\n',
        ):
            with self.subTest(process=process):
                status, unit, errors = self.generate(process +
                    'hostname-discovery:\n  enable: true\n'
                    '  endpoint: /run/mihomo-hostname/bootstrap.sock\n  wait-ms: 50\n')
                self.assertEqual(status, 0, errors)
                hostname = unit[unit.index('Wants=mihomo-hostname-observer.service'):]
                self.assertIn('BindReadOnlyPaths=-/run/mihomo-hostname', hostname)
                self.assertIn('InaccessiblePaths=-/sys/fs/bpf/mihomo-hostname', hostname)
                for grant in ('Requires=', 'BindsTo=', 'PartOf=', 'Capability',
                              'ProtectProc', 'BindReadOnlyPaths=/sys/fs/bpf', 'hostname-target'):
                    self.assertNotIn(grant, hostname)

    def test_disabled_hostname_does_not_mount_or_start_observer(self):
        for value in ('null', '{}', '{enable: false}', '{enable: off}',
                      '{enable: null, endpoint: /unavailable}', '{wait-ms: 50}'):
            with self.subTest(value=value):
                status, unit, errors = self.generate(
                    'find-process-mode: off\nhostname-discovery: ' + value + '\n')
                self.assertEqual(status, 0, errors)
                self.assertNotIn('hostname', unit)

    def test_nested_aliases_merges_and_legacy_boolean(self):
        status, unit, errors = self.generate('''
find-process-mode: off
defaults: &defaults
  enable: false
  endpoint: /run/mihomo-hostname/bootstrap.sock
hostname-discovery:
  <<: *defaults
  enable: yes
''')
        self.assertEqual(status, 0, errors)
        self.assertIn('Wants=mihomo-hostname-observer.service', unit)

    def test_bad_hostname_settings_deny_without_logging_secrets(self):
        for settings in ('true', '[]', '{enable: maybe}', '{enable: "true"}',
                         '{enable: 1}', '{enable: true}',
                         '{enable: true, endpoint: /wrong/path}',
                         '{enable: true, endpoint: [secret-marker]}',
                         '{enable: false, enable: true}'):
            with self.subTest(settings=settings):
                status, unit, errors = self.generate(
                    'find-process-mode: off\npassword: secret-marker\n'
                    'hostname-discovery: ' + settings + '\n')
                self.assertEqual(status, 1)
                self.assertEqual(unit, '[Service]\nExecStart=\nExecStart=/usr/bin/false\n')
                self.assertNotIn('secret-marker', errors + unit)

    def test_disabling_removes_generated_observer_access(self):
        self.generate('find-process-mode: off\nhostname-discovery: '
                      '{enable: true, endpoint: /run/mihomo-hostname/bootstrap.sock}\n')
        status, unit, errors = self.generate('find-process-mode: off\n')
        self.assertEqual(status, 0, errors)
        self.assertNotIn('hostname', unit)
