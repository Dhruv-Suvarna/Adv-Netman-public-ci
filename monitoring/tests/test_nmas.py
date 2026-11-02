"""Offline checks of NMAS failure propagation and credential safeguards."""
import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from modules import nmas


class NmasTests(unittest.TestCase):
    def test_receiver_failure_stops_storage_and_verification(self):
        calls = []
        def stage(label, command, verbose=False):
            calls.append(label)
            raise nmas.NmasError("receiver failed")
        with patch.object(nmas, 'validate_runtime'), patch.object(nmas, 'validate_inventory'), patch.object(nmas, 'stage', side_effect=stage):
            with self.assertRaises(nmas.NmasError):
                nmas.ensure_nmas_infrastructure(prepared=True)
        self.assertEqual(calls, ['Receivers and logrotate'])

    def test_verification_failure_is_not_success(self):
        calls = []
        def stage(label, command, verbose=False):
            calls.append(label)
            if label == 'Verification':
                raise nmas.NmasError('health gate failed')
        with patch.object(nmas, 'validate_runtime'), patch.object(nmas, 'validate_inventory'), patch.object(nmas, 'stage', side_effect=stage):
            with self.assertRaises(nmas.NmasError):
                nmas.ensure_nmas_infrastructure(prepared=True)
        self.assertEqual(calls, ['Receivers and logrotate', 'InfluxDB and Grafana', 'Retention', 'Verification'])

    def test_missing_credentials_with_existing_data_refuses_regeneration(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(nmas, 'MONITORING', Path(directory)):
            data = Path(directory) / 'runtime/grafana'
            data.mkdir(parents=True)
            (data / 'grafana.db').write_text('existing')
            with self.assertRaisesRegex(nmas.NmasError, 'Runtime data exists'):
                nmas.validate_runtime()

    def test_unsafe_environment_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(nmas, 'MONITORING', Path(directory)):
            env = Path(directory) / 'runtime/monitoring.env'
            env.parent.mkdir()
            env.write_text('INFLUXDB_TOKEN=$(touch unwanted)\n')
            env.chmod(0o600)
            with self.assertRaises(nmas.NmasError):
                nmas.validate_runtime()

    def test_subprocess_failure_redacts_credentials(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(nmas, 'MONITORING', Path(directory)):
            env = Path(directory) / 'runtime/monitoring.env'
            env.parent.mkdir()
            env.write_text('INFLUXDB_TOKEN=secret-value\n')
            output = io.StringIO()
            result = subprocess.CompletedProcess([], 1, 'secret-value', '')
            with patch.object(nmas.subprocess, 'run', return_value=result), contextlib.redirect_stdout(output):
                with self.assertRaises(nmas.NmasError):
                    nmas.stage('Retention', ['false'])
            self.assertNotIn('secret-value', output.getvalue())
            self.assertIn('FAIL', output.getvalue())


if __name__ == '__main__':
    unittest.main()
