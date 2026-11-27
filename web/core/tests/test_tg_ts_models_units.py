"""Direct tests for the Troubleshooter evidence models' write guards (core/models.py, Ts* records).

Case records keep secret-shaped keys out of structured metadata, an exception policy needs a narrow scope, a hypothesis a
known state, a collection run is immutable once final, and append-only records are never updated or deleted -- not by an
instance, a queryset or a bulk call.
"""

from __future__ import annotations

from datetime import timedelta

from django.test import TestCase

from core import models as m
from core.services.test_governance.cases import case
from core.services.troubleshooting import repository as repo
from core.tests.test_tg_ts_engine_units import open_case
from core.tests.test_troubleshooting_engine import ACTOR, T0

SECRET_SHAPED = {"password": "placeholder"}


class TsRecordWriteGuardTests(TestCase):
    def setUp(self):
        self.case = open_case(key="tg-ts-models")

    def rid(self, prefix):
        return repo._rid(prefix)                 # pylint: disable=protected-access  # the repository's own record-id generator

    def test_record_saves_persist_scoped_metadata(self):
        rows = (m.TsExceptionPolicy(record_id=self.rid("EXC"), case=self.case, scope={"src": "h1", "dst": "h2", "protocols": ["icmp"]},
                                    expires_at=T0 + timedelta(hours=1)),
                m.TsHypothesis(record_id=self.rid("HYP"), case=self.case, title="link down", state="OPEN"),
                m.TsProductionFlowMonitor(record_id=self.rid("FLW"), case=self.case, selector={"protocol": "tcp", "port": 443}),
                m.TsVerificationRecord(record_id=self.rid("VER"), case=self.case, observed_values={"loss_pct": 0.0}, outcome="VERIFIED"))
        for row in rows:
            with self.subTest(model=type(row).__name__):
                row.save()
                self.assertTrue(type(row).objects.filter(pk=row.pk).exists())

    def test_record_saves_refuse_secret_shaped_metadata_or_an_empty_scope(self):
        cases = (("an exception policy with an empty scope", m.TsExceptionPolicy(record_id=self.rid("EXC"), case=self.case, scope={},
                                                                                   expires_at=T0)),
                 ("a flow monitor with a secret-shaped selector", m.TsProductionFlowMonitor(record_id=self.rid("FLW"), case=self.case,
                                                                                             selector=SECRET_SHAPED)),
                 ("a verification with secret-shaped values", m.TsVerificationRecord(record_id=self.rid("VER"), case=self.case,
                                                                                      observed_values=SECRET_SHAPED)))
        for label, row in cases:
            with self.subTest(f"{label} is refused"), self.assertRaises(ValueError):
                row.save()
            self.assertFalse(type(row).objects.filter(record_id=row.record_id).exists())

    def test_full_clean_json_passes_clean_structured_metadata(self):
        self.assertIsNone(m.TsHypothesis(record_id=self.rid("HYP"), case=self.case, title="t", supporting_evidence=["EV-1"]).full_clean_json())
        self.assertIsNone(self.evidence().full_clean_json())

    def evidence(self, device="r1"):
        return repo.store_evidence(ACTOR, self.case, source_type="cli", device=device, command_or_api="show version", adapter="unit",
                                   adapter_version="1", collected_at=T0, raw="version 4.36.2F")

    def run_(self, key="tg-models-run"):
        return repo.begin_collection_run(ACTOR, self.case, idempotency_key=key, collector="cli", targets=["r1"],
                                         command_or_api="show version", now=T0)

    def test_collection_run_save_records_progress_until_final(self):
        run = self.run_()
        run.attempts = 1
        run.save()
        self.assertEqual(m.TsCollectionRun.objects.get(pk=run.pk).attempts, 1)

    @case("TS_COLLECTION_RUN_DELETE_IS_REFUSED", target="web/core/models.py::TsCollectionRun.delete", polarity="POSITIVE",
          condition="any request to delete a collection run, final or not",
          expected="the intended outcome is a refusal: ValueError, and the run (the provenance of every observation it produced) remains")
    def test_collection_run_delete_keeps_the_run(self):
        run = self.run_("tg-models-delete")
        with self.assertRaises(ValueError):
            run.delete()
        self.assertTrue(m.TsCollectionRun.objects.filter(pk=run.pk).exists())

    @case("TS_APPEND_ONLY_QUERYSET_BULK_UPDATE_IS_REFUSED", target="web/core/models.py::_TsAppendOnlyQuerySet.bulk_update",
          polarity="POSITIVE", condition="a bulk update of append-only troubleshooting records",
          expected="the intended outcome is a refusal: ValueError, and every stored row is unchanged")
    def test_append_only_bulk_update_keeps_every_row(self):
        refs = [self.evidence("r1"), self.evidence("r2")]
        for ref in refs:
            ref.device = "rewritten"
        with self.assertRaises(ValueError):
            m.TsEvidenceRef.objects.filter(case=self.case).bulk_update(refs, ["device"])
        self.assertEqual(set(m.TsEvidenceRef.objects.filter(case=self.case).values_list("device", flat=True)), {"r1", "r2"})

    @case("TS_APPEND_ONLY_QUERYSET_DELETE_IS_REFUSED", target="web/core/models.py::_TsAppendOnlyQuerySet.delete", polarity="POSITIVE",
          condition="a queryset delete of append-only troubleshooting records",
          expected="the intended outcome is a refusal: ValueError, and every stored row remains")
    def test_append_only_queryset_delete_keeps_every_row(self):
        self.evidence()
        with self.assertRaises(ValueError):
            m.TsEvidenceRef.objects.filter(case=self.case).delete()
        self.assertEqual(m.TsEvidenceRef.objects.filter(case=self.case).count(), 1)
