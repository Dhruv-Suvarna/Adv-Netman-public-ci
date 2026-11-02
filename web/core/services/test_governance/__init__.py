"""NMAS test governance (Lab 7): unit-test catalog, function/symbol coverage, runtime code coverage and Pylint.

ONE canonical layer that answers two questions from repository-owned data, without a person reading test source:

* WHICH deployed automation artifacts / functions / platform-feature cells are tested, and by WHICH tests?
* HOW MUCH of each one is covered (explicit positive cases, explicit negative cases, statements, branches)?

Pipeline (heavy work runs in Tier-3 or a management command, never on a page view)::

    inventory   discover + classify every deployed artifact (stable ``PY:`` / ``JINJA:`` / ``YAML:`` ... ids)
    symbols     AST inventory of every function / method, each with a disposition
                (POSITIVE + NEGATIVE required / POSITIVE required / INTERNAL / EXEMPT with a reason)
    catalog     the REQUIRED case catalog (the "Y" of every "X / Y"): symbol cases, template / structured /
                executable artifact cases, platform x feature cell cases and declared cases (``@case``)
    tracer      during the test run, which deployed functions each test invoked DIRECTLY from its own body,
                and whether the call returned or raised (``sys.monitoring``; never "a line happened to run")
    coverage    coverage.py statement + branch data over the deployed scope only
    pylint      the repository-owned ``.pylintrc`` quality gate
    report      one immutable, schema-validated, hashed evidence document (``test-governance-report.json``)
    evidence    the persisted copy NMAS pages read, with CURRENT / STALE against the deployed source
    gate        the Tier-3 closure gate (failures, missing cases, new debt, broken references, regressions)

Nothing in this package contacts a device, NetBox or the lab; device-facing code is only ever exercised by tests
through fakes.  See docs/UNIT_TEST_AND_CODE_COVERAGE.md.
"""
