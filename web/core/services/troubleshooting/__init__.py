"""NMAS V2 troubleshooting (spec NMAS_V2_TROUBLESHOOTING_IMPLEMENTATION_SPEC.md).

M1 (this package's foundation): persistent case/evidence/journal substrate and the structured report renderer.

    contracts    versioned, serializable schemas (collection bundle, observation, test verdict, incident report, AI handoff),
                 the dependency-free validator, enums, redaction and freshness primitives.  Pure: no ORM, no I/O.
    repository   the ONLY write path to the Ts* tables: scoped access, intake, evidence, runs, observations, tests, audit chain.
    reporting    the eleven-section case report (dict / Markdown / HTML) built from repository reads only.

Other milestones add sibling modules and import ONLY from these three; they must not edit this package.
"""

SCHEMA_PACKAGE_VERSION = "nmas.troubleshooting/1"
