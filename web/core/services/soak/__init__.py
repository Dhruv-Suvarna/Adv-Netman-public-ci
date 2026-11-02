"""Phase-20 probation soak: observe one exact immutable Probation bundle over real elapsed time, then let the OPERATOR decide.

Layout (each module has ONE job; nothing here configures a device, writes NetBox / Git, deploys anything or holds a lock for the window):

    codes.py         vocabularies, stable start-blocker / terminal-reason catalogues, versions
    policy.py        the server-owned soak policy (duration, cadence, gap, coverage) and its pinned snapshot
    interference.py  "did a LATER execution touch this candidate's devices?" from the persisted Phase-17 execution history
    eligibility.py   may this Probation bundle START a soak?  (read-only)
    assessment.py    PURE classification of health / postcheck results into one sample verdict (the explicit transient-failure policy)
    sampling.py      one read-only evidence read: integrity + interference + Phase-15 postcheck engine + existing monitoring telemetry
    evaluator.py     PURE deterministic evaluation of a run's samples (elapsed duration, coverage, gaps, streaks) + the evidence digest
    lifecycle.py     start / cancel / the idempotent, restartable collector tick (short transactions; audit; best-effort notifications)
    decision.py      the operator's explicit APPROVE / REJECT of a technically passed soak (APPROVE reuses ``bundles.golden``)

The scheduler entry point is the ``probation_soak_tick`` management command.  Nothing in this package can create a Golden bundle except
``decision.decide`` on an explicit operator request; the collector never imports it.
"""
