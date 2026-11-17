# Controlled fault injection (`break.py`)

`break.py` is an inert-by-default campaign controller. Its policy names an
exact topology, campaign authorization, allowlisted fault ID, device, object,
ManagementPath reference, maximum duration, and IPv4/IPv6 protected-flow
selectors. Wildcards, R5, arbitrary addresses, raw CLI, unknown fault kinds,
unverified identities, and ineligible lifecycle/write state are refused.

The initial allowed fault kind is an administrative shutdown of one exact
interface. The repository fixture uses a mock interface only. A real policy
does not create a live transport: the CLI refuses non-fixture execution until
a separately approved narrow gateway is supplied.

Campaign state and ground truth are stored separately at mode 0600 under a
mode-0700 directory. Public results reveal only campaign state and timestamps,
not the injected defect. Preparation requires healthy measured IPv4 and IPv6
flows, management, monitoring, a captured baseline, an authorization ID, and a
16-character policy-digest confirmation. Only one unfinished campaign may
exist.

The watchdog is independent of the Troubleshooter. It invokes the fixed
rollback method on deadline expiry, loss-threshold breach, management change,
or monitoring failure, then requires baseline readback and dual-stack health
before reporting `RESTORED`. It never relies on an AI response.

Validation: `core.tests.test_troubleshooting_fault_injection` and the fixture
policy `deploy/sandbox/fault-campaign.fixture.json`. The CLI `simulate` path
exercises `ARMED → ACTIVE → RESTORED` without contacting a host, container, or
device. No live fault campaign is authorized by these tests.

