"""V2 Lifecycle Phase 3: native zero-touch provisioning under NMAS lifecycle governance.

    adapters/     one native-ZTP adapter per NOS (the platform-facing contract; vendor details stay here)
    dhcp/         the DHCP provider contract, the operational ISC DHCP provider and the Kea configuration provider
    policy.py     bootstrap-network safety rules and the provider-neutral DHCP bootstrap policy
    discovery.py  ingestion of the provider's own lease database into Phase 2 observations (claims vs trusted relay evidence)
    artifacts.py  bounded, secret-free bootstrap artifacts and their delivery decisions (transport-independent)
    servers.py    the read-only HTTP and TFTP delivery servers (thin protocol shells over ``artifacts.serve``)
    management.py first management contact and authenticated verification over the bootstrap network (SSH, host-key pinned)
    workflow.py   the ZTP session: open, discover, deliver, enroll host key, verify, BOOTSTRAPPED -- or fail with native guidance
    dependencies.py  generic upstream / bootstrap-path prerequisites (e.g. R4 -> R6 -> R7)

Nothing here admits a device to production, enables production routing or touches a production DHCP service.
"""
