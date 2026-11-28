# Stage B resolver-root prerequisite amendment

Change: `CHG-NMAS-20261115-STAGE-B-001`

Status: prerequisite remains prepared and tested; the independent systemd DNS
consumer blocker identified below is resolved in the corrected final plan. No
live `/etc/netns` change or research activation has been made.

The earlier 60-minute maintenance window is not treated as active. This
amendment does not authorize the live filesystem mutation or a research retry.

## Inspected state and accepted contract

VM1 `/etc` is a real directory on the root ext4 filesystem, not a symlink:

```text
directory root:root 0755 /etc
device=2051 inode=131073
/var and /var/lib: real directories, root:root 0755
/etc/netns: ABSENT
```

No currently loaded systemd unit or existing process was found to rely on
`/etc/netns`; the path is absent. Repository references are confined to the
proposed namespace controller and this amendment. The future research resolver
lifecycle is therefore the only project consumer.

The old preflight check accepted any real directory. The amended check accepts
exactly:

```text
/etc/netns  directory, never a symlink, root:root, mode 0755
```

Mode `0755` permits namespace-aware readers to traverse it but permits only
root to create, replace or remove entries. The new prerequisite tool also binds
ownership to an external receipt:

```text
/var/lib/nmas-stage-b-resolver-root.json  root:root, mode 0600
schema=nmas.resolver-root-ownership/1
change_id=CHG-NMAS-20261115-STAGE-B-001
parent device/inode + directory device/inode + uid/gid/mode
```

The receipt is created with `O_EXCL|O_NOFOLLOW` relative to a no-follow
descriptor for trusted `/var/lib`. The directory is created with `mkdirat`
relative to a no-follow descriptor for trusted `/etc`. Both parent descriptors
are checked against the device/inode observed before opening. A pre-existing
directory, symlink, partial root/receipt pair, changed inode, owner/mode drift or
different change ID is refused and never adopted.

## Proposed live commands — not yet authorized

Mutation-free plan:

```bash
cd /home/student/Scripts/nmas-public-dev-troubleshooting
python3 deploy/sandbox/resolver_root.py plan \
  --change-id CHG-NMAS-20261115-STAGE-B-001
```

Only after the owner explicitly authorizes this exact filesystem prerequisite:

```bash
sudo /usr/bin/python3 deploy/sandbox/resolver_root.py install \
  --change-id CHG-NMAS-20261115-STAGE-B-001
sudo /usr/bin/python3 deploy/sandbox/resolver_root.py verify \
  --change-id CHG-NMAS-20261115-STAGE-B-001
sudo test ! -L /etc/netns
sudo test ! -L /var/lib/nmas-stage-b-resolver-root.json
sudo stat -c '%F %U:%G %a %n inode=%i dev=%d' /etc/netns
sudo stat -c '%F %U:%G %a %n' /var/lib/nmas-stage-b-resolver-root.json
```

Expected result is exactly `root:root 0755 /etc/netns` and `root:root 0600`
for the receipt. Repeated install is an idempotent `already-owned` result.

After research namespace rollback removes
`/etc/netns/nmas-ts-research/resolv.conf` and its owned per-namespace directory,
remove the prerequisite independently:

```bash
sudo /usr/bin/python3 deploy/sandbox/resolver_root.py rollback \
  --change-id CHG-NMAS-20261115-STAGE-B-001
```

Rollback validates the change ID, receipt type/mode/owner, trusted parent and
the exact recorded directory device/inode. It uses `rmdir`; any content causes
`REFUSED: owned resolver root is not empty; refusing deletion`. It never removes
a foreign replacement or any contents.

## Disposable evidence

`python3 deploy/sandbox/test_resolver_root.py` passed:

- create, verify, repeated-install idempotency and repeated rollback;
- root mode `0755` and receipt mode `0600`;
- pre-existing foreign directory preservation;
- target, receipt and parent symlink refusal;
- non-empty directory rollback refusal with content preserved;
- changed-inode verify/rollback refusal;
- symlinked parent refusal.

The full disposable namespace suite passed 19 groups, including the new
`resolver-root-requires-root-owner-and-0755` check, every-step activation
failure cleanup, independent rollback, foreign-object preservation and an
unchanged real-host baseline. Focused application tests passed 29/29; proposal
schema/digest tests passed.

## Independent blocker discovered

Creating `/etc/netns` alone is insufficient to make the planned live research
worker resolve DNS. The local `ip-netns(8)` contract says that **`ip netns
exec`** creates a mount namespace and bind-mounts
`/etc/netns/<name>/resolv.conf` over `/etc/resolv.conf` for namespace-unaware
applications. The planned `nmas-research-broker.service` instead uses:

```text
NetworkNamespacePath=/run/netns/nmas-ts-research
```

`systemd.exec(5)` documents that this joins the network namespace; it does not
apply the iproute2 `/etc/netns` bind-mount convention. The unit has no
`BindReadOnlyPaths` entry for the research resolver file. VM1 `/etc/resolv.conf`
points to the host stub `127.0.0.53`; that listener is not present on the
research namespace's loopback. Consequently the service is expected to fail
DNS even after the directory prerequisite passes.

Fixing that requires a separately reviewed unit/runtime mounting decision,
for example an exact read-only bind of the owned research resolver file over
the worker's `/etc/resolv.conf`. That is outside this filesystem-only amendment
and was not implemented because the owner prohibited changes to the deployed
package and namespace security model.

No live retry should be authorized from this amendment alone.

Resolution: `nmas-research-broker.service.in` now uses an exact
`BindReadOnlyPaths=/etc/netns/nmas-ts-research/resolv.conf:/etc/resolv.conf`
mount and a root-only startup preflight that verifies the resolver-root receipt,
source inode/content, mounted inode, network namespace, policy digest and
IPv6-disabled state. See `stage-b-final-fail-closed-activation-plan.md`.

`STAGE_B_RESEARCH_READY_FOR_FINAL_AUTHORIZATION`
