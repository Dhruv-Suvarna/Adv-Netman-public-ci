# Phase integration workflow (developer tooling)

`tools/phase_integrate.py` automates the Git / GitHub steps that used to be typed by hand after every phase: create the
phase branch, work out which files to stage, keep the runtime logs out of the commit, validate, commit, push, open the PR,
watch the hosted Tier-3 run, merge with a merge commit and fast-forward local `main`.

It is **source-control tooling only**. It runs `git`, the GitHub CLI (`gh`) and this repository's own local Tier-3
validator (`tier3.py`). It never configures a network device, never calls `master.py` or any execution / NetBox /
Containerlab / SNMP code, and no GitHub workflow deploys anything. It is not part of the Django application and is not a
"phase" itself.

## Prerequisites

* `git`, and an `origin` remote pointing at the GitHub repository.
* The GitHub CLI, authenticated: `gh auth status` must succeed. The tool never handles tokens; if `gh` is not
  authenticated it stops **before anything is committed** and tells you to run `gh auth login`.
* Run it with the project's Python (`/home/student/Scripts/.venv/bin/python`); `prepare` reuses that interpreter for `tier3.py`.
* `git push` must already work non-interactively (the tool sets `GIT_TERMINAL_PROMPT=0` and never works around credentials).

## Normal flow (future phases)

```bash
python tools/phase_integrate.py start   --phase 19 --slug golden-probation-bundles
# ... implement, test, review the phase ...
python tools/phase_integrate.py prepare --phase 19 --message "Phase 19: add Golden and Probation bundles"
python tools/phase_integrate.py status          # while the hosted Tier-3 run is in progress
python tools/phase_integrate.py merge           # the one deliberate human decision
```

Branch names are generated from validated parts only: `phase<N>-<slug>` with `N` a positive integer (1-999, no leading zero)
and `slug` matching `[a-z0-9]+(-[a-z0-9]+)*` (at most 60 characters, so it can never start with `-`).

## `start`

Creates `phase<N>-<slug>` from `main` and switches to it. Nothing is committed, nothing is pushed.

Refuses (`BLOCKED`, exit 1, nothing changed) unless: the current branch is `main`; nothing is staged; the only dirty files are
the permitted runtime artifacts; local `main` equals `origin/main` (compared with `git ls-remote`; it never fetches, merges,
rebases or resets - if `main` is behind or ahead you reconcile it yourself); and the phase branch exists neither locally nor on
`origin` (starting over a branch is never silent - to continue existing work use `git switch <branch>` and `prepare`).
It prints the base branch, base HEAD, the new branch and the allowed dirty runtime artifacts.

## `prepare`

Runs, in order, and stops at the first problem:

1. **Preconditions** - the right branch (`phase<N>-<slug>`, or `main` with `--adopt-working-tree`), an empty index, at least one
   source change (or commits already on the branch - see *Resuming*), and an authenticated `gh`.
2. **Candidate discovery** - `git status --porcelain=v1 -z --untracked-files=all --no-renames`. Every dirty path except the exact
   runtime artifacts is a source candidate (modified, untracked, deleted).
3. **Suspicious-file gate** - refuses (nothing is staged, nothing is deleted) on `.env` / `.env.*` (except `.env.example`), keys and
   certificate stores (`*.pem`, `*.key`, `id_rsa`, `id_ed25519`, ...), credential files, SQLite / database files and dumps, virtual
   environments, `node_modules`, `.git` / nested repositories, generated archives, Docker sockets, symlinks, editor swap files, files
   over 5 MiB, `monitoring/runtime/` (except `.gitkeep`) and **any other log file** (`*.log`, `logs/...`) - only the two exact runtime
   artifacts may stay dirty, so an unexpected `logs/R1.log` change blocks rather than being committed. This gate is path-based; file
   *content* is scanned by the repository's own Tier-3 `static.hygiene` check in the next step.
4. **Source diff check** - `git diff --check` limited to the tracked source candidates (the runtime logs' whitespace never matters).
5. **Local validation** - `python tier3.py --base main --working-tree --format json` (targeted at the change effect). `--full` adds
   `--mode full` for the whole regression surface. `PASS` and `PASS_WITH_WARNINGS` continue; `FAIL`, `INCOMPLETE`, a timeout or a
   crash stop here with the command, exit code and blocking checks - **nothing has been staged, committed, pushed or opened**, and on
   `--adopt-working-tree` you are still on `main` with the working tree untouched.
6. **Branch** (adoption only) - `git switch -c phase<N>-<slug>` from `main`. Because the new branch starts at the current commit, no
   file, staged or unstaged state changes; the tool verifies the dirty-file set is identical afterwards.
7. **Stage** - one `git add -- <path>` per derived candidate. Never `git add .`, `-A`, `-u` or `git commit -a`. The tool's command
   allowlist cannot even express those, and cannot stage the runtime logs.
8. **Verify the staged set** - `git diff --cached --check`, and the staged manifest must equal the derived candidate set exactly, with
   the runtime logs unstaged and nothing else changed meanwhile. On a mismatch it aborts before committing and unstages only its own
   paths (`git restore --staged`, index only - your working-tree content is never touched).
9. **Commit** - `git commit -m "<--message>"` (plus any `--trailer "Key: value"`). Verified: HEAD moved, the commit contains exactly the
   intended paths, only the runtime logs remain dirty.
10. **Push** - `git push -u origin <branch>`. **Never** forced: a remote branch whose history is not an ancestor of yours stops the tool
    (`REMOTE_DIVERGED`) before pushing. After the push the remote tip is verified.
11. **Pull request** - `gh pr list --head <branch>` first; an open PR is reused (never duplicated). Otherwise `gh pr create --base main
    --head <branch>` with a generated body (phase, base HEAD, phase commit, local validation result, the runtime-log exclusion and the
    reminder that hosted Tier-3 must succeed). `--pr-title` overrides the title (default: the commit subject); `--pr-footer` appends
    text to the body. If a PR for the branch was already merged, it stops (`PR_ALREADY_MERGED`).

`prepare` **never merges**. It ends with `PR_CREATED` (or `PR_REUSED`) plus the current hosted state, normally `WAITING_FOR_CI`.

### Resuming and idempotency

Re-running `prepare` on the phase branch with nothing left to commit goes straight to push and PR (no new commit, no duplicate PR).
If new source changes exist it validates and adds a follow-up commit to the same PR (for example after a review or a failed hosted run).
`merge` on an already-merged PR does not merge again; it just synchronises `main`. `status` and `--dry-run` never change anything.

## `--adopt-working-tree` (one-time bootstrap)

For work that was implemented, uncommitted, on `main` before this tool existed (Phase 18):

```bash
python tools/phase_integrate.py prepare --phase 18 --slug raw-configlets \
    --message "Phase 18: add Raw Configlets and isolated verifier sandbox" \
    --pr-title "Phase 18: Raw Configlets and isolated verifier sandbox" --adopt-working-tree
```

Explicit only: it needs `--slug`, requires the current branch to be `main` (equal to `origin/main`), an empty index, at least one
source change and a free branch name. After validation passes it creates the branch from the same commit, so the whole working tree
(source and runtime logs) is preserved, then continues as above. Without the flag, dirty source on `main` is a refusal, never adopted.

## `status` (read-only)

`python tools/phase_integrate.py status [--phase N]` resolves the phase branch (the current one, or from `main` via `--phase N`) and
prints the branch, local / remote / PR head SHAs, the PR (number, URL, state, base <- head), GitHub's mergeability, the hosted
`Tier-3 validation` result, other checks, the working-tree state and finally one of `MERGE_ALLOWED`, `WAITING_FOR_CI`, `BLOCKED`,
`NO_PR` or `MERGED`. Exit 0 for `MERGE_ALLOWED` / `WAITING_FOR_CI` / `MERGED`, 1 otherwise. It uses `gh pr view --json` and never
scrapes terminal output or Markdown summaries.

## `merge` (the approval boundary)

`python tools/phase_integrate.py merge [--phase N]` is the only way this tool merges. It refuses unless **all** hold:

* a PR exists, is `OPEN`, not a draft, not from a fork, its base is `main` and its head is the expected phase branch;
* the PR head SHA equals the local phase branch tip and `origin/<branch>` (the phase commit you prepared);
* the required hosted check is **`Tier-3 validation`** (workflow `Tier-3 validation`, `.github/workflows/tier3-validation.yml`, job
  `Tier-3 validation`) and its structured conclusion is `SUCCESS`. Pending / queued / in progress, cancelled, skipped, failure,
  timed out, action required, neutral, stale / unrecognised, or not reported at all all refuse (the last two states are "not yet"
  or "unknown", never a pass). `PASS_WITH_WARNINGS` *inside* the report is fine when the GitHub job itself succeeded;
* no other reported check is failing or still running;
* GitHub reports the PR `MERGEABLE` with merge state `CLEAN` / `HAS_HOOKS`;
* nothing is staged and no source file changed since `prepare` (the two runtime logs may stay dirty).

It then runs `gh pr merge <n> --merge --match-head-commit <sha>`: a **merge commit** (like Phases 16 and 17), pinned to the verified head so
a late push cannot slip in. Never `--squash`, `--rebase`, `--auto`, `--admin` or `--delete-branch`. Afterwards it runs `git switch main` (if
needed) and `git pull --ff-only origin main`, verifies `main` contains the merge commit, prints the new `main` HEAD and `git log -5`, and
checks that only the runtime logs are dirty. Anything unexpected is reported (`MERGED_LOCAL_STATE_UNEXPECTED`, exit 1), never cleaned.
Phase branches are not deleted; cleanup is a separate, deliberate action.

## Runtime-log policy

`Run_Logs.log` and `logs/R2.log` are the only permitted dirty paths (`RUNTIME_ARTIFACTS` in the tool, one place, exact paths, no globs).
They are excluded from candidates, may never be staged (the command allowlist refuses it), survive every command, and are not
evaluated by the source diff gate. Adding another path is a deliberate edit of that constant.

## `--dry-run`

`start`, `prepare` and `merge` accept `--dry-run`. It performs every **read-only** check (preconditions, `git ls-remote`, candidate
discovery, the suspicious-file gate, `git diff --check`, `gh auth status`, PR / check lookup) and prints what would happen: the branch
operation, candidates and exclusions, the validation command, the commit, the push and the PR / merge. It creates no branch, stages nothing,
commits nothing, pushes nothing, opens / merges no PR and **does not run the Tier-3 validation** (that is the documented boundary: validation
is shown, not executed). Mutation is blocked structurally: every non-read command is skipped by the runner in dry-run mode.

## `--json`

`--json` prints one document on stdout (progress goes to stderr) with `command`, `result`, `phase`, `branch`, `base_head`, `phase_head`,
`pr_number`, `pr_url`, `checks`, `tier3`, `merge_allowed`, `blockers`, `final_main_head` where applicable. On a refusal: `result` is
`BLOCKED` with `reason` and `details`.

## Results and exit codes

| Result | Meaning |
|---|---|
| `READY` | `start` created the branch |
| `PR_CREATED` / `PR_REUSED` | `prepare` finished; the PR exists; not merged |
| `WAITING_FOR_CI` / `MERGE_ALLOWED` | hosted validation is still running / passed and merge is permitted |
| `MERGED` | merged with a merge commit and local `main` synchronised |
| `DRY_RUN` | read-only checks passed; nothing was changed |
| `BLOCKED` | a safety refusal or failed gate |

Exit `0` success, `1` blocked / failed gate, `2` usage error, `3` a `git` or `gh` command itself failed.

## Failure and recovery

| Situation | What happened | What to do |
|---|---|---|
| Validation failed | nothing staged / committed / pushed; branch not created (adoption) | fix, re-run `prepare` |
| Suspicious file | nothing staged, nothing deleted | remove or ignore the file, re-run |
| Staging mismatch | aborted before commit; own staging undone | inspect `git status`, re-run |
| `REMOTE_DIVERGED` | the commit exists locally, nothing pushed | reconcile with the remote yourself; the tool never forces |
| Push / `gh` failure | reported verbatim (exit 3); no credential workaround | fix authentication / network, re-run (idempotent) |
| Hosted Tier-3 failed | `merge` refuses | fix, re-run `prepare` (adds a commit, same PR), wait, `merge` |
| Merged but local sync failed | GitHub is merged | `git switch main && git pull --ff-only origin main`, or re-run `merge` |

No command ever uses `reset`, `clean`, `stash`, `checkout`, `rebase`, `--force` or `--force-with-lease`.

## Safety design

Every external command passes through one allowlist (`classify_argv`): a fixed set of argument shapes for `git`, `gh` and the
Tier-3 launcher, executed with an argv list and `shell=False` (there is exactly one `subprocess` call site). A contract test
(`web/core/tests/test_phase_integrate.py`) proves the tool imports no device / network automation, spells no shell, force, add-all,
commit-all, reset, clean, stash, squash or rebase command, and keeps the runtime-log paths in one constant. Tier-3 classifies
`tools/**` as the `dev_tooling` subsystem, which selects the tool's own test module in addition to the baseline static gates.

## Limits

The tool trusts `gh` for GitHub semantics (including branch-protection outcomes reported as merge state) and does not implement its own
GitHub client. The suspicious-file gate is path-based and conservative, not a secret scanner. Branch cleanup after a merge is manual.
