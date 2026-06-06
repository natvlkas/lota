# Branch model and release flow

LOTA uses a two-branch model: a stable storefront and an integration branch.

```
features (PR) ---> lota-next (1) ---> PR (merge commit) ---> main (2)

(1) - v*-rc tags (pre-releases)
(2) - v* tags (stable releases)
```

## `main` - the storefront

- The default branch: it is what visitors see first.
- Holds **only** fully stable, released code.
- No direct pushes. Changes enter only through a pull request from
  `lota-next`, merged as a **merge commit** (no squash, no rebase) so the
  integration history is preserved. Done only by `Maintainers`.
- Stable releases are tagged here (`v1.0.0`, ...).

See [BUILD-REPRODUCIBLE.md](BUILD-REPRODUCIBLE.md) for how a tag is built and signed.

## `lota-next` - the integration branch

- The permanent integration branch where all new work lands first.
- Cannot be deleted (branch protection).
- Release **candidates** are tagged here (`v1.0.0-rc1`, `v1.0.0-rc2`, ...). The
  release workflow marks any `0.x` or `-`-suffixed tag as a GitHub
  **pre-release**, so these show up under Releases as pre-releases.
- The fuzzers and long-running CI (Syzkaller, configured separately) run
  against this branch.
- The developer and testing policy lives in [DEVELOPMENT.md](DEVELOPMENT.md);
  `README-NEXT.md` is a short pointer to it, identical on both branches, so an
  integration merge never touches it.

## Contributing

Open pull requests against **`lota-next`**, never `main`. Because `main` is the
default branch, a PR opened against it by an outside contributor is
automatically retargeted to `lota-next` with an explanatory comment
(`.github/workflows/pr-router.yml`). The standard checks run on every PR (the
`pull_request` trigger has no branch filter) and on pushes to `lota-next`.
