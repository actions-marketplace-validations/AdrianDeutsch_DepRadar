# ADR 0021 — Multi-ecosystem auto-fix (package.json, requirements.txt)

- Status: Accepted
- Date: 2026-07-01
- Deciders: Architecture

## Context

`depradar fix` ([ADR 0014]) rewrote vulnerable direct dependencies in `.csproj`/props
files only. With manifests now first-class scan targets ([ADR 0020]) and OSV fix data
available for every ecosystem, the remediation loop should close for npm and PyPI too.

## Decision

- **Same semantics, per-ecosystem mechanics.** `EcosystemFix` reuses the NuGet
  parent-bump strategy: a direct dependency needs fixing if anything in *its* resolved
  graph carries an advisory; candidates above the currently-resolved version (via the
  shared, pure `SafeUpgradeFinder.Candidates`) are scored until one resolves a fully
  clean graph. The scanners gained a `ListVersionsAsync` port for the candidate pool.
- **Pure patchers, targeted text edits.** `NpmManifestPatcher` rewrites only inside the
  `dependencies` object (brace-tracked span) and **keeps the declared `^`/`~` operator**,
  so the manifest stays idiomatic; `devDependencies` are untouched. `RequirementsPatcher`
  rewrites only exact `==` pins (PEP 503 name matching), preserving trailing comments and
  markers — any other specifier has no single unambiguous version to replace and is
  reported for a manual bump instead.
- **One entry point.** `depradar fix` dispatches by file name (`package.json` → npm,
  `*.txt` → PyPI, else NuGet XML); `--dry-run`, in-place patching and `--open-pr` work
  identically because the PR port is content-based.

## Consequences

- PyPI bumps are written zero-padded (`5.4` → `==5.4.0`); PEP 440 treats them as equal,
  so pip resolves them identically.
- A fix is only proposed when a candidate's *entire* graph is clean — verified live:
  idna 2.7 was correctly left unfixed because OSV flags even 3.7's fix as bypassable
  (GHSA-65pc-fj4g-8rjx), while minimist 1.2.5 → 1.2.6 and pyyaml 5.3.1 → 5.4.0 (comment
  preserved) patched cleanly.
- The candidate cap (`SafeUpgradeFinder.MaxCandidates`) bounds registry traffic; a fix
  further away than that surfaces as "no newer version resolves a clean graph".

[ADR 0014]: 0014-remediation-minimal-safe-upgrade.md
[ADR 0020]: 0020-manifest-scanning-and-ecosystem-cli.md

## Follow-up (2026-07-03): Cargo and Go

`fix` now covers all five ecosystems. `CargoManifestPatcher` rewrites the three
manifest forms (`name = "1.0"`, inline table, `[dependencies.name]` sub-table),
preserving a leading `=`/`^`/`~`; `GoModPatcher` rewrites single and block `require`
lines with the `v` prefix. One semantic split: the fix bar is now explicit
(`EcosystemFix.WholeGraphClean` vs `RootClean`). Go uses **root-clean** — a declared
go.mod graph pins historical minimum versions MVS never actually installs, so the
whole-graph bar is unsatisfiable there (verified: x/text 0.3.8's declared graph still
carries ancient x/net pseudo-version Criticals); `go get module@vNEW` bumps exactly
the module itself. npm/PyPI/Cargo keep the stricter parent-bump bar.
Verified live: Cargo.toml regex `=1.5.4`→`=1.5.5` + smallvec `=1.6.0`→`=1.6.1`;
go.mod x/text `v0.3.7`→`v0.3.8` + gin `v1.9.0`→`v1.9.1`, patched in place.
