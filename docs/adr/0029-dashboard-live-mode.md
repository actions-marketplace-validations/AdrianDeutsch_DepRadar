# ADR 0029 — Dashboard live mode (multi-ecosystem without persistence)

- Status: Accepted
- Date: 2026-07-03
- Deciders: Architecture

## Context

The web path (scan queue → Worker → Postgres → dashboard) is NuGet-only; the four
other ecosystems lived exclusively in the CLI. Generalizing the persistence pipeline
(ecosystem column on packages/scans/snapshots, worker dispatch, every query) is a
multi-slice rebuild — but the *visualization* value doesn't need it: the stateless
scanner path already produces a full `GraphAssessment` for every ecosystem.

## Decision

- **A live query, not a schema change.** `GetLiveGraphQuery(ecosystem, package,
  version)` dispatches to the ecosystem's scanner (NuGet goes through the stateless
  `ProjectAnalyzer`) and projects the one `GraphAssessment` into the SAME two DTOs the
  persisted path serves (`PackageGraphDto` + `GraphRiskDto`) — so the client renders
  both modes with identical code.
- **`GET /api/live/{ecosystem}/{**package}`** — a catch-all package segment, because
  Go module paths and npm scopes contain slashes; the version rides as a query
  parameter. Unknown ecosystems are a 400, unresolvable packages a 404. The scan runs
  inside the request (seconds, thanks to the bounded-concurrent advisory lookups of
  ADR 0027) and is cached by HybridCache like every other scan.
- **The dashboard gains an ecosystem selector** and a `?eco=npm&package=express`
  deep link. In live mode the DB-backed panels (upgrade advice, diff, drift, chat,
  SBOM/report downloads) hide via one `db-only` CSS class — the graph and the risk
  ranking are the product here, and the status line says "live, not persisted"
  honestly.

## Consequences

- All five ecosystems are now visible in the web UI with zero schema/migration risk;
  drift, watchlist, badges and the report/chat features remain NuGet-only (the
  documented next frontier if persistence ever generalizes).
- A live request does real registry/OSV work; repeated views are served from
  HybridCache within the API process.
- Verified end-to-end against a real host: `/api/live/npm/left-pad`,
  `/api/live/go/golang.org/x/text?version=v0.3.7` (slash path), a 400 for `maven`,
  and a headless-Chrome screenshot of `?eco=npm&package=express` rendering the
  68-node express graph (now `docs/assets/dashboard-live.png`).

[ADR 0027]: 0027-cli-consistency-and-performance.md
