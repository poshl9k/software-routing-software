# ADR-0001: Remove demo data and LAB_MODE entirely

- Status: accepted
- Date: 2026-10-01
- Deciders: project owner, agent

## Context

The product carried two "non-production" surfaces:

1. **Demo data** — when no saved configuration version existed, the UI fell back
   to fabricated `demoConfiguration` / `demoEvents` (and the unused `demoLeases`),
   showing invented interfaces, zones and events plus a "demo data" banner. This
   was used for screenshots and lab views.
2. **LAB_MODE** — `bootstrap.sh --lab` installed an insecure plain-HTTP TCP bridge
   (`vs-router-web-tcp.service` on :8080) and wrote a drop-in setting
   `VS_ROUTER_COOKIE_SECURE=0`, disabling Secure cookies.

Maintaining both complicates the release model (a demo build flag / a separate
`demo` branch) and ships an insecure access path and fabricated content into the
product. The owner chose simplicity: remove both, and on an empty DB/config the
panel simply offers primary setup.

## Decision

- Remove all fabricated demo data from the frontend: `demoConfiguration`,
  `demoEvents`, `demoLeases` (and the abandoned `VITE_DEMO` build flag,
  `buildConfig.ts`, `vite-env.d.ts`, `.env.demo`, `build:demo`/`test:demo`
  scripts). The unconfigured fallback becomes `emptyConfiguration` with a banner
  prompting primary setup.
- The test that relied on `demoConfiguration` (`maintenance-features.test.tsx`)
  uses a neutral `sampleConfiguration` (one tunnel + one peer) instead.
- Remove LAB_MODE entirely: the `--lab` bootstrap flag and its prompt, the
  `vs-router-web-tcp.service` unit file, the `lab.conf` drop-in, and the
  `VS_ROUTER_COOKIE_SECURE` toggle (cookies are now always `Secure`).
- Remove all doc references to the lab TCP bridge / port 8080
  (`README.md`, `installer/README.md`, `docs/install.md`) and the `lab/`
  developer-script directory.
- Keep `mockups/` as design reference (not shipped, not LAB_MODE).
- Delete the `demo` branch (already pushed) and discard the uncommitted
  `VITE_DEMO` WIP on `main`.

## Consequences

- No populated/screenshot view without a real (or lab) configuration; first-run
  UX is an explicit setup prompt, not invented data.
- Cookies are always Secure; the insecure lab access path is gone.
- Single branch, no demo build flag — simpler release/merge model.
- Tests exercise the real empty/unconfigured path.

## Trade-off

We lose the ability to show a populated panel for demos/screenshots without
first configuring a server. Accepted: the simplicity and the removal of an
insecure path outweigh it. If a populated demo is later needed, it should be a
separate, clearly-marked build artifact rather than fallback data in the
working line.
