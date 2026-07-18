# Pleiades / MODOS Integration Boundary

This repository is a managed fork of the upstream `Conway-Research/automaton` runtime. It is retained as a **reference corpus**, not as a directly runnable Pleiades component.

## Why the boundary is strict

The upstream runtime is intentionally capable of consequential action. Its documented surfaces include shell and file operations, wallet and payment activity, external service provisioning, self-modification, scheduled background work, and child-agent replication. Those mechanisms are useful research material, but the repository as a whole does not satisfy MODOS's bounded-authority, promotion-before-canon, and replaceable-organ requirements.

A repository-level component declaration cannot make those execution paths proposal-only. Accordingly, MODOS assigns this source `authority: none`, `lifecycle: reference`, and `promotionPolicy: never-promote`.

## Allowed use

Pleiades agents may:

- inspect a reviewed source snapshot in an isolated workspace;
- extract narrowly defined runtime, planner, memory, heartbeat, or coordination patterns;
- produce threat models and comparison evidence;
- propose a clean adapter or reimplementation with typed inputs and outputs;
- test that candidate in a Ghost world or disposable environment.

## Prohibited use

Pleiades must not:

- launch this repository as a MODOS workload;
- expose its shell, wallet, domain, payment, replication, or self-modification tools as PDK capabilities;
- treat its constitution or internal policy checks as an authority boundary;
- import mutable runtime state, credentials, wallets, or agent identity into Atlas or canon;
- promote this fork, an upstream release, or a generated child directly into operational infrastructure.

## Promotion path for a useful mechanism

A mechanism becomes eligible only after it is separated into a bounded adapter or clean implementation that:

1. declares typed domain objects and capability requirements;
2. has no ambient shell, wallet, network, or self-modification authority;
3. runs in an isolated evaluation environment;
4. emits evidence and rollback metadata;
5. passes machine, steward, and—where user-facing—ordinary-person evaluation;
6. enters canon only through a separate governed promotion transaction.

The source repository remains reference material even when one of its extracted ideas earns promotion elsewhere.
