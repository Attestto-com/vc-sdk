# @attestto/vc-sdk — Operating Rules

> Universal SDK for issuing and verifying W3C Verifiable Credentials -- any schema, any DID method.

## Stack

- TypeScript (ESM + CJS dual export)
- Build: tsup
- Tests: Vitest
- Crypto: @noble/curves, @noble/hashes, jose
- Node >= 18

## Commands

- `pnpm install` -- install deps
- `pnpm build` -- build with tsup
- `pnpm test` -- run tests (vitest)
- `pnpm test:watch` -- run tests in watch mode
- `pnpm test:coverage` -- run tests with coverage
- `pnpm lint` -- lint src and tests (eslint)
- `pnpm typecheck` -- type-check without emitting
- `pnpm clean` -- remove dist and coverage

## Architecture

- `VCIssuer` -- issues signed VCs (Ed25519 or ES256)
- `VCVerifier` -- verifies VCs with key or resolver
- `generateKeyPair` -- key generation utility
- Schema plugins register via `issuer.use()` for domain-specific context injection

## Rules

- This is a public `@attestto/*` package -- changes must not break downstream consumers (cr-vc-sdk depends on this)
- Ship tests with every change
- Zero native dependencies -- keep it that way
- W3C VC Data Model v2.0 compliance is mandatory
- Do not add CORTEX-specific rules here -- this repo has its own conventions
- Do not run `pnpm dev` -- user owns the dev server
