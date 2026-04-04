# @attestto-com/vc-sdk

Universal SDK for issuing and verifying W3C Verifiable Credentials, developed by [Attestto Open](https://attestto.org).

> **Any credential type. Any DID method. Any schema. Zero native dependencies.**
>
> This SDK implements the [W3C Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/). Domain-specific credential types (driving, banking, health, etc.) are defined in separate schema packages and are proposals open to institutional review.

## Install

```bash
npm install @attestto-com/vc-sdk
```

## Quick start

```typescript
import { VCIssuer, VCVerifier, generateKeyPair } from '@attestto-com/vc-sdk'

// Generate keys (Ed25519 or ES256)
const keys = generateKeyPair()

// Create an issuer
const issuer = new VCIssuer({
  did: 'did:web:my-org.attestto.id',
  privateKey: keys.privateKey,
})

// Issue any credential — no type constraints
const vc = await issuer.issue({
  type: 'UniversityDegree',
  context: 'https://schemas.example.org/education/v1',
  subjectDid: 'did:web:student.attestto.id',
  claims: {
    degree: {
      name: 'Computer Science',
      level: 'Bachelor',
      university: 'Universidad de Costa Rica',
    },
  },
})

// Verify
const verifier = new VCVerifier()
const result = await verifier.verifyWithKey(vc, keys.publicKey, 'Ed25519', {
  expectedType: 'UniversityDegree',
  expectedIssuer: 'did:web:my-org.attestto.id',
})
console.log(result.valid) // true
```

## Schema plugins (plug-and-play)

Domain-specific schemas register as plugins — auto-add JSON-LD context and wrap claims:

```typescript
import { VCIssuer } from '@attestto-com/vc-sdk'

const issuer = new VCIssuer({ did: 'did:web:cosevi.attestto.id', privateKey })

// Register the CR driving schema plugin
issuer.use({
  context: 'https://schemas.attestto.org/cr/driving/v1',
  types: ['DrivingLicense', 'TheoreticalTestResult', 'PracticalTestResult'],
  propertyMap: {
    DrivingLicense: 'license',
    TheoreticalTestResult: 'theoreticalTest',
    PracticalTestResult: 'practicalTest',
  },
})

// Now issue — context and property wrapping are automatic
const vc = await issuer.issue({
  type: 'DrivingLicense',
  subjectDid: 'did:web:maria.attestto.id',
  claims: {
    licenseNumber: 'CR-2026-045678',
    categories: ['B'],
    status: 'active',
  },
})
// vc['@context'] includes cr/driving/v1 automatically
// vc.credentialSubject.license wraps the claims automatically
```

## Available schema packages

| Package | Domain | Repo |
|---|---|---|
| **cr-vc-schemas** | Costa Rica driving ecosystem (mDL, tests, medical, vehicles) | [Attestto-com/cr-vc-schemas](https://github.com/Attestto-com/cr-vc-schemas) |
| cr-banking-schemas | Banking KYC, accounts, transfers | Planned |
| cr-health-schemas | Medical, CCSS, professional licenses | Planned |
| cr-education-schemas | Degrees, certifications, MEP | Planned |
| cr-legal-schemas | Firma digital BCCR, notarial, powers of attorney | Planned |
| cr-property-schemas | Registro Nacional, real estate | Planned |

## API

### `VCIssuer`

```typescript
const issuer = new VCIssuer(config: IssuerConfig)
issuer.use(plugin: SchemaPlugin)       // Register domain schemas
const vc = await issuer.issue(options)  // Issue a signed VC
```

### `VCVerifier`

```typescript
const verifier = new VCVerifier(config?: VerifierConfig)
const result = await verifier.verify(vc, options?)
const result = await verifier.verifyWithKey(vc, publicKey, algorithm, options?)
```

### `generateKeyPair`

```typescript
const keys = generateKeyPair('Ed25519') // or 'ES256'
```

## Ecosystem

Full index: [Attestto-com/attestto-open](https://github.com/Attestto-com/attestto-open)

| Repo | What |
|---|---|
| [vc-sdk](https://github.com/Attestto-com/vc-sdk) | This — universal VC SDK |
| [cr-vc-sdk](https://github.com/Attestto-com/cr-vc-sdk) | CR-specific SDK (TypeScript, typed wrappers) |
| [cr-vc-sdk-dotnet](https://github.com/Attestto-com/cr-vc-sdk-dotnet) | CR-specific SDK (.NET 8) |
| [cr-vc-schemas](https://github.com/Attestto-com/cr-vc-schemas) | CR driving schemas (11 types) |
| [did-sns-spec](https://github.com/Attestto-com/did-sns-spec) | did:sns DID method spec |
| [did-sns-resolver](https://github.com/Attestto-com/did-sns-resolver) | Universal Resolver driver for did:sns |
| [id-wallet-adapter](https://github.com/Attestto-com/id-wallet-adapter) | Wallet discovery protocol |

## License

Apache 2.0
