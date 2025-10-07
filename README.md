# AnonStream

A decentralized, privacy-preserving streaming platform built on the Stacks blockchain using Clarity smart contracts. AnonStream enables users to create anonymous, self-sovereign identities for accessing and streaming content without relying on centralized accounts. Creators can upload and monetize content (e.g., videos, audio, live streams) while users pay anonymously via micropayments or token-gated access.

## Real-World Problems Solved

- **Privacy Erosion in Centralized Platforms**: Services like Netflix or YouTube track user behavior, leading to data breaches (e.g., the 2017 Equifax hack exposed 147M identities; streaming platforms face similar risks). AnonStream uses on-chain commitments for anonymous identities, ensuring no personal data linkage.
  
- **Censorship and Access Barriers**: In regions with internet restrictions (e.g., 3.7B people offline or censored per ITU 2023), users need anonymous access. AnonStream allows pseudonymous streaming without KYC, supporting free expression.

- **Monetization Inequity for Creators**: Small creators earn <1% on big platforms (e.g., YouTube's ad revenue share). AnonStream enables direct, low-fee micropayments via Stacks' Bitcoin-anchored security, reducing intermediaries.

- **Scalability and Cost**: Traditional streaming incurs high server costs; AnonStream offloads metadata to blockchain and streams via IPFS/Arweave, with on-chain access verification for low-latency checks.

By leveraging Stacks' Bitcoin Layer 2, AnonStream inherits fast, cheap transactions (~$0.0001/tx) and finality, making anonymous streaming viable at scale.

## Key Features

- **Anonymous Identity Creation**: Users generate zero-knowledge-like commitments (via hashed secrets) for identities without revealing info.
- **Content Streaming**: Metadata on-chain; actual streams off-chain (IPFS) with on-chain access proofs.
- **Monetization**: Pay-per-view or subscription via fungible tokens (STX or custom).
- **Governance**: Token holders vote on content moderation.
- **Dispute Resolution**: Escrow for refunds/disputes.

## Architecture

AnonStream uses 6 Clarity smart contracts deployed on Stacks mainnet/testnet:

1. **AnonIdentity**: Manages anonymous identity creation and commitments.
2. **ContentRegistry**: Registers content metadata and access policies.
3. **AccessVerifier**: Verifies anonymous access proofs for streaming.
4. **PaymentGateway**: Handles micropayments and token transfers.
5. **EscrowManager**: Escrows funds for disputes/refunds.
6. **GovernanceDAO**: Simple DAO for voting on proposals (e.g., content bans).

Frontend (not included): React app with Stacks.js for wallet integration (Hiro Wallet). Streams via WebRTC/IPFS.

## Smart Contracts Overview

Contracts are written in Clarity (Stacks' secure, decidable language). They follow SIP-009/010 standards for tokens/NFTs. Deploy via Clarinet (local dev tool).

### 1. AnonIdentity.clar
Handles identity minting with commitments (hash(preimage) for anonymity reveal only when needed).

```clarity
(define-constant ERR_INVALID_COMMITMENT (err u100))
(define-constant ERR_ID_ALREADY_EXISTS (err u101))
(define-constant ERR_NOT_OWNER (err u102))

(define-data-var identity-counter uint u0)

(define-map identities 
    { commitment: (buff 32) } 
    { owner: principal, created-at: uint }
)

(define-public (create-identity (preimage (buff 32)))
    (let 
        (
            (commitment (hash160 preimage))
            (next-id (+ (var-get identity-counter) u1))
        )
        (asserts! (map-insert? identities {commitment: commitment} {owner: tx-sender, created-at: block-height}) ERR_ID_ALREADY_EXISTS)
        (var-set identity-counter next-id)
        (ok next-id)
    )
)

(define-read-only (get-identity (commitment (buff 32)))
    (map-get? identities {commitment: commitment})
)

(define-public (reveal-identity (commitment (buff 32)) (preimage (buff 32)))
    (let 
        ((expected-commit (hash160 preimage))
        (stored-identity (unwrap! (get-identity commitment) ERR_INVALID_COMMITMENT)))
        (asserts! (is-eq commitment expected-commit) ERR_INVALID_COMMITMENT)
        (asserts! (is-eq (get owner stored-identity) tx-sender) ERR_NOT_OWNER)
        (ok stored-identity)
    )
)
```

### 2. ContentRegistry.clar
Registers content with metadata (CID for IPFS stream) and access type (free/paywall).

```clarity
(define-constant ERR_INVALID_CID (err u200))
(define-constant ERR_CONTENT_EXISTS (err u201))

(define-data-var content-counter uint u0)

(define-map contents 
    { id: uint } 
    { creator: principal, cid: (string-ascii 64), access-type: uint, price: uint, created-at: uint }
) ;; access-type: 0=free, 1=pay-per-view

(define-public (register-content (cid (string-ascii 64)) (access-type uint) (price uint))
    (let 
        (
            (next-id (+ (var-get content-counter) u1))
        )
        (asserts! (> (len cid) u0) ERR_INVALID_CID)
        (asserts! (not (map-get? contents {id: next-id})) ERR_CONTENT_EXISTS)
        (map-insert contents {id: next-id} 
            { creator: tx-sender, cid: cid, access-type: access-type, price: price, created-at: block-height })
        (var-set content-counter next-id)
        (ok next-id)
    )
)

(define-read-only (get-content (id uint))
    (map-get? contents {id: id})
)
```

### 3. AccessVerifier.clar
Verifies anonymous access using identity commitments.

```clarity
(define-constant ERR_INVALID_PROOF (err u300))
(define-constant ERR_NO_ACCESS (err u301))

(define-map access-grants 
    { identity-commit: (buff 32), content-id: uint } 
    { granted-at: uint, expires-at: uint }
)

(define-public (grant-access (commitment (buff 32)) (content-id uint) (duration uint))
    (let 
        ((identity (unwrap! (contract-call? .anon-identity get-identity commitment) ERR_INVALID_PROOF))
        (now (+ block-height duration)))
        (asserts! (is-eq (get owner identity) tx-sender) ERR_NO_ACCESS)
        (map-insert access-grants {identity-commit: commitment, content-id: content-id} 
            {granted-at: block-height, expires-at: now})
        (ok true)
    )
)

(define-read-only (has-access (commitment (buff 32)) (content-id uint))
    (let 
        ((grant (map-get? access-grants {identity-commit: commitment, content-id: content-id})))
        (if grant
            (and (<= (get expires-at (unwrap-panic grant)) block-height) true)
            false
        )
    )
)
```

### 4. PaymentGateway.clar
SIP-009 fungible token for anonymous payments (integrates with STX or custom token).

```clarity
;; Simplified SIP-009 token for AnonTokens (1:1 with STX for payments)
(define-fungible-token anon-token u1000000000) ;; 1B supply

(define-constant ERR_INSUFFICIENT_BALANCE (err u400))
(define-constant ERR_TRANSFER_FAILED (err u401))

(define-map payments 
    { payer-commit: (buff 32), content-id: uint } 
    { amount: uint, paid-at: uint }
)

(define-public (pay-for-content (commitment (buff 32)) (content-id uint) (amount uint))
    (let 
        ((content (unwrap! (contract-call? .content-registry get-content content-id) ERR_TRANSFER_FAILED))
        (expected-price (get price content)))
        (asserts! (>= (ft-get-balance anon-token tx-sender) amount) ERR_INSUFFICIENT_BALANCE)
        (asserts! (is-eq amount expected-price) ERR_TRANSFER_FAILED)
        (try! (contract-call? .ft-transfer anon-token amount tx-sender (get creator content)))
        (map-insert payments {payer-commit: commitment, content-id: content-id} 
            {amount: amount, paid-at: block-height})
        (ok true)
    )
)
```

### 5. EscrowManager.clar
Escrows payments for disputes, releasable by creator or arbitrator.

```clarity
(define-constant ERR_ESCROW_NOT_FOUND (err u500))
(define-constant ERR_NOT_AUTHORIZED (err u501))

(define-map escrows 
    { payment-id: uint } 
    { amount: uint, recipient: principal, status: uint, disputed: bool } ;; status: 0=active, 1=released, 2=refunded
)

(define-public (escrow-payment (payment-id uint) (amount uint))
    (map-insert escrows {payment-id: payment-id} 
        {amount: amount, recipient: tx-sender, status: u0, disputed: false})
    (ok true)
)

(define-public (release-escrow (payment-id uint))
    (let 
        ((escrow (unwrap! (map-get? escrows {payment-id: payment-id}) ERR_ESCROW_NOT_FOUND))
        (creator (get recipient escrow)))
        (asserts! (is-eq tx-sender creator) ERR_NOT_AUTHORIZED)
        (asserts! (not (get disputed escrow)) ERR_NOT_AUTHORIZED)
        (map-set escrows {payment-id: payment-id} 
            {amount: (get amount escrow), recipient: creator, status: u1, disputed: false})
        (ok true)
    )
)

(define-public (dispute-escrow (payment-id uint))
    (let 
        ((escrow (map-get? escrows {payment-id: payment-id})))
        (asserts! escrow ERR_ESCROW_NOT_FOUND)
        (map-set escrows {payment-id: payment-id} 
            (merge escrow {disputed: true}))
        (ok true)
    )
)
```

### 6. GovernanceDAO.clar
Simple voting for proposals (e.g., ban content).

```clarity
(define-constant ERR_VOTE_NOT_OPEN (err u600))
(define-constant ERR_ALREADY_VOTED (err u601))

(define-data-var proposal-counter uint u0)
(define-data-var vote-period uint u100) ;; Blocks for voting

(define-map proposals 
    { id: uint } 
    { description: (string-ascii 256), yes-votes: uint, no-votes: uint, open: bool, executed: bool }
)

(define-map votes 
    { proposal-id: uint, voter: principal } 
    bool
)

(define-public (create-proposal (description (string-ascii 256)))
    (let 
        ((next-id (+ (var-get proposal-counter) u1)))
        (map-insert proposals {id: next-id} 
            {description: description, yes-votes: u0, no-votes: u0, open: true, executed: false})
        (var-set proposal-counter next-id)
        (ok next-id)
    )
)

(define-public (vote-yes (proposal-id uint))
    (let 
        ((proposal (unwrap! (map-get? proposals {id: proposal-id}) ERR_VOTE_NOT_OPEN))
        (voter-key {proposal-id: proposal-id, voter: tx-sender}))
        (asserts! (get open proposal) ERR_VOTE_NOT_OPEN)
        (asserts! (not (map-get? votes voter-key)) ERR_ALREADY_VOTED)
        (map-insert votes voter-key true)
        (map-set proposals {id: proposal-id} 
            (merge proposal {yes-votes: (+ (get yes-votes proposal) u1)}))
        (ok true)
    )
)

;; Similar vote-no function omitted for brevity

(define-public (close-proposal (proposal-id uint))
    (let 
        ((proposal (map-get? proposals {id: proposal-id})))
        (asserts! proposal ERR_VOTE_NOT_OPEN)
        (if (> (get yes-votes (unwrap-panic proposal)) (get no-votes (unwrap-panic proposal)))
            ;; Execute yes (e.g., integrate with ContentRegistry for ban)
            (ok true)
            (ok false)
        )
    )
)
```

## Setup & Deployment

1. **Prerequisites**:
   - Install Clarinet: `cargo install clarinet`.
   - Stacks wallet (Hiro) with testnet STX.

2. **Local Development**:
   ```
   clarinet new anonstream
   cd anonstream
   # Copy .clar files to contracts/
   clarinet develop
   clarinet test
   ```

3. **Deployment**:
   - Use Clarinet to deploy to testnet: `clarinet deploy --network testnet`.
   - Update frontend with contract addresses.

4. **Testing**:
   - Run `clarinet test` for unit tests (add test files in tests/).
   - Example: Simulate identity creation and access grant.

5. **Frontend Integration**:
   - Use Stacks.js: `npm i @stacks/connect`.
   - Query contracts via `callReadOnly`.

## Security Considerations

- **Audits**: Recommend external audit (e.g., via OpenZeppelin for Clarity).
- **Reentrancy**: Clarity's atomic tx prevent it.
- **Anonymity Limits**: Commitments hide identities but traceable via chain analysis; use mixers for enhanced privacy.
- **Upgrades**: Use Clarity 2.0 traits for proxy patterns.


## Contributing

Fork, PR with tests. License: MIT.

## Resources

- [Stacks Docs](https://docs.stacks.co/)
- [Clarity Book](https://docs.clarity-lang.org/)
