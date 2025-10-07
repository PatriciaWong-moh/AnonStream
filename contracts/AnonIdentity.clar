(define-constant ERR-NOT-AUTHORIZED u100)
(define-constant ERR-INVALID-PREIMAGE u101)
(define-constant ERR-INVALID-COMMITMENT u102)
(define-constant ERR-ID-ALREADY-EXISTS u103)
(define-constant ERR-ID-NOT-FOUND u104)
(define-constant ERR-NOT-OWNER u105)
(define-constant ERR-INVALID-TIMESTAMP u106)
(define-constant ERR-AUTHORITY-NOT-VERIFIED u107)
(define-constant ERR-INVALID-METADATA u108)
(define-constant ERR-INVALID-EXPIRY u109)
(define-constant ERR-ID-EXPIRED u110)
(define-constant ERR-INVALID-UPDATE-PARAM u111)
(define-constant ERR-MAX-IDS-EXCEEDED u112)
(define-constant ERR-INVALID-ID-TYPE u113)
(define-constant ERR-INVALID-FEE u114)
(define-constant ERR-INVALID-STATUS u115)
(define-constant ERR-INVALID-REVEAL-CONTEXT u116)
(define-constant ERR-INVALID-BLACKLIST-REASON u117)
(define-constant ERR-ALREADY-BLACKLISTED u118)
(define-constant ERR-NOT-BLACKLISTED u119)
(define-constant ERR-INVALID-OWNER u120)

(define-data-var next-id uint u0)
(define-data-var max-ids uint u1000000)
(define-data-var creation-fee uint u10)
(define-data-var authority-contract (optional principal) none)

(define-map identities
  uint
  {
    commitment: (buff 32),
    preimage-hash: (buff 32),
    metadata: (buff 128),
    expiry: uint,
    timestamp: uint,
    owner: principal,
    id-type: (string-utf8 50),
    status: bool,
    reveal-count: uint
  }
)

(define-map identities-by-commitment
  (buff 32)
  uint)

(define-map identity-updates
  uint
  {
    update-metadata: (buff 128),
    update-expiry: uint,
    update-timestamp: uint,
    updater: principal
  }
)

(define-map blacklisted-ids
  uint
  {
    reason: (string-utf8 256),
    blacklisted-at: uint,
    blacklister: principal
  }
)

(define-read-only (get-identity (id uint))
  (map-get? identities id)
)

(define-read-only (get-identity-updates (id uint))
  (map-get? identity-updates id)
)

(define-read-only (is-id-registered (commitment (buff 32)))
  (is-some (map-get? identities-by-commitment commitment))
)

(define-read-only (get-blacklist-info (id uint))
  (map-get? blacklisted-ids id)
)

(define-private (validate-preimage (preimage (buff 32)))
  (if (> (len preimage) u0)
      (ok true)
      (err ERR-INVALID-PREIMAGE))
)

(define-private (validate-commitment (commitment (buff 32)))
  (if (is-eq (len commitment) u32)
      (ok true)
      (err ERR-INVALID-COMMITMENT))
)

(define-private (validate-metadata (meta (buff 128)))
  (if (<= (len meta) u128)
      (ok true)
      (err ERR-INVALID-METADATA))
)

(define-private (validate-expiry (exp uint))
  (if (> exp block-height)
      (ok true)
      (err ERR-INVALID-EXPIRY))
)

(define-private (validate-timestamp (ts uint))
  (if (>= ts block-height)
      (ok true)
      (err ERR-INVALID-TIMESTAMP))
)

(define-private (validate-id-type (type (string-utf8 50)))
  (if (or (is-eq type u"anon") (is-eq type u"pseudonym") (is-eq type u"verified"))
      (ok true)
      (err ERR-INVALID-ID-TYPE))
)

(define-private (validate-status (status bool))
  (ok true)
)

(define-private (validate-reveal-count (count uint))
  (if (<= count u10)
      (ok true)
      (err ERR-INVALID-REVEAL-CONTEXT))
)

(define-private (validate-blacklist-reason (reason (string-utf8 256)))
  (if (> (len reason) u0)
      (ok true)
      (err ERR-INVALID-BLACKLIST-REASON))
)

(define-private (validate-principal (p principal))
  (if (not (is-eq p 'SP000000000000000000002Q6VF78))
      (ok true)
      (err ERR-INVALID-OWNER))
)

(define-private (check-not-expired (id uint))
  (let ((identity (unwrap! (get-identity id) (err ERR-ID-NOT-FOUND))))
    (if (<= (get expiry identity) block-height)
        (err ERR-ID-EXPIRED)
        (ok true))
  )
)

(define-private (check-not-blacklisted (id uint))
  (if (is-some (get-blacklist-info id))
      (err ERR-ALREADY-BLACKLISTED)
      (ok true))
)

(define-public (set-authority-contract (contract-principal principal))
  (begin
    (try! (validate-principal contract-principal))
    (asserts! (is-none (var-get authority-contract)) (err ERR-AUTHORITY-NOT-VERIFIED))
    (var-set authority-contract (some contract-principal))
    (ok true)
  )
)

(define-public (set-max-ids (new-max uint))
  (begin
    (asserts! (> new-max u0) (err ERR-MAX-IDS-EXCEEDED))
    (asserts! (is-some (var-get authority-contract)) (err ERR-AUTHORITY-NOT-VERIFIED))
    (var-set max-ids new-max)
    (ok true)
  )
)

(define-public (set-creation-fee (new-fee uint))
  (begin
    (asserts! (>= new-fee u0) (err ERR-INVALID-FEE))
    (asserts! (is-some (var-get authority-contract)) (err ERR-AUTHORITY-NOT-VERIFIED))
    (var-set creation-fee new-fee)
    (ok true)
  )
)

(define-public (create-identity
  (preimage (buff 32))
  (metadata (buff 128))
  (expiry uint)
  (id-type (string-utf8 50))
)
  (let (
        (next-id (var-get next-id))
        (current-max (var-get max-ids))
        (authority (var-get authority-contract))
        (commitment (hash160 preimage))
        (preimage-hash (sha256 preimage))
      )
    (asserts! (< next-id current-max) (err ERR-MAX-IDS-EXCEEDED))
    (try! (validate-preimage preimage))
    (try! (validate-commitment commitment))
    (try! (validate-metadata metadata))
    (try! (validate-expiry expiry))
    (try! (validate-id-type id-type))
    (asserts! (is-none (map-get? identities-by-commitment commitment)) (err ERR-ID-ALREADY-EXISTS))
    (let ((authority-recipient (unwrap! authority (err ERR-AUTHORITY-NOT-VERIFIED))))
      (try! (stx-transfer? (var-get creation-fee) tx-sender authority-recipient))
    )
    (map-set identities next-id
      {
        commitment: commitment,
        preimage-hash: preimage-hash,
        metadata: metadata,
        expiry: expiry,
        timestamp: block-height,
        owner: tx-sender,
        id-type: id-type,
        status: true,
        reveal-count: u0
      }
    )
    (map-set identities-by-commitment commitment next-id)
    (var-set next-id (+ next-id u1))
    (print { event: "identity-created", id: next-id })
    (ok next-id)
  )
)

(define-public (update-identity
  (id uint)
  (update-metadata (buff 128))
  (update-expiry uint)
)
  (let ((identity (map-get? identities id)))
    (match identity
      i
        (begin
          (asserts! (is-eq (get owner i) tx-sender) (err ERR-NOT-OWNER))
          (try! (check-not-expired id))
          (try! (check-not-blacklisted id))
          (try! (validate-metadata update-metadata))
          (try! (validate-expiry update-expiry))
          (map-set identities id
            {
              commitment: (get commitment i),
              preimage-hash: (get preimage-hash i),
              metadata: update-metadata,
              expiry: update-expiry,
              timestamp: block-height,
              owner: (get owner i),
              id-type: (get id-type i),
              status: (get status i),
              reveal-count: (get reveal-count i)
            }
          )
          (map-set identity-updates id
            {
              update-metadata: update-metadata,
              update-expiry: update-expiry,
              update-timestamp: block-height,
              updater: tx-sender
            }
          )
          (print { event: "identity-updated", id: id })
          (ok true)
        )
      (err ERR-ID-NOT-FOUND)
    )
  )
)

(define-public (reveal-identity (id uint) (preimage (buff 32)) (context (string-utf8 100)))
  (let ((identity (unwrap! (get-identity id) (err ERR-ID-NOT-FOUND))))
    (try! (check-not-expired id))
    (try! (check-not-blacklisted id))
    (asserts! (is-eq (get owner identity) tx-sender) (err ERR-NOT-OWNER))
    (asserts! (is-eq (sha256 preimage) (get preimage-hash identity)) (err ERR-INVALID_PREIMAGE))
    (asserts! (is-eq (hash160 preimage) (get commitment identity)) (err ERR-INVALID_COMMITMENT))
    (map-set identities id
      (merge identity { reveal-count: (+ (get reveal-count identity) u1) })
    )
    (print { event: "identity-revealed", id: id, context: context })
    (ok identity)
  )
)

(define-public (blacklist-identity (id uint) (reason (string-utf8 256)))
  (begin
    (asserts! (is-some (var-get authority-contract)) (err ERR-AUTHORITY-NOT-VERIFIED))
    (asserts! (is-eq tx-sender (unwrap! (var-get authority-contract) (err ERR-AUTHORITY-NOT-VERIFIED))) (err ERR-NOT-AUTHORIZED))
    (try! (validate-blacklist-reason reason))
    (asserts! (is-none (get-blacklist-info id)) (err ERR-ALREADY-BLACKLISTED))
    (map-set blacklisted-ids id
      {
        reason: reason,
        blacklisted-at: block-height,
        blacklister: tx-sender
      }
    )
    (let ((identity (unwrap! (get-identity id) (err ERR-ID-NOT-FOUND))))
      (map-set identities id
        (merge identity { status: false })
      )
    )
    (print { event: "identity-blacklisted", id: id })
    (ok true)
  )
)

(define-public (unblacklist-identity (id uint))
  (begin
    (asserts! (is-some (var-get authority-contract)) (err ERR-AUTHORITY-NOT-VERIFIED))
    (asserts! (is-eq tx-sender (unwrap! (var-get authority-contract) (err ERR-AUTHORITY-NOT-VERIFIED))) (err ERR-NOT-AUTHORIZED))
    (asserts! (is-some (get-blacklist-info id)) (err ERR-NOT-BLACKLISTED))
    (map-delete blacklisted-ids id)
    (let ((identity (unwrap! (get-identity id) (err ERR-ID-NOT-FOUND))))
      (map-set identities id
        (merge identity { status: true })
      )
    )
    (print { event: "identity-unblacklisted", id: id })
    (ok true)
  )
)

(define-public (transfer-identity-ownership (id uint) (new-owner principal))
  (let ((identity (unwrap! (get-identity id) (err ERR-ID-NOT-FOUND))))
    (try! (check-not-expired id))
    (try! (check-not-blacklisted id))
    (asserts! (is-eq (get owner identity) tx-sender) (err ERR-NOT-OWNER))
    (try! (validate-principal new-owner))
    (map-set identities id
      (merge identity { owner: new-owner })
    )
    (print { event: "identity-ownership-transferred", id: id, new-owner: new-owner })
    (ok true)
  )
)

(define-public (get-id-count)
  (ok (var-get next-id))
)

(define-public (check-id-existence (commitment (buff 32)))
  (ok (is-id-registered commitment))
)

(define-public (verify-ownership (commitment (buff 32)) (preimage (buff 32)))
  (let ((expected-commit (hash160 preimage)))
    (asserts! (is-eq commitment expected-commit) (err ERR-INVALID_COMMITMENT))
    (match (map-get? identities-by-commitment commitment)
      id
        (let ((identity (unwrap! (get-identity id) (err ERR-ID-NOT-FOUND))))
          (try! (check-not-expired id))
          (try! (check-not-blacklisted id))
          (ok (is-eq (get owner identity) tx-sender))
        )
      (err ERR-ID-NOT-FOUND)
    )
  )
)