(define-constant ERR_INVALID_PROOF u300)
(define-constant ERR_NO_ACCESS u301)
(define-constant ERR_INVALID_COMMITMENT u302)
(define-constant ERR_INVALID_CONTENT_ID u303)
(define-constant ERR_INVALID_DURATION u304)
(define-constant ERR_ACCESS_ALREADY_GRANTED u305)
(define-constant ERR_ACCESS_EXPIRED u306)
(define-constant ERR_NOT_OWNER u307)
(define-constant ERR_INVALID_TIMESTAMP u308)
(define-constant ERR_AUTHORITY_NOT_SET u309)
(define-constant ERR_INVALID_MAX_DURATION u310)
(define-constant ERR_INVALID_MIN_DURATION u311)
(define-constant ERR_MAX_GRANTS_EXCEEDED u312)
(define-constant ERR_INVALID_ACCESS_TYPE u313)
(define-constant ERR_INVALID_PENALTY u314)
(define-constant ERR_INVALID_VOTING_THRESHOLD u315)
(define-constant ERR_GRANT_NOT_FOUND u316)
(define-constant ERR_INVALID_UPDATE_PARAM u317)
(define-constant ERR_UPDATE_NOT_ALLOWED u318)
(define-constant ERR_INVALID_LOCATION u319)
(define-constant ERR_INVALID_CURRENCY u320)

(define-data-var next-grant-id uint u0)
(define-data-var max-grants uint u10000)
(define-data-var grant-fee uint u100)
(define-data-var authority-contract (optional principal) none)
(define-data-var max-duration uint u525600)
(define-data-var min-duration uint u60)

(define-map access-grants
  { identity-commit: (buff 32), content-id: uint }
  {
    granted-at: uint,
    expires-at: uint,
    access-type: uint,
    penalty: uint,
    voting-threshold: uint,
    timestamp: uint,
    granter: principal,
    location: (string-utf8 100),
    currency: (string-utf8 20),
    status: bool
  }
)

(define-map grants-by-commit
  (buff 32)
  uint
)

(define-map grant-updates
  uint
  {
    update-duration: uint,
    update-access-type: uint,
    update-timestamp: uint,
    updater: principal
  }
)

(define-read-only (get-grant (commitment (buff 32)) (content-id uint))
  (map-get? access-grants { identity-commit: commitment, content-id: content-id })
)

(define-read-only (get-grant-updates (grant-id uint))
  (map-get? grant-updates grant-id)
)

(define-read-only (is-grant-registered (commitment (buff 32)))
  (is-some (map-get? grants-by-commit commitment))
)

(define-private (validate-commitment (commitment (buff 32)))
  (if (is-eq (len commitment) u32)
      (ok true)
      (err ERR_INVALID_COMMITMENT))
)

(define-private (validate-content-id (id uint))
  (if (> id u0)
      (ok true)
      (err ERR_INVALID_CONTENT_ID))
)

(define-private (validate-duration (duration uint))
  (if (and (>= duration (var-get min-duration)) (<= duration (var-get max-duration)))
      (ok true)
      (err ERR_INVALID_DURATION))
)

(define-private (validate-access-type (type uint))
  (if (or (is-eq type u0) (is-eq type u1) (is-eq type u2))
      (ok true)
      (err ERR_INVALID_ACCESS_TYPE))
)

(define-private (validate-penalty (penalty uint))
  (if (<= penalty u100)
      (ok true)
      (err ERR_INVALID_PENALTY))
)

(define-private (validate-voting-threshold (threshold uint))
  (if (and (> threshold u0) (<= threshold u100))
      (ok true)
      (err ERR_INVALID_VOTING_THRESHOLD))
)

(define-private (validate-timestamp (ts uint))
  (if (>= ts block-height)
      (ok true)
      (err ERR_INVALID_TIMESTAMP))
)

(define-private (validate-location (loc (string-utf8 100)))
  (if (and (> (len loc) u0) (<= (len loc) u100))
      (ok true)
      (err ERR_INVALID_LOCATION))
)

(define-private (validate-currency (cur (string-utf8 20)))
  (if (or (is-eq cur u"STX") (is-eq cur u"USD") (is-eq cur u"BTC"))
      (ok true)
      (err ERR_INVALID_CURRENCY))
)

(define-private (validate-principal (p principal))
  (if (not (is-eq p 'SP000000000000000000002Q6VF78))
      (ok true)
      (err ERR_NOT_OWNER))
)

(define-public (set-authority-contract (contract-principal principal))
  (begin
    (try! (validate-principal contract-principal))
    (asserts! (is-none (var-get authority-contract)) (err ERR_AUTHORITY_NOT_SET))
    (var-set authority-contract (some contract-principal))
    (ok true)
  )
)

(define-public (set-max-grants (new-max uint))
  (begin
    (asserts! (> new-max u0) (err ERR_MAX_GRANTS_EXCEEDED))
    (asserts! (is-some (var-get authority-contract)) (err ERR_AUTHORITY_NOT_SET))
    (var-set max-grants new-max)
    (ok true)
  )
)

(define-public (set-grant-fee (new-fee uint))
  (begin
    (asserts! (>= new-fee u0) (err ERR_INVALID_UPDATE_PARAM))
    (asserts! (is-some (var-get authority-contract)) (err ERR_AUTHORITY_NOT_SET))
    (var-set grant-fee new-fee)
    (ok true)
  )
)

(define-public (set-max-duration (new-max uint))
  (begin
    (asserts! (> new-max (var-get min-duration)) (err ERR_INVALID_MAX_DURATION))
    (asserts! (is-some (var-get authority-contract)) (err ERR_AUTHORITY_NOT_SET))
    (var-set max-duration new-max)
    (ok true)
  )
)

(define-public (set-min-duration (new-min uint))
  (begin
    (asserts! (< new-min (var-get max-duration)) (err ERR_INVALID_MIN_DURATION))
    (asserts! (is-some (var-get authority-contract)) (err ERR_AUTHORITY_NOT_SET))
    (var-set min-duration new-min)
    (ok true)
  )
)

(define-public (grant-access
  (commitment (buff 32))
  (content-id uint)
  (duration uint)
  (access-type uint)
  (penalty uint)
  (voting-threshold uint)
  (location (string-utf8 100))
  (currency (string-utf8 20))
)
  (let
    (
      (next-id (var-get next-grant-id))
      (current-max (var-get max-grants))
      (authority (var-get authority-contract))
      (identity (unwrap! (contract-call? .anon-identity get-identity commitment) (err ERR_INVALID_PROOF)))
      (expires (+ block-height duration))
    )
    (asserts! (< next-id current-max) (err ERR_MAX_GRANTS_EXCEEDED))
    (try! (validate-commitment commitment))
    (try! (validate-content-id content-id))
    (try! (validate-duration duration))
    (try! (validate-access-type access-type))
    (try! (validate-penalty penalty))
    (try! (validate-voting-threshold voting-threshold))
    (try! (validate-location location))
    (try! (validate-currency currency))
    (asserts! (is-eq (get owner identity) tx-sender) (err ERR_NOT_OWNER))
    (asserts! (is-none (map-get? access-grants { identity-commit: commitment, content-id: content-id })) (err ERR_ACCESS_ALREADY_GRANTED))
    (let ((authority-recipient (unwrap! authority (err ERR_AUTHORITY_NOT_SET))))
      (try! (stx-transfer? (var-get grant-fee) tx-sender authority-recipient))
    )
    (map-set access-grants { identity-commit: commitment, content-id: content-id }
      {
        granted-at: block-height,
        expires-at: expires,
        access-type: access-type,
        penalty: penalty,
        voting-threshold: voting-threshold,
        timestamp: block-height,
        granter: tx-sender,
        location: location,
        currency: currency,
        status: true
      }
    )
    (map-set grants-by-commit commitment next-id)
    (var-set next-grant-id (+ next-id u1))
    (print { event: "access-granted", id: next-id })
    (ok next-id)
  )
)

(define-public (update-grant
  (commitment (buff 32))
  (content-id uint)
  (update-duration uint)
  (update-access-type uint)
)
  (let ((grant (map-get? access-grants { identity-commit: commitment, content-id: content-id })))
    (match grant
      g
        (begin
          (asserts! (is-eq (get granter g) tx-sender) (err ERR_NOT_OWNER))
          (try! (validate-duration update-duration))
          (try! (validate-access-type update-access-type))
          (let ((new-expires (+ block-height update-duration)))
            (map-set access-grants { identity-commit: commitment, content-id: content-id }
              {
                granted-at: (get granted-at g),
                expires-at: new-expires,
                access-type: update-access-type,
                penalty: (get penalty g),
                voting-threshold: (get voting-threshold g),
                timestamp: block-height,
                granter: (get granter g),
                location: (get location g),
                currency: (get currency g),
                status: (get status g)
              }
            )
          )
          (let ((grant-id (unwrap! (map-get? grants-by-commit commitment) (err ERR_GRANT_NOT_FOUND))))
            (map-set grant-updates grant-id
              {
                update-duration: update-duration,
                update-access-type: update-access-type,
                update-timestamp: block-height,
                updater: tx-sender
              }
            )
          )
          (print { event: "grant-updated", commitment: commitment, content-id: content-id })
          (ok true)
        )
      (err ERR_GRANT_NOT_FOUND)
    )
  )
)

(define-public (revoke-grant (commitment (buff 32)) (content-id uint))
  (let ((grant (map-get? access-grants { identity-commit: commitment, content-id: content-id })))
    (match grant
      g
        (begin
          (asserts! (is-eq (get granter g) tx-sender) (err ERR_NOT_OWNER))
          (map-set access-grants { identity-commit: commitment, content-id: content-id }
            (merge g { status: false })
          )
          (print { event: "grant-revoked", commitment: commitment, content-id: content-id })
          (ok true)
        )
      (err ERR_GRANT_NOT_FOUND)
    )
  )
)

(define-read-only (has-access (commitment (buff 32)) (content-id uint))
  (let
    (
      (grant (map-get? access-grants { identity-commit: commitment, content-id: content-id }))
    )
    (match grant
      g
        (if (and (get status g) (> (get expires-at g) block-height))
            true
            false
        )
      false
    )
  )
)

(define-public (get-grant-count)
  (ok (var-get next-grant-id))
)

(define-public (check-grant-existence (commitment (buff 32)))
  (ok (is-grant-registered commitment))
)