;; title: TrustChain - Dynamic Identity Verification Network
;; version: 1.0.0
;; summary: Self-sovereign identity verification through cross-referencing multiple attestation sources
;; description: A decentralized identity system that allows users to mint identity NFTs with verifiable
;;              attributes while maintaining privacy through zero-knowledge proofs and selective disclosure.
;;              Features reputation staking, progressive trust building, and portable identity across dApps.

;; traits
(define-trait nft-trait
  (
    (get-last-token-id () (response uint uint))
    (get-token-uri (uint) (response (optional (string-ascii 256)) uint))
    (get-owner (uint) (response (optional principal) uint))
    (transfer (uint principal principal) (response bool uint))
  )
)

(define-trait attestation-provider-trait
  (
    (verify-attestation ((buff 32)) (response bool uint))
    (get-reputation () (response uint uint))
  )
)

;; token definitions
(define-non-fungible-token trust-identity uint)

;; constants
(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_NOT_AUTHORIZED (err u100))
(define-constant ERR_INVALID_TOKEN (err u101))
(define-constant ERR_TOKEN_EXISTS (err u102))
(define-constant ERR_INSUFFICIENT_STAKE (err u103))
(define-constant ERR_INVALID_PROOF (err u104))
(define-constant ERR_ATTESTATION_NOT_FOUND (err u105))
(define-constant ERR_PROVIDER_NOT_REGISTERED (err u106))
(define-constant ERR_INSUFFICIENT_REPUTATION (err u107))
(define-constant ERR_INVALID_DISCLOSURE (err u108))
(define-constant ERR_CONTRACT_PAUSED (err u109))
(define-constant ERR_RATE_LIMIT_EXCEEDED (err u110))
(define-constant ERR_OVERFLOW (err u111))
(define-constant ERR_INVALID_INPUT (err u112))
(define-constant ERR_ATTESTATION_REVOKED (err u113))
(define-constant ERR_BATCH_TOO_LARGE (err u114))

(define-constant MIN_STAKE_AMOUNT u1000000) ;; 1 STX minimum stake
(define-constant MIN_REPUTATION_THRESHOLD u100)
(define-constant MAX_ATTRIBUTES u10)
(define-constant RATE-LIMIT-BLOCKS u10)
(define-constant MAX-OPERATIONS-PER-BLOCK u5)
(define-constant MAX_BATCH_SIZE u20)
(define-constant REPUTATION_DECAY_RATE u5) ;; 5% decay per period
(define-constant DECAY_PERIOD_BLOCKS u4320) ;; ~30 days

;; data vars
(define-data-var token-id-nonce uint u0)
(define-data-var contract-uri (string-ascii 256) "https://trustchain.network/metadata/")
(define-data-var contract-paused bool false)

;; data maps
;; Identity token metadata
(define-map identity-metadata uint {
  owner: principal,
  created-at: uint,
  attribute-count: uint,
  trust-score: uint,
  is-active: bool
})

;; Verifiable attributes with zero-knowledge commitments
(define-map identity-attributes {token-id: uint, attribute-type: (string-ascii 64)} {
  commitment-hash: (buff 32),
  proof-hash: (buff 32),
  attestation-count: uint,
  verified-at: uint,
  is-public: bool
})

;; Attestation providers registry
(define-map attestation-providers principal {
  reputation: uint,
  stake-amount: uint,
  total-attestations: uint,
  successful-attestations: uint,
  is-active: bool,
  registered-at: uint
})

;; Individual attestations
(define-map attestations (buff 32) {
  provider: principal,
  token-id: uint,
  attribute-type: (string-ascii 64),
  confidence-score: uint,
  created-at: uint,
  is-verified: bool
})

;; Reputation staking records
(define-map reputation-stakes {provider: principal, token-id: uint} {
  stake-amount: uint,
  locked-until: uint,
  is-slashed: bool
})

;; Cross-dApp consent management
(define-map dapp-permissions {token-id: uint, dapp: principal} {
  allowed-attributes: (list 10 (string-ascii 64)),
  expires-at: uint,
  granted-at: uint,
  is-active: bool
})

;; Zero-knowledge proof registry
(define-map zk-proofs (buff 32) {
  token-id: uint,
  proof-type: (string-ascii 32),
  public-inputs: (buff 256),
  verified-at: uint,
  verifier: principal
})

(define-map last-operation-block principal uint)
(define-map operations-per-block {user: principal, block: uint} uint)
(define-map revoked-attestations (buff 32) {revoked-at: uint, reason: (string-ascii 128)})
(define-map reputation-decay-tracker principal {last-decay-block: uint, decayed-amount: uint})

;; Security helper functions
(define-private (check-not-paused)
  (if (var-get contract-paused)
    ERR_CONTRACT_PAUSED
    (ok true)
  )
)

(define-private (safe-add (a uint) (b uint))
  (let ((result (+ a b)))
    (asserts! (>= result a) ERR_OVERFLOW)
    (ok result)
  )
)

(define-private (safe-mul (a uint) (b uint))
  (let ((result (* a b)))
    (asserts! (or (is-eq b u0) (is-eq (/ result b) a)) ERR_OVERFLOW)
    (ok result)
  )
)

(define-private (check-rate-limit (user principal))
  (let (
    (current-block burn-block-height)
    (last-block (default-to u0 (map-get? last-operation-block user)))
    (ops-count (default-to u0 (map-get? operations-per-block {user: user, block: current-block})))
  )
    (asserts! 
      (or 
        (>= (- current-block last-block) RATE-LIMIT-BLOCKS)
        (< ops-count MAX-OPERATIONS-PER-BLOCK)
      )
      ERR_RATE_LIMIT_EXCEEDED
    )
    (map-set last-operation-block user current-block)
    (map-set operations-per-block {user: user, block: current-block} (+ ops-count u1))
    (ok true)
  )
)

;; public functions

;; Pause/unpause contract (owner only)
(define-public (pause-contract)
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
    (var-set contract-paused true)
    (ok true)
  )
)

(define-public (unpause-contract)
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
    (var-set contract-paused false)
    (ok true)
  )
)

;; Mint a new identity NFT
(define-public (mint-identity (recipient principal) (metadata-uri (string-ascii 256)))
  (let ((token-id (unwrap! (safe-add (var-get token-id-nonce) u1) ERR_OVERFLOW)))
    (try! (check-not-paused))
    (try! (check-rate-limit tx-sender))
    (asserts! (is-eq tx-sender recipient) ERR_NOT_AUTHORIZED)
    (asserts! (> (len metadata-uri) u0) ERR_INVALID_INPUT)
    (try! (nft-mint? trust-identity token-id recipient))
    (map-set identity-metadata token-id {
      owner: recipient,
      created-at: burn-block-height,
      attribute-count: u0,
      trust-score: u0,
      is-active: true
    })
    (var-set token-id-nonce token-id)
    (ok token-id)
  )
)

;; Add verifiable attribute to identity
(define-public (add-attribute 
  (token-id uint) 
  (attribute-type (string-ascii 64))
  (commitment-hash (buff 32))
  (proof-hash (buff 32))
  (is-public bool)
)
  (let ((identity (unwrap! (map-get? identity-metadata token-id) ERR_INVALID_TOKEN)))
    (try! (check-not-paused))
    (try! (check-rate-limit tx-sender))
    (asserts! (is-eq tx-sender (get owner identity)) ERR_NOT_AUTHORIZED)
    (asserts! (< (get attribute-count identity) MAX_ATTRIBUTES) ERR_NOT_AUTHORIZED)
    (asserts! (> (len attribute-type) u0) ERR_INVALID_INPUT)
    
    (map-set identity-attributes 
      {token-id: token-id, attribute-type: attribute-type}
      {
        commitment-hash: commitment-hash,
        proof-hash: proof-hash,
        attestation-count: u0,
        verified-at: burn-block-height,
        is-public: is-public
      }
    )
    
    (map-set identity-metadata token-id 
      (merge identity {attribute-count: (unwrap! (safe-add (get attribute-count identity) u1) ERR_OVERFLOW)})
    )
    
    (ok true)
  )
)

;; Register as attestation provider
(define-public (register-provider (stake-amount uint))
  (begin
    (asserts! (>= stake-amount MIN_STAKE_AMOUNT) ERR_INSUFFICIENT_STAKE)
    (try! (stx-transfer? stake-amount tx-sender (as-contract tx-sender)))
    
    (map-set attestation-providers tx-sender {
      reputation: u100, ;; Starting reputation
      stake-amount: stake-amount,
      total-attestations: u0,
      successful-attestations: u0,
      is-active: true,
      registered-at: u0  ;; TODO: Replace with actual timestamp when available
    })
    
    (ok true)
  )
)

;; Create attestation for an attribute
(define-public (create-attestation 
  (token-id uint)
  (attribute-type (string-ascii 64))
  (attestation-id (buff 32))
  (confidence-score uint)
)
  (let (
    (provider-data (unwrap! (map-get? attestation-providers tx-sender) ERR_PROVIDER_NOT_REGISTERED))
    (attribute-key {token-id: token-id, attribute-type: attribute-type})
    (attribute-data (unwrap! (map-get? identity-attributes attribute-key) ERR_ATTESTATION_NOT_FOUND))
  )
    (asserts! (get is-active provider-data) ERR_PROVIDER_NOT_REGISTERED)
    (asserts! (>= (get reputation provider-data) MIN_REPUTATION_THRESHOLD) ERR_INSUFFICIENT_REPUTATION)
    (asserts! (<= confidence-score u100) ERR_NOT_AUTHORIZED)
    
    ;; Create the attestation
    (map-set attestations attestation-id {
      provider: tx-sender,
      token-id: token-id,
      attribute-type: attribute-type,
      confidence-score: confidence-score,
      created-at: u0,  ;; TODO: Replace with actual timestamp when available
      is-verified: false
    })
    
    ;; Update attribute attestation count
    (map-set identity-attributes attribute-key
      (merge attribute-data {attestation-count: (+ (get attestation-count attribute-data) u1)})
    )
    
    ;; Update provider statistics
    (map-set attestation-providers tx-sender
      (merge provider-data {total-attestations: (+ (get total-attestations provider-data) u1)})
    )
    
    (ok attestation-id)
  )
)

;; Verify zero-knowledge proof for selective disclosure
(define-public (verify-zk-proof 
  (proof-id (buff 32))
  (token-id uint)
  (proof-type (string-ascii 32))
  (public-inputs (buff 256))
  (proof-data (buff 512))
)
  (let ((identity (unwrap! (map-get? identity-metadata token-id) ERR_INVALID_TOKEN)))
    ;; In a real implementation, this would verify the actual ZK proof
    ;; For now, we'll do basic validation and store the proof
    (asserts! (get is-active identity) ERR_INVALID_TOKEN)
    
    (map-set zk-proofs proof-id {
      token-id: token-id,
      proof-type: proof-type,
      public-inputs: public-inputs,
      verified-at: u0,  ;; TODO: Replace with actual timestamp when available
      verifier: tx-sender
    })
    
    (ok true)
  )
)

;; Grant dApp permissions for attribute access
(define-public (grant-dapp-permission 
  (token-id uint)
  (dapp principal)
  (allowed-attributes (list 10 (string-ascii 64)))
  (duration uint)
)
  (let ((identity (unwrap! (map-get? identity-metadata token-id) ERR_INVALID_TOKEN)))
    (asserts! (is-eq tx-sender (get owner identity)) ERR_NOT_AUTHORIZED)
    
    (map-set dapp-permissions 
      {token-id: token-id, dapp: dapp}
      {
        allowed-attributes: allowed-attributes,
        expires-at: duration,  ;; TODO: Replace with actual block height calculation when available
        granted-at: u0,  ;; TODO: Replace with actual timestamp when available
        is-active: true
      }
    )
    
    (ok true)
  )
)

;; Stake reputation on attestation
(define-public (stake-on-attestation (token-id uint) (stake-amount uint) (lock-duration uint))
  (let ((provider-data (unwrap! (map-get? attestation-providers tx-sender) ERR_PROVIDER_NOT_REGISTERED)))
    (asserts! (>= stake-amount MIN_STAKE_AMOUNT) ERR_INSUFFICIENT_STAKE)
    (try! (stx-transfer? stake-amount tx-sender (as-contract tx-sender)))
    
    (map-set reputation-stakes 
      {provider: tx-sender, token-id: token-id}
      {
        stake-amount: stake-amount,
        locked-until: lock-duration,  ;; TODO: Replace with actual block height calculation when available
        is-slashed: false
      }
    )
    
    (ok true)
  )
)

;; Transfer identity NFT
(define-public (transfer (token-id uint) (sender principal) (recipient principal))
  (begin
    (try! (check-not-paused))
    (asserts! (is-eq tx-sender sender) ERR_NOT_AUTHORIZED)
    (asserts! (is-some (nft-get-owner? trust-identity token-id)) ERR_INVALID_TOKEN)
    (try! (nft-transfer? trust-identity token-id sender recipient))
    
    ;; Update identity metadata
    (map-set identity-metadata token-id 
      (merge (unwrap-panic (map-get? identity-metadata token-id)) {owner: recipient})
    )
    
    (ok true)
  )
)

;; NEW FEATURE: Batch create multiple attestations
(define-public (batch-create-attestations 
  (attestation-list (list 20 {token-id: uint, attribute-type: (string-ascii 64), attestation-id: (buff 32), confidence-score: uint}))
)
  (let ((provider-data (unwrap! (map-get? attestation-providers tx-sender) ERR_PROVIDER_NOT_REGISTERED)))
    (try! (check-not-paused))
    (try! (check-rate-limit tx-sender))
    (asserts! (get is-active provider-data) ERR_PROVIDER_NOT_REGISTERED)
    (asserts! (>= (get reputation provider-data) MIN_REPUTATION_THRESHOLD) ERR_INSUFFICIENT_REPUTATION)
    (asserts! (<= (len attestation-list) MAX_BATCH_SIZE) ERR_BATCH_TOO_LARGE)
    
    (ok (fold batch-create-attestation-iter attestation-list u0))
  )
)

;; NEW FEATURE: Revoke an attestation
(define-public (revoke-attestation (attestation-id (buff 32)) (reason (string-ascii 128)))
  (let ((attestation (unwrap! (map-get? attestations attestation-id) ERR_ATTESTATION_NOT_FOUND)))
    (try! (check-not-paused))
    (asserts! (is-eq tx-sender (get provider attestation)) ERR_NOT_AUTHORIZED)
    (asserts! (> (len reason) u0) ERR_INVALID_INPUT)
    
    (map-set revoked-attestations attestation-id {
      revoked-at: burn-block-height,
      reason: reason
    })
    
    (ok true)
  )
)

;; NEW FEATURE: Apply reputation decay
(define-public (apply-reputation-decay (provider principal))
  (let (
    (provider-data (unwrap! (map-get? attestation-providers provider) ERR_PROVIDER_NOT_REGISTERED))
    (decay-tracker (default-to {last-decay-block: u0, decayed-amount: u0} (map-get? reputation-decay-tracker provider)))
    (blocks-since-decay (- burn-block-height (get last-decay-block decay-tracker)))
  )
    (asserts! (>= blocks-since-decay DECAY_PERIOD_BLOCKS) ERR_NOT_AUTHORIZED)
    
    (let (
      (current-reputation (get reputation provider-data))
      (decay-amount (/ (unwrap! (safe-mul current-reputation REPUTATION_DECAY_RATE) ERR_OVERFLOW) u100))
      (new-reputation (if (>= current-reputation decay-amount) (- current-reputation decay-amount) u0))
    )
      (map-set attestation-providers provider (merge provider-data {reputation: new-reputation}))
      (map-set reputation-decay-tracker provider {
        last-decay-block: burn-block-height,
        decayed-amount: (unwrap! (safe-add (get decayed-amount decay-tracker) decay-amount) ERR_OVERFLOW)
      })
      (ok new-reputation)
    )
  )
)

;; read only functions

;; Get identity metadata
(define-read-only (get-identity (token-id uint))
  (map-get? identity-metadata token-id)
)

;; Get attribute data
(define-read-only (get-attribute (token-id uint) (attribute-type (string-ascii 64)))
  (map-get? identity-attributes {token-id: token-id, attribute-type: attribute-type})
)

;; Get provider reputation
(define-read-only (get-provider-reputation (provider principal))
  (map-get? attestation-providers provider)
)

;; Get attestation details
(define-read-only (get-attestation (attestation-id (buff 32)))
  (map-get? attestations attestation-id)
)

;; Check dApp permissions
(define-read-only (get-dapp-permission (token-id uint) (dapp principal))
  (let ((permission (map-get? dapp-permissions {token-id: token-id, dapp: dapp})))
    (match permission
      some-perm (if (get is-active some-perm)
                   (some some-perm)
                   none)
      none
    )
  )
)

;; Get ZK proof
(define-read-only (get-zk-proof (proof-id (buff 32)))
  (map-get? zk-proofs proof-id)
)

;; Get token owner
(define-read-only (get-owner (token-id uint))
  (ok (nft-get-owner? trust-identity token-id))
)

;; Get token URI
(define-read-only (get-token-uri (token-id uint))
  (ok (some (concat (var-get contract-uri) (int-to-ascii token-id))))
)

;; Get last token ID
(define-read-only (get-last-token-id)
  (ok (var-get token-id-nonce))
)

;; Calculate trust score based on attestations
(define-read-only (calculate-trust-score (token-id uint))
  (let ((identity (map-get? identity-metadata token-id)))
    (match identity
      some-identity (ok (* (get attribute-count some-identity) u10)) ;; Simple scoring
      (ok u0)
    )
  )
)

;; Verify selective disclosure without revealing data
(define-read-only (verify-selective-disclosure 
  (token-id uint)
  (attribute-type (string-ascii 64))
  (proof-hash (buff 32))
)
  (let ((attribute (map-get? identity-attributes {token-id: token-id, attribute-type: attribute-type})))
    (match attribute
      some-attr (ok (is-eq (get proof-hash some-attr) proof-hash))
      (ok false)
    )
  )
)

;; NEW: Security read-only functions
(define-read-only (is-contract-paused)
  (var-get contract-paused)
)

(define-read-only (get-last-operation-block (user principal))
  (default-to u0 (map-get? last-operation-block user))
)

(define-read-only (is-attestation-revoked (attestation-id (buff 32)))
  (is-some (map-get? revoked-attestations attestation-id))
)

(define-read-only (get-revocation-details (attestation-id (buff 32)))
  (map-get? revoked-attestations attestation-id)
)

(define-read-only (get-reputation-decay-info (provider principal))
  (map-get? reputation-decay-tracker provider)
)

;; private functions

;; Helper function to validate proof format
(define-private (is-valid-proof (proof-data (buff 512)))
  (> (len proof-data) u0)
)

;; Helper function to calculate reputation adjustment
(define-private (calculate-reputation-adjustment (success bool) (confidence uint))
  (if success
    (/ confidence u10)
    (- u0 (/ confidence u5))
  )
)

;; Helper function to check attribute ownership
(define-private (check-attribute-ownership (token-id uint) (caller principal))
  (let ((identity (map-get? identity-metadata token-id)))
    (match identity
      some-id (is-eq caller (get owner some-id))
      false
    )
  )
)

;; Helper for batch attestation creation
(define-private (batch-create-attestation-iter 
  (attestation {token-id: uint, attribute-type: (string-ascii 64), attestation-id: (buff 32), confidence-score: uint})
  (count uint)
)
  (let (
    (attribute-key {token-id: (get token-id attestation), attribute-type: (get attribute-type attestation)})
    (attribute-data (map-get? identity-attributes attribute-key))
  )
    (match attribute-data
      some-attr (begin
        (map-set attestations (get attestation-id attestation) {
          provider: tx-sender,
          token-id: (get token-id attestation),
          attribute-type: (get attribute-type attestation),
          confidence-score: (get confidence-score attestation),
          created-at: burn-block-height,
          is-verified: false
        })
        (map-set identity-attributes attribute-key
          (merge some-attr {attestation-count: (+ (get attestation-count some-attr) u1)})
        )
        (+ count u1)
      )
      count
    )
  )
)