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
    (verify-attestation (buff 32 buff 256) (response bool uint))
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

(define-constant MIN_STAKE_AMOUNT u1000000) ;; 1 STX minimum stake
(define-constant MIN_REPUTATION_THRESHOLD u100)
(define-constant MAX_ATTRIBUTES u10)

;; data vars
(define-data-var token-id-nonce uint u0)
(define-data-var contract-uri (string-ascii 256) "https://trustchain.network/metadata/")

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

;; public functions

;; Mint a new identity NFT
(define-public (mint-identity (recipient principal) (metadata-uri (string-ascii 256)))
  (let ((token-id (+ (var-get token-id-nonce) u1)))
    (asserts! (is-eq tx-sender recipient) ERR_NOT_AUTHORIZED)
    (try! (nft-mint? trust-identity token-id recipient))
    (map-set identity-metadata token-id {
      owner: recipient,
      created-at: block-height,
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
    (asserts! (is-eq tx-sender (get owner identity)) ERR_NOT_AUTHORIZED)
    (asserts! (< (get attribute-count identity) MAX_ATTRIBUTES) ERR_NOT_AUTHORIZED)
    
    (map-set identity-attributes 
      {token-id: token-id, attribute-type: attribute-type}
      {
        commitment-hash: commitment-hash,
        proof-hash: proof-hash,
        attestation-count: u0,
        verified-at: block-height,
        is-public: is-public
      }
    )
    
    (map-set identity-metadata token-id 
      (merge identity {attribute-count: (+ (get attribute-count identity) u1)})
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
      registered-at: block-height
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
      created-at: block-height,
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
      verified-at: block-height,
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
        expires-at: (+ block-height duration),
        granted-at: block-height,
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
        locked-until: (+ block-height lock-duration),
        is-slashed: false
      }
    )
    
    (ok true)
  )
)

;; Transfer identity NFT
(define-public (transfer (token-id uint) (sender principal) (recipient principal))
  (begin
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
