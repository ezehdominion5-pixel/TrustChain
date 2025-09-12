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