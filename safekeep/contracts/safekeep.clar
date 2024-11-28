;; SafeKeep: Time-Locked Multi-Signature Vault with Emergency Unlock
;; A secure smart contract for conditional asset storage and controlled release

(define-constant ERR-NOT-AUTHORIZED (err u1))
(define-constant ERR-INSUFFICIENT-SIGNATURES (err u2))
(define-constant ERR-TIME-LOCK-NOT-EXPIRED (err u3))
(define-constant ERR-INVALID-SIGNER (err u4))
(define-constant ERR-ALREADY-SIGNED (err u5))
(define-constant ERR-EMERGENCY-UNLOCK-NOT-ALLOWED (err u6))
(define-constant ERR-GUARDIAN-REQUIRED (err u7))

;; Vault configuration
(define-map vault-config
  { vault-id: uint }
  {
    release-timestamp: uint,
    required-signatures: uint,
    signers: (list 5 principal),
    total-amount: uint,
    signed-signers: (list 5 principal),
    guardian: (optional principal),
    emergency-unlock-enabled: bool,
    emergency-unlock-after: (optional uint)
  }
)

;; Track individual vault signatures
(define-map vault-signatures
  { vault-id: uint, signer: principal }
  { has-signed: bool }
)

;; Create a new time-locked multi-sig vault with optional emergency unlock
(define-public (create-vault 
  (release-timestamp uint)
  (required-signatures uint)
  (signers (list 5 principal))
  (initial-deposit uint)
  (guardian (optional principal))
  (emergency-unlock-enabled bool)
  (emergency-unlock-after (optional uint)))
  (let 
    (
      (vault-id (var-get next-vault-id))
      (sender tx-sender)
    )
    ;; Validate input parameters
    (asserts! (> required-signatures u0) ERR-INVALID-SIGNER)
    (asserts! (<= required-signatures (len signers)) ERR-INSUFFICIENT-SIGNATURES)
    
    ;; If emergency unlock is enabled, guardian is required
    (asserts! 
      (if emergency-unlock-enabled 
        (is-some guardian) 
        true
      ) 
      ERR-GUARDIAN-REQUIRED
    )
    
    ;; Transfer initial deposit to contract
    (try! (stx-transfer? initial-deposit sender (as-contract tx-sender)))
    
    ;; Store vault configuration
    (map-set vault-config 
      { vault-id: vault-id }
      {
        release-timestamp: release-timestamp,
        required-signatures: required-signatures,
        signers: signers,
        total-amount: initial-deposit,
        signed-signers: (list),
        guardian: guardian,
        emergency-unlock-enabled: emergency-unlock-enabled,
        emergency-unlock-after: emergency-unlock-after
      }
    )
    
    ;; Increment vault ID
    (var-set next-vault-id (+ vault-id u1))
    
    (ok vault-id)
  )
)

;; Sign the vault for release
(define-public (sign-vault (vault-id uint))
  (let 
    (
      (vault (unwrap! (map-get? vault-config { vault-id: vault-id }) ERR-NOT-AUTHORIZED))
      (sender tx-sender)
    )
    ;; Validate signer
    (asserts! (is-some (index-of (get signers vault) sender)) ERR-NOT-AUTHORIZED)
    (asserts! (is-none (map-get? vault-signatures { vault-id: vault-id, signer: sender })) ERR-ALREADY-SIGNED)
    
    ;; Record signature
    (map-set vault-signatures 
      { vault-id: vault-id, signer: sender }
      { has-signed: true }
    )
    
    ;; Update signed signers list
    (map-set vault-config 
      { vault-id: vault-id }
      (merge vault { 
        signed-signers: (unwrap-panic (as-max-len? (append (get signed-signers vault) sender) u5)) 
      })
    )
    
    (ok true)
  )
)

;; Emergency unlock by guardian
(define-public (emergency-unlock (vault-id uint))
  (let 
    (
      (vault (unwrap! (map-get? vault-config { vault-id: vault-id }) ERR-NOT-AUTHORIZED))
      (sender tx-sender)
    )
    ;; Check emergency unlock is enabled
    (asserts! (get emergency-unlock-enabled vault) ERR-EMERGENCY-UNLOCK-NOT-ALLOWED)
    
    ;; Verify sender is the guardian
    (asserts! 
      (is-eq sender (unwrap! (get guardian vault) ERR-NOT-AUTHORIZED)) 
      ERR-NOT-AUTHORIZED
    )
    
    ;; Check emergency unlock conditions
    (asserts! 
      (match (get emergency-unlock-after vault)
        unlock-block (>= block-height unlock-block)
        true
      )
      ERR-EMERGENCY-UNLOCK-NOT-ALLOWED
    )
    
    ;; Transfer funds to guardian
    (as-contract 
      (stx-transfer? (get total-amount vault) tx-sender sender)
    )
  )
)

;; Withdraw funds from the vault
(define-public (withdraw-vault (vault-id uint))
  (let 
    (
      (vault (unwrap! (map-get? vault-config { vault-id: vault-id }) ERR-NOT-AUTHORIZED))
      (sender tx-sender)
    )
    ;; Check time lock has expired
    (asserts! (>= block-height (get release-timestamp vault)) ERR-TIME-LOCK-NOT-EXPIRED)
    
    ;; Check signature threshold met
    (asserts! 
      (>= (len (get signed-signers vault)) (get required-signatures vault)) 
      ERR-INSUFFICIENT-SIGNATURES
    )
    
    ;; Transfer funds back to sender
    (as-contract 
      (stx-transfer? (get total-amount vault) tx-sender sender)
    )
  )
)

;; Allow depositing additional funds to an existing vault
(define-public (deposit-to-vault (vault-id uint) (amount uint))
  (let 
    (
      (vault (unwrap! (map-get? vault-config { vault-id: vault-id }) ERR-NOT-AUTHORIZED))
      (sender tx-sender)
    )
    ;; Transfer additional funds
    (try! (stx-transfer? amount sender (as-contract tx-sender)))
    
    ;; Update total amount
    (map-set vault-config 
      { vault-id: vault-id }
      (merge vault { total-amount: (+ (get total-amount vault) amount) })
    )
    
    (ok true)
  )
)

;; Initialize the next vault ID
(define-data-var next-vault-id uint u1)

;; Read-only function to check vault details
(define-read-only (get-vault-details (vault-id uint))
  (map-get? vault-config { vault-id: vault-id })
)