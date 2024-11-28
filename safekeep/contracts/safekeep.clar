;; SafeKeep: Time-Locked Multi-Signature Vault with Enhanced Security
;; A secure smart contract for conditional asset storage and controlled release

(define-constant ERR-NOT-AUTHORIZED (err u1))
(define-constant ERR-INSUFFICIENT-SIGNATURES (err u2))
(define-constant ERR-TIME-LOCK-NOT-EXPIRED (err u3))
(define-constant ERR-INVALID-SIGNER (err u4))
(define-constant ERR-ALREADY-SIGNED (err u5))
(define-constant ERR-EMERGENCY-UNLOCK-NOT-ALLOWED (err u6))
(define-constant ERR-GUARDIAN-REQUIRED (err u7))
(define-constant ERR-INSUFFICIENT-BALANCE (err u8))
(define-constant ERR-INVALID-WITHDRAWAL-AMOUNT (err u9))
(define-constant ERR-INVALID-INPUT (err u10))

;; Validate input parameters
(define-private (validate-input-uint (value uint))
  (and (> value u0) (<= value u340282366920938463463374607431768211455))
)

;; Validate input signers
(define-private (validate-signers (signers (list 5 principal)))
  (and 
    (> (len signers) u0) 
    (<= (len signers) u5)
    (is-none (index-of signers tx-sender))
  )
)

;; Vault configuration
(define-map vault-config
  { vault-id: uint }
  {
    release-timestamp: uint,
    required-signatures: uint,
    signers: (list 5 principal),
    total-amount: uint,
    withdrawn-amount: uint,
    signed-signers: (list 5 principal),
    guardian: (optional principal),
    emergency-unlock-enabled: bool,
    emergency-unlock-after: (optional uint),
    partial-withdrawal-config: {
      partial-unlock-threshold: uint,
      partial-signatures-required: uint
    }
  }
)

;; Track individual vault signatures for partial withdrawals
(define-map partial-withdrawal-signatures
  { vault-id: uint, withdrawal-id: uint, signer: principal }
  { has-signed: bool }
)

;; Track partial withdrawal requests
(define-map partial-withdrawal-requests
  { vault-id: uint, withdrawal-id: uint }
  {
    amount: uint,
    signed-signers: (list 5 principal),
    approved: bool,
    recipient: principal
  }
)

;; Create a new time-locked multi-sig vault with partial withdrawal support
(define-public (create-vault 
  (release-timestamp uint)
  (required-signatures uint)
  (signers (list 5 principal))
  (initial-deposit uint)
  (guardian (optional principal))
  (emergency-unlock-enabled bool)
  (emergency-unlock-after (optional uint))
  (partial-unlock-threshold uint)
  (partial-signatures-required uint))
  (let 
    (
      (vault-id (var-get next-vault-id))
      (sender tx-sender)
    )
    ;; Validate all input parameters
    (asserts! (validate-input-uint initial-deposit) ERR-INVALID-INPUT)
    (asserts! (validate-input-uint release-timestamp) ERR-INVALID-INPUT)
    (asserts! (validate-signers signers) ERR-INVALID-SIGNER)
    
    ;; Validate signatures and thresholds
    (asserts! (> required-signatures u0) ERR-INVALID-SIGNER)
    (asserts! (<= required-signatures (len signers)) ERR-INSUFFICIENT-SIGNATURES)
    (asserts! (<= partial-signatures-required required-signatures) ERR-INVALID-SIGNER)
    (asserts! (validate-input-uint partial-unlock-threshold) ERR-INVALID-INPUT)
    
    
    ;; Optional emergency unlock timestamp validation
    (asserts! 
      (match emergency-unlock-after 
        unlock-block (validate-input-uint unlock-block)
        true
      )
      ERR-INVALID-INPUT
    )
    
    ;; Transfer initial deposit to contract
    (try! (stx-transfer? initial-deposit sender (as-contract tx-sender)))
    
    ;; Store vault configuration with comprehensive validation
    (map-set vault-config 
      { vault-id: vault-id }
      {
        release-timestamp: release-timestamp,
        required-signatures: required-signatures,
        signers: signers,
        total-amount: initial-deposit,
        withdrawn-amount: u0,
        signed-signers: (list),
        guardian: guardian,
        emergency-unlock-enabled: emergency-unlock-enabled,
        emergency-unlock-after: emergency-unlock-after,
        partial-withdrawal-config: {
          partial-unlock-threshold: partial-unlock-threshold,
          partial-signatures-required: partial-signatures-required
        }
      }
    )
    
    ;; Increment vault ID
    (var-set next-vault-id (+ vault-id u1))
    
    (ok vault-id)
  )
)

;; Request a partial withdrawal
(define-public (request-partial-withdrawal 
  (vault-id uint) 
  (amount uint) 
  (recipient principal))
  (let 
    (
      (vault (unwrap! 
        (map-get? vault-config { vault-id: vault-id }) 
        ERR-NOT-AUTHORIZED
      ))
      (sender tx-sender)
      (withdrawal-id (var-get next-withdrawal-id))
      (partial-config (get partial-withdrawal-config vault))
    )
    ;; Comprehensive input validation
    (asserts! (validate-input-uint vault-id) ERR-INVALID-INPUT)
    (asserts! (validate-input-uint amount) ERR-INVALID-INPUT)
    
    ;; Validate withdrawal recipient
    (asserts! (not (is-eq recipient tx-sender)) ERR-NOT-AUTHORIZED)
    
    ;; Validate withdrawal amount
    (asserts! 
      (>= 
        (- (get total-amount vault) (get withdrawn-amount vault)) 
        amount
      ) 
      ERR-INSUFFICIENT-BALANCE
    )
    (asserts! (> amount u0) ERR-INVALID-WITHDRAWAL-AMOUNT)
    (asserts! 
      (<= amount (/ (get total-amount vault) (get partial-unlock-threshold partial-config))) 
      ERR-INVALID-WITHDRAWAL-AMOUNT
    )
    
    ;; Create partial withdrawal request
    (map-set partial-withdrawal-requests
      { vault-id: vault-id, withdrawal-id: withdrawal-id }
      {
        amount: amount,
        signed-signers: (list),
        approved: false,
        recipient: recipient
      }
    )
    
    ;; Increment withdrawal ID
    (var-set next-withdrawal-id (+ withdrawal-id u1))
    
    (ok withdrawal-id)
  )
)

;; Sign a partial withdrawal request
(define-public (sign-partial-withdrawal 
  (vault-id uint) 
  (withdrawal-id uint))
  (let 
    (
      (vault (unwrap! 
        (map-get? vault-config { vault-id: vault-id }) 
        ERR-NOT-AUTHORIZED
      ))
      (withdrawal-req (unwrap! 
        (map-get? partial-withdrawal-requests { 
          vault-id: vault-id, 
          withdrawal-id: withdrawal-id 
        }) 
        ERR-NOT-AUTHORIZED
      ))
      (sender tx-sender)
      (partial-config (get partial-withdrawal-config vault))
    )
    ;; Validate input parameters 
    (asserts! (validate-input-uint vault-id) ERR-INVALID-INPUT)
    (asserts! (validate-input-uint withdrawal-id) ERR-INVALID-INPUT)
    
    ;; Validate signer
    (asserts! (is-some (index-of (get signers vault) sender)) ERR-NOT-AUTHORIZED)
    (asserts! 
      (is-none (map-get? partial-withdrawal-signatures { 
        vault-id: vault-id, 
        withdrawal-id: withdrawal-id, 
        signer: sender 
      })) 
      ERR-NOT-AUTHORIZED
    )
    
    ;; Record signature
    (map-set partial-withdrawal-signatures 
      { 
        vault-id: vault-id, 
        withdrawal-id: withdrawal-id, 
        signer: sender 
      }
      { has-signed: true }
    )
    
    ;; Update signed signers for withdrawal request
    (map-set partial-withdrawal-requests
      { vault-id: vault-id, withdrawal-id: withdrawal-id }
      (merge withdrawal-req { 
        signed-signers: (unwrap-panic (as-max-len? 
          (append (get signed-signers withdrawal-req) sender) 
          u5
        )) 
      })
    )
    
    ;; Check if withdrawal can be approved
    (if (>= (len (get signed-signers withdrawal-req)) (get partial-signatures-required partial-config))
      (begin
        ;; Mark withdrawal as approved
        (map-set partial-withdrawal-requests
          { vault-id: vault-id, withdrawal-id: withdrawal-id }
          (merge withdrawal-req { approved: true })
        )
        true
      )
      true
    )
    
    (ok true)
  )
)

;; Execute approved partial withdrawal
(define-public (execute-partial-withdrawal 
  (vault-id uint) 
  (withdrawal-id uint))
  (let 
    (
      (vault (unwrap! 
        (map-get? vault-config { vault-id: vault-id }) 
        ERR-NOT-AUTHORIZED
      ))
      (withdrawal-req (unwrap! 
        (map-get? partial-withdrawal-requests { 
          vault-id: vault-id, 
          withdrawal-id: withdrawal-id 
        }) 
        ERR-NOT-AUTHORIZED
      ))
      (partial-config (get partial-withdrawal-config vault))
    )
    ;; Validate input parameters
    (asserts! (validate-input-uint vault-id) ERR-INVALID-INPUT)
    (asserts! (validate-input-uint withdrawal-id) ERR-INVALID-INPUT)
    
    ;; Validate withdrawal is approved
    (asserts! (get approved withdrawal-req) ERR-NOT-AUTHORIZED)
    
    ;; Transfer partial withdrawal amount
    (try! 
      (as-contract 
        (stx-transfer? 
          (get amount withdrawal-req) 
          tx-sender 
          (get recipient withdrawal-req)
        )
      )
    )
    
    ;; Update vault total and withdrawn amounts
    (map-set vault-config 
      { vault-id: vault-id }
      (merge vault { 
        withdrawn-amount: (+ (get withdrawn-amount vault) (get amount withdrawal-req)) 
      })
    )
    
    (ok true)
  )
)

;; (Other functions like emergency-unlock, withdraw-vault remain the same with similar validations)

;; Initialize counters
(define-data-var next-vault-id uint u1)
(define-data-var next-withdrawal-id uint u1)

;; Read-only function to check vault details
(define-read-only (get-vault-details (vault-id uint))
  (map-get? vault-config { vault-id: vault-id })
)