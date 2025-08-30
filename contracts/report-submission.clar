;; report-submission.clar
;; EcoWatch Report Submission Contract
;; Handles submission, versioning, categorization, collaborators, status updates, licensing, and revenue sharing for environmental threat reports.

;; Constants
(define-constant ERR-INVALID-INPUT u1)
(define-constant ERR-REPORT-EXISTS u2)
(define-constant ERR-UNAUTHORIZED u3)
(define-constant ERR-INVALID-STATUS u4)
(define-constant ERR-MAX-VERSIONS-REACHED u5)
(define-constant ERR-INVALID-LICENSE u6)
(define-constant ERR-INVALID-SHARE u7)
(define-constant ERR-PAUSED u8)
(define-constant MAX-VERSIONS u10)
(define-constant MAX-TAGS u15)
(define-constant MAX-PERMISSIONS u10)
(define-constant MAX-METADATA-LEN u1024)
(define-constant MAX-DESCRIPTION-LEN u512)
(define-constant MAX-THREAT-TYPE-LEN u32)
(define-constant VERIFICATION-POOL-CONTRACT 'SP000000000000000000002Q6VF78.verification-pool) ;; Placeholder for verification contract

;; Data Variables
(define-data-var contract-paused bool false)
(define-data-var report-counter uint u0)
(define-data-var admin principal tx-sender)
(define-data-var version-counters (list 1000 uint) (list)) ;; Track version counts per report
(define-data-var status-update-counters (list 1000 uint) (list)) ;; Track status updates per report

;; Data Maps
(define-map reports
  { report-id: uint }
  {
    reporter: principal,
    geolocation: { lat: int, long: int },
    evidence-hash: (buff 32),
    threat-type: (string-ascii 32),
    description: (string-utf8 512),
    timestamp: uint,
    status: (string-ascii 20),
    metadata: (string-utf8 1024)
  }
)

(define-map report-versions
  { report-id: uint, version: uint }
  {
    updated-evidence-hash: (buff 32),
    update-notes: (string-utf8 256),
    timestamp: uint,
    updater: principal
  }
)

(define-map report-categories
  { report-id: uint }
  {
    category: (string-ascii 50),
    tags: (list 15 (string-ascii 20))
  }
)

(define-map report-collaborators
  { report-id: uint, collaborator: principal }
  {
    role: (string-ascii 50),
    permissions: (list 10 (string-ascii 20)),
    added-at: uint
  }
)

(define-map report-status-history
  { report-id: uint, update-id: uint }
  {
    status: (string-ascii 20),
    visibility: bool,
    timestamp: uint,
    updater: principal
  }
)

(define-map data-licenses
  { report-id: uint, licensee: principal }
  {
    expiry: uint,
    terms: (string-utf8 256),
    active: bool
  }
)

(define-map revenue-shares
  { report-id: uint, participant: principal }
  {
    percentage: uint,
    total-received: uint
  }
)

;; Public Functions

;; Submit a new environmental threat report
(define-public (submit-report 
  (lat int) 
  (long int) 
  (evidence-hash (buff 32)) 
  (threat-type (string-ascii 32)) 
  (description (string-utf8 512))
  (metadata (string-utf8 1024)))
  (let ((report-id (+ (var-get report-counter) u1)))
    (asserts! (not (var-get contract-paused)) (err ERR-PAUSED))
    (asserts! (and 
      (> (len threat-type) u0) (<= (len threat-type) MAX-THREAT-TYPE-LEN)
      (> (len description) u0) (<= (len description) MAX-DESCRIPTION-LEN)
      (<= (len metadata) MAX-METADATA-LEN)
      (is-eq (len evidence-hash) u32)) (err ERR-INVALID-INPUT))
    (asserts! (map-insert reports
      { report-id: report-id }
      {
        reporter: tx-sender,
        geolocation: { lat: lat, long: long },
        evidence-hash: evidence-hash,
        threat-type: threat-type,
        description: description,
        timestamp: block-height,
        status: "pending",
        metadata: metadata
      })
      (err ERR-REPORT-EXISTS))
    (var-set report-counter report-id)
    (var-set version-counters (append (var-get version-counters) u0))
    (var-set status-update-counters (append (var-get status-update-counters) u0))
    (map-set report-status-history 
      { report-id: report-id, update-id: u1 }
      { status: "pending", visibility: true, timestamp: block-height, updater: tx-sender })
    (print { event: "report-submitted", report-id: report-id, reporter: tx-sender })
    (ok report-id)
  )
)

;; Add a new version to an existing report
(define-public (add-report-version 
  (report-id uint) 
  (new-evidence-hash (buff 32)) 
  (notes (string-utf8 256)))
  (let ((report (unwrap! (map-get? reports { report-id: report-id }) (err ERR-INVALID-INPUT)))
        (version-count (unwrap! (element-at (var-get version-counters) (- report-id u1)) (err ERR-INVALID-INPUT))))
    (asserts! (> report-id u0) (err ERR-INVALID-INPUT))
    (asserts! (<= report-id (var-get report-counter)) (err ERR-INVALID-INPUT))
    (asserts! (or (is-eq tx-sender (get reporter report)) (has-permission report-id tx-sender "edit")) (err ERR-UNAUTHORIZED))
    (asserts! (< version-count MAX-VERSIONS) (err ERR-MAX-VERSIONS-REACHED))
    (asserts! (and (is-eq (len new-evidence-hash) u32) (<= (len notes) u256)) (err ERR-INVALID-INPUT))
    (map-set report-versions
      { report-id: report-id, version: (+ version-count u1) }
      {
        updated-evidence-hash: new-evidence-hash,
        update-notes: notes,
        timestamp: block-height,
        updater: tx-sender
      })
    (var-set version-counters (replace-at (var-get version-counters) (- report-id u1) (+ version-count u1)))
    (print { event: "report-version-added", report-id: report-id, version: (+ version-count u1) })
    (ok true)
  )
)

;; Add category and tags to a report
(define-public (add-report-category
  (report-id uint)
  (category (string-ascii 50))
  (tags (list 15 (string-ascii 20))))
  (let ((report (unwrap! (map-get? reports { report-id: report-id }) (err ERR-INVALID-INPUT))))
    (asserts! (> report-id u0) (err ERR-INVALID-INPUT))
    (asserts! (<= report-id (var-get report-counter)) (err ERR-INVALID-INPUT))
    (asserts! (is-eq tx-sender (get reporter report)) (err ERR-UNAUTHORIZED))
    (asserts! (and (<= (len category) u50) (<= (len tags) MAX-TAGS)) (err ERR-INVALID-INPUT))
    (map-set report-categories
      { report-id: report-id }
      { category: category, tags: tags })
    (ok true)
  )
)

;; Add collaborator to a report
(define-public (add-collaborator
  (report-id uint)
  (collaborator principal)
  (role (string-ascii 50))
  (permissions (list 10 (string-ascii 20))))
  (let ((report (unwrap! (map-get? reports { report-id: report-id }) (err ERR-INVALID-INPUT))))
    (asserts! (> report-id u0) (err ERR-INVALID-INPUT))
    (asserts! (<= report-id (var-get report-counter)) (err ERR-INVALID-INPUT))
    (asserts! (not (is-eq collaborator tx-sender)) (err ERR-INVALID-INPUT))
    (asserts! (is-eq tx-sender (get reporter report)) (err ERR-UNAUTHORIZED))
    (asserts! (and (<= (len role) u50) (<= (len permissions) MAX-PERMISSIONS)) (err ERR-INVALID-INPUT))
    (map-set report-collaborators
      { report-id: report-id, collaborator: collaborator }
      { role: role, permissions: permissions, added-at: block-height })
    (ok true)
  )
)

;; Update report status
(define-public (update-report-status
  (report-id uint)
  (new-status (string-ascii 20))
  (visibility bool))
  (let ((report (unwrap! (map-get? reports { report-id: report-id }) (err ERR-INVALID-INPUT)))
        (update-count (unwrap! (element-at (var-get status-update-counters) (- report-id u1)) (err ERR-INVALID-INPUT))))
    (asserts! (> report-id u0) (err ERR-INVALID-INPUT))
    (asserts! (<= report-id (var-get report-counter)) (err ERR-INVALID-INPUT))
    (asserts! (or 
      (is-eq tx-sender (get reporter report)) 
      (has-permission report-id tx-sender "verify") 
      (is-eq contract-caller VERIFICATION-POOL-CONTRACT)) (err ERR-UNAUTHORIZED))
    (asserts! (<= (len new-status) u20) (err ERR-INVALID-INPUT))
    (asserts! (is-ok (validate-status new-status)) (err ERR-INVALID-STATUS))
    (map-set reports { report-id: report-id } (merge report { status: new-status }))
    (map-set report-status-history 
      { report-id: report-id, update-id: (+ update-count u1) }
      { status: new-status, visibility: visibility, timestamp: block-height, updater: tx-sender })
    (var-set status-update-counters (replace-at (var-get status-update-cCounters) (- report-id u1) (+ update-count u1)))
    (print { event: "status-updated", report-id: report-id, new-status: new-status })
    (ok true)
  )
)

;; Helper to validate status
(define-private (validate-status (status (string-ascii 20)))
  (if (or (is-eq status "pending") (is-eq status "verified") (is-eq status "rejected") (is-eq status "archived")) 
    (ok true) 
    (err ERR-INVALID-STATUS)))

;; Helper to check permissions
(define-private (has-permission (report-id uint) (user principal) (permission (string-ascii 20)))
  (let ((collaborator-entry (map-get? report-collaborators { report-id: report-id, collaborator: user })))
    (match collaborator-entry
      entry (is-some (index-of (get permissions entry) permission))
      false)))

;; Grant data license for report usage
(define-public (grant-license 
  (report-id uint)
  (licensee principal)
  (expiry uint)
  (terms (string-utf8 256)))
  (let ((report (unwrap! (map-get? reports { report-id: report-id }) (err ERR-INVALID-INPUT))))
    (asserts! (> report-id u0) (err ERR-INVALID-INPUT))
    (asserts! (<= report-id (var-get report-counter)) (err ERR-INVALID-INPUT))
    (asserts! (not (is-eq licensee tx-sender)) (err ERR-INVALID-INPUT))
    (asserts! (is-eq tx-sender (get reporter report)) (err ERR-UNAUTHORIZED))
    (asserts! (and (> expiry block-height) (<= (len terms) u256)) (err ERR-INVALID-LICENSE))
    (map-set data-licenses
      { report-id: report-id, licensee: licensee }
      { expiry: expiry, terms: terms, active: true })
    (print { event: "license-granted", report-id: report-id, licensee: licensee })
    (ok true)
  )
)