package model

import "encoding/json"

type Policy struct {
	Version                   int      `json:"version"`
	UpdatedAt                 string   `json:"updated_at"`
	AllowedSigAlgos           []string `json:"allowed_sig_algos"`
	AllowedKeyTypes           []string `json:"allowed_key_types"`
	MaxValidityDays           int      `json:"max_validity_days"`
	MinValidityHours          int      `json:"min_validity_hours"`
	RequireLeafSAN            bool     `json:"require_leaf_san"`
	AllowWildcardDNS          bool     `json:"allow_wildcard_dns"`
	RequireAKI                bool     `json:"require_aki"`
	AllowedCriticalExtensions []string `json:"allowed_critical_extensions,omitempty"`
}

type DN struct {
	CommonName         string `json:"common_name"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty"`
	Country            string `json:"country,omitempty"`
	Locality           string `json:"locality,omitempty"`
	Province           string `json:"province,omitempty"`
}

type KeySpec struct {
	Type  string `json:"type"`
	Bits  int    `json:"bits,omitempty"`
	Curve string `json:"curve,omitempty"`
}

type NameConstraints struct {
	PermittedDNS   []string `json:"permitted_dns,omitempty"`
	ExcludedDNS    []string `json:"excluded_dns,omitempty"`
	PermittedIPNet []string `json:"permitted_ip_net,omitempty"`
	ExcludedIPNet  []string `json:"excluded_ip_net,omitempty"`
	PermittedEmail []string `json:"permitted_email,omitempty"`
	ExcludedEmail  []string `json:"excluded_email,omitempty"`
	PermittedURI   []string `json:"permitted_uri,omitempty"`
	ExcludedURI    []string `json:"excluded_uri,omitempty"`
}

type CustomExtension struct {
	OID      string `json:"oid"`
	Critical bool   `json:"critical"`
	Hex      string `json:"hex"`
}

type SubjectRequest struct {
	Purpose            string            `json:"purpose"`
	Name               string            `json:"name,omitempty"`
	TemplateID         string            `json:"template_id,omitempty"`
	IssuerID           string            `json:"issuer_id,omitempty"`
	Subject            DN                `json:"subject"`
	Key                KeySpec           `json:"key"`
	SignatureAlgorithm string            `json:"signature_algorithm,omitempty"`
	IssuerIDs          []string          `json:"issuer_ids,omitempty"`
	NotBefore          string            `json:"not_before"`
	NotAfter           string            `json:"not_after"`
	DNSNames           []string          `json:"dns_names,omitempty"`
	IPAddresses        []string          `json:"ip_addresses,omitempty"`
	EmailAddresses     []string          `json:"email_addresses,omitempty"`
	URIs               []string          `json:"uris,omitempty"`
	EKUs               []string          `json:"ekus,omitempty"`
	KeyUsage           []string          `json:"key_usage,omitempty"`
	MaxPathLen         int               `json:"max_path_len,omitempty"`
	NameConstraints    NameConstraints   `json:"name_constraints,omitempty"`
	CustomExtensions   []CustomExtension `json:"custom_extensions,omitempty"`
}

type CheckStep struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

type ExtensionDiff struct {
	OID            string `json:"oid"`
	Name           string `json:"name"`
	Change         string `json:"change"`
	CriticalBefore bool   `json:"critical_before"`
	CriticalAfter  bool   `json:"critical_after"`
	BeforeHex      string `json:"before_hex,omitempty"`
	AfterHex       string `json:"after_hex,omitempty"`
}

type Certificate struct {
	ID                 string `json:"id"`
	Kind               string `json:"kind"`
	Name               string `json:"name"`
	RequestID          string `json:"request_id,omitempty"`
	TemplateID         string `json:"template_id,omitempty"`
	ParentID           string `json:"parent_id,omitempty"`
	KeyRef             string `json:"key_ref"`
	Serial             string `json:"serial"`
	DER                []byte `json:"der"`
	NotBefore          string `json:"not_before"`
	NotAfter           string `json:"not_after"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	Fingerprint        string `json:"fingerprint"`
	SubjectKeyID       string `json:"subject_key_id"`
	AuthorityKeyID     string `json:"authority_key_id,omitempty"`
	Status             string `json:"status"`
	PolicyVersion      int    `json:"policy_version"`
	CreatedAt          string `json:"created_at"`
	RevokedAt          string `json:"revoked_at,omitempty"`
	RevocationReason   string `json:"revocation_reason,omitempty"`
}

type IntermediateTemplate struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Subject         DN              `json:"subject"`
	KeyRef          string          `json:"key_ref"`
	PublicKeyDER    []byte          `json:"public_key_der"`
	MaxPathLen      int             `json:"max_path_len"`
	NameConstraints NameConstraints `json:"name_constraints"`
	CreatedAt       string          `json:"created_at"`
}

type Request struct {
	ID                   string                     `json:"id"`
	IdempotencyKey       string                     `json:"idempotency_key,omitempty"`
	PayloadHash          string                     `json:"payload_hash"`
	Input                SubjectRequest             `json:"input"`
	Status               string                     `json:"status"`
	CandidateCertIDs     []string                   `json:"candidate_cert_ids"`
	CertID               string                     `json:"cert_id,omitempty"`
	PolicyVersion        int                        `json:"policy_version"`
	Checks               []CheckStep                `json:"checks"`
	ExtensionDiffs       []ExtensionDiff            `json:"extension_diffs"`
	ExtensionDiffsByCert map[string][]ExtensionDiff `json:"extension_diffs_by_cert,omitempty"`
	CreatedAt            string                     `json:"created_at"`
	DecidedAt            string                     `json:"decided_at,omitempty"`
	RejectionReason      string                     `json:"rejection_reason,omitempty"`
}

type Intent struct {
	ID             string          `json:"id"`
	Operation      string          `json:"operation"`
	RequestID      string          `json:"request_id,omitempty"`
	CertID         string          `json:"cert_id,omitempty"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
	PayloadHash    string          `json:"payload_hash,omitempty"`
	Input          json.RawMessage `json:"input,omitempty"`
	ExpectedHash   string          `json:"expected_hash,omitempty"`
	CreatedAt      string          `json:"created_at"`
}

type State struct {
	EventSeq     int64                           `json:"event_seq"`
	NextSerial   int64                           `json:"next_serial"`
	Policy       Policy                          `json:"policy"`
	Certificates map[string]Certificate          `json:"certificates"`
	Requests     map[string]Request              `json:"requests"`
	Templates    map[string]IntermediateTemplate `json:"templates"`
	Serials      map[string]bool                 `json:"serials"`
	Intents      map[string]Intent               `json:"intents"`
	Recovery     []string                        `json:"recovery"`
}

type Event struct {
	Seq      int64           `json:"seq"`
	ID       string          `json:"id"`
	Type     string          `json:"type"`
	At       string          `json:"at"`
	PrevHash string          `json:"prev_hash"`
	Hash     string          `json:"hash"`
	Payload  json.RawMessage `json:"payload"`
}

type ValidationResult struct {
	OK          bool         `json:"ok"`
	Request     Request      `json:"request"`
	Certificate *Certificate `json:"certificate,omitempty"`
}

type ChainLink struct {
	CertID      string `json:"cert_id"`
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	Serial      string `json:"serial"`
	Fingerprint string `json:"fingerprint"`
	Status      string `json:"status"`
}

type ChainResult struct {
	ID        string      `json:"id"`
	Qualified bool        `json:"qualified"`
	Default   bool        `json:"default"`
	Reason    string      `json:"reason,omitempty"`
	Links     []ChainLink `json:"links"`
	OrderKey  string      `json:"order_key"`
}

type VerificationReport struct {
	CertID       string        `json:"cert_id"`
	VerifyAt     string        `json:"verify_at"`
	BoundaryRule string        `json:"boundary_rule"`
	Chains       []ChainResult `json:"chains"`
	DefaultChain *ChainResult  `json:"default_chain,omitempty"`
}

func DefaultPolicy() Policy {
	return Policy{
		Version:                   1,
		UpdatedAt:                 "1970-01-01T00:00:00Z",
		AllowedSigAlgos:           []string{"SHA256-RSA", "SHA256-ECDSA", "SHA384-ECDSA", "Ed25519"},
		AllowedKeyTypes:           []string{"RSA-2048", "RSA-3072", "EC-P256", "EC-P384", "Ed25519"},
		MaxValidityDays:           3650,
		MinValidityHours:          1,
		RequireLeafSAN:            true,
		AllowWildcardDNS:          true,
		RequireAKI:                true,
		AllowedCriticalExtensions: nil,
	}
}
