package fastdns

//go:generate go run gen/sort.go ./

type ARecord struct {
	Name   string `json:"name,omitempty"`
	TTL    int    `json:"ttl,omitempty"`
	Active bool   `json:"active,omitempty"`
	Target string `json:"target,omitempty"`
}

type AAAARecord struct {
	Name   string `json:"name,omitempty"`
	TTL    int    `json:"ttl,omitempty"`
	Active bool   `json:"active,omitempty"`
	Target string `json:"target,omitempty"`
}

type AFSDBRecord struct {
	Name    string `json:"name,omitempty"`
	TTL     int    `json:"ttl,omitempty"`
	Active  bool   `json:"active,omitempty"`
	Target  string `json:"target,omitempty"`
	Subtype int    `json:"subtype,omitempty"`
}

type CNAMERecord struct {
	Name   string `json:"name,omitempty"`
	TTL    int    `json:"ttl,omitempty"`
	Active bool   `json:"active,omitempty"`
	Target string `json:"target,omitempty"`
}

type DNSKEYRecord struct {
	Name      string `json:"name,omitempty"`
	TTL       int    `json:"ttl,omitempty"`
	Active    bool   `json:"active,omitempty"`
	Flags     int    `json:"flags,omitempty"`
	Protocol  int    `json:"protocol,omitempty"`
	Algorithm int    `json:"algorithm,omitempty"`
	Key       string `json:"key,omitempty"`
}

type DSRecord struct {
	Name       string `json:"name,omitempty"`
	TTL        int    `json:"ttl,omitempty"`
	Active     bool   `json:"active,omitempty"`
	Keytag     int    `json:"keytag,omitempty"`
	Algorithm  int    `json:"algorithm,omitempty"`
	DigestType int    `json:"digest_type,omitempty"`
	Digest     string `json:"digest,omitempty"`
}

type HINFORecord struct {
	Name     string `json:"name,omitempty"`
	TTL      int    `json:"ttl,omitempty"`
	Active   bool   `json:"active,omitempty"`
	Hardware string `json:"hardware,omitempty"`
	Software string `json:"software,omitempty"`
}

type LOCRecord struct {
	Name   string `json:"name,omitempty"`
	TTL    int    `json:"ttl,omitempty"`
	Active bool   `json:"active,omitempty"`
	Target string `json:"target,omitempty"`
}

type MXRecord struct {
	Name     string `json:"name,omitempty"`
	TTL      int    `json:"ttl,omitempty"`
	Active   bool   `json:"active,omitempty"`
	Target   string `json:"target,omitempty"`
	Priority int    `json:"priority,omitempty"`
}

type NAPTRRecord struct {
	Name        string `json:"name,omitempty"`
	TTL         int    `json:"ttl,omitempty"`
	Active      bool   `json:"active,omitempty"`
	Order       int    `json:"order,omitempty"`
	Preference  int    `json:"preference,omitempty"`
	Flags       string `json:"flags,omitempty"`
	Service     string `json:"service,omitempty"`
	Regexp      string `json:"regexp,omitempty"`
	Replacement string `json:"replacement,omitempty"`
}

type NSRecord struct {
	Name   string `json:"name,omitempty"`
	TTL    int    `json:"ttl,omitempty"`
	Active bool   `json:"active,omitempty"`
	Target string `json:"target,omitempty"`
}

type NSEC3Record struct {
	Name                string `json:"name,omitempty"`
	TTL                 int    `json:"ttl,omitempty"`
	Active              bool   `json:"active,omitempty"`
	Algorithm           int    `json:"algorithm,omitempty"`
	Flags               int    `json:"flags,omitempty"`
	Iterations          int    `json:"iterations,omitempty"`
	Salt                string `json:"salt,omitempty"`
	NextHashedOwnerName string `json:"next_hashed_owner_name,omitempty"`
	TypeBitmaps         string `json:"type_bitmaps,omitempty"`
}

type NSEC3PARAMRecord struct {
	Name       string `json:"name,omitempty"`
	TTL        int    `json:"ttl,omitempty"`
	Active     bool   `json:"active,omitempty"`
	Algorithm  int    `json:"algorithm,omitempty"`
	Flags      int    `json:"flags,omitempty"`
	Iterations int    `json:"iterations,omitempty"`
	Salt       string `json:"salt,omitempty"`
}

type PTRRecord struct {
	Name   string `json:"name,omitempty"`
	TTL    int    `json:"ttl,omitempty"`
	Active bool   `json:"active,omitempty"`
	Target string `json:"target,omitempty"`
}

type RPRecord struct {
	Name    string `json:"name,omitempty"`
	TTL     int    `json:"ttl,omitempty"`
	Active  bool   `json:"active,omitempty"`
	Mailbox string `json:"mailbox,omitempty"`
	Txt     string `json:"txt,omitempty"`
}

type RRRecord struct {
	Name    string `json:"name,omitempty"`
	TTL     int    `json:"ttl,omitempty"`
	Active  bool   `json:"active,omitempty"`
	Mailbox string `json:"mailbox,omitempty"`
	Txt     string `json:"txt,omitempty"`
}

type RRSIGRecord struct {
	Name        string `json:"name,omitempty"`
	TTL         int    `json:"ttl,omitempty"`
	Active      bool   `json:"active,omitempty"`
	TypeCovered string `json:"type_covered,omitempty"`
	Algorithm   int    `json:"algorithm,omitempty"`
	OriginalTTL int    `json:"original_ttl,omitempty"`
	Expiration  string `json:"expiration,omitempty"`
	Inception   string `json:"inception,omitempty"`
	Keytag      int    `json:"keytag,omitempty"`
	Signer      string `json:"signer,omitempty"`
	Signature   string `json:"signature,omitempty"`
	Labels      int    `json:"labels,omitempty"`
}

type SPFRecord struct {
	Name   string `json:"name,omitempty"`
	TTL    int    `json:"ttl,omitempty"`
	Active bool   `json:"active,omitempty"`
	Target string `json:"target,omitempty"`
}

type SRVRecord struct {
	Name     string `json:"name,omitempty"`
	TTL      int    `json:"ttl,omitempty"`
	Active   bool   `json:"active,omitempty"`
	Target   string `json:"target,omitempty"`
	Priority int    `json:"priority,omitempty"`
	Weight   uint   `json:"weight,omitempty"`
	Port     int    `json:"port,omitempty"`
}

type SSHFPRecord struct {
	Name            string `json:"name,omitempty"`
	TTL             int    `json:"ttl,omitempty"`
	Active          bool   `json:"active,omitempty"`
	Algorithm       int    `json:"algorithm,omitempty"`
	FingerprintType int    `json:"fingerprint_type,omitempty"`
	Fingerprint     string `json:"fingerprint,omitempty"`
}

type TXTRecord struct {
	Name   string `json:"name,omitempty"`
	TTL    int    `json:"ttl,omitempty"`
	Active bool   `json:"active,omitempty"`
	Target string `json:"target,omitempty"`
}

type ARecordList []ARecord
type AAAARecordList []AAAARecord
type AFSDBRecordList []AFSDBRecord
type CNAMERecordList []CNAMERecord
type DNSKEYRecordList []DNSKEYRecord
type DSRecordList []DSRecord
type HINFORecordList []HINFORecord
type LOCRecordList []LOCRecord
type MXRecordList []MXRecord
type NAPTRRecordList []NAPTRRecord
type NSRecordList []NSRecord
type NSEC3RecordList []NSEC3Record
type NSEC3PARAMRecordList []NSEC3PARAMRecord
type PTRRecordList []PTRRecord
type RPRecordList []RPRecord
type RRRecordList []RRRecord
type RRSIGRecordList []RRSIGRecord
type SPFRecordList []SPFRecord
type SRVRecordList []SRVRecord
type SSHFPRecordList []SSHFPRecord
type TXTRecordList []TXTRecord
