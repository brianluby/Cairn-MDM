package vpn

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

// RowStore is the persistence the server catalogue needs; *sqlite.DB provides it.
type RowStore interface {
	ListVPNServers(ctx context.Context) ([]sqlite.VPNServerRow, error)
	GetVPNServer(ctx context.Context, id int64) (sqlite.VPNServerRow, error)
	CreateVPNServer(ctx context.Context, r sqlite.VPNServerRow, actor string) (int64, error)
	UpdateVPNServer(ctx context.Context, r sqlite.VPNServerRow, actor string) error
	DeleteVPNServer(ctx context.Context, id int64, actor string) error
}

// Servers is the catalogue of server records. It validates on write and keeps
// each server's shared TLS key sealed at rest.
type Servers struct {
	rows RowStore
	seal cipher.AEAD
}

// NewServers builds the catalogue. key is the 32-byte key from the VPN key file.
func NewServers(rows RowStore, key []byte) (*Servers, error) {
	if len(key) != 32 {
		return nil, errors.New("vpn: a 32-byte encryption key is required")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Servers{rows: rows, seal: aead}, nil
}

// storedConfig is the JSON kept in vpn_servers.config: every setting except the
// TLS key.
type storedConfig struct {
	Kind           string      `json:"kind,omitempty"` // absent on OpenVPN records
	IKEv2          *IKEv2      `json:"ikev2,omitempty"`
	WiFi           *WiFi       `json:"wifi,omitempty"`
	Remotes        []Remote    `json:"remotes"`
	VerifyX509Name string      `json:"verify_x509_name"`
	CAPEM          string      `json:"ca_pem"`
	TLSKeyMode     string      `json:"tls_key_mode"`
	KeyDirection   int         `json:"key_direction"`
	Cipher         string      `json:"cipher"`
	Auth           string      `json:"auth"`
	TunMTU         int         `json:"tun_mtu"`
	UserAuth       bool        `json:"user_auth"`
	OnDemand       bool        `json:"on_demand"`
	Extra          []Directive `json:"extra,omitempty"`
}

// The slug is bound into the ciphertext so a sealed key cannot be moved to
// another server's row.
func aad(slug string) []byte { return []byte("vpn-server-tls-key:" + slug) }

func (c *Servers) sealKey(slug, key string) ([]byte, error) {
	nonce := make([]byte, c.seal.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return c.seal.Seal(nonce, nonce, []byte(key), aad(slug)), nil
}

func (c *Servers) openKey(slug string, sealed []byte) (string, error) {
	n := c.seal.NonceSize()
	if len(sealed) < n {
		return "", errors.New("vpn: stored TLS key is truncated")
	}
	plain, err := c.seal.Open(nil, sealed[:n], sealed[n:], aad(slug))
	if err != nil {
		return "", errors.New("vpn: stored TLS key cannot be decrypted with this key file")
	}
	return string(plain), nil
}

func (c *Servers) fromRow(r sqlite.VPNServerRow) (Server, error) {
	var cfg storedConfig
	if err := json.Unmarshal(r.Config, &cfg); err != nil {
		return Server{}, fmt.Errorf("vpn: server %q settings unreadable: %w", r.Slug, err)
	}
	s := Server{
		ID: r.ID, Name: r.Name, Slug: r.Slug,
		Remotes: cfg.Remotes, VerifyX509Name: cfg.VerifyX509Name, CAPEM: cfg.CAPEM,
		TLSKeyMode: cfg.TLSKeyMode, KeyDirection: cfg.KeyDirection,
		Cipher: cfg.Cipher, Auth: cfg.Auth, TunMTU: cfg.TunMTU,
		UserAuth: cfg.UserAuth, OnDemand: cfg.OnDemand, Extra: cfg.Extra,
		Kind: KindOpenVPN,
	}
	if cfg.Kind == KindIKEv2 && cfg.IKEv2 != nil {
		s.Kind, s.IKEv2 = KindIKEv2, *cfg.IKEv2
	}
	if cfg.Kind == KindWiFi && cfg.WiFi != nil {
		s.Kind, s.WiFi = KindWiFi, *cfg.WiFi
	}
	if len(r.SealedKey) > 0 {
		key, err := c.openKey(r.Slug, r.SealedKey)
		if err != nil {
			return Server{}, err
		}
		s.TLSKey = key
	}
	return s, nil
}

func toConfig(s Server) ([]byte, error) {
	if s.IsIKEv2() {
		return json.Marshal(storedConfig{Kind: KindIKEv2, IKEv2: &s.IKEv2, CAPEM: s.CAPEM, OnDemand: s.OnDemand})
	}
	if s.IsWiFi() {
		return json.Marshal(storedConfig{Kind: KindWiFi, WiFi: &s.WiFi, CAPEM: s.CAPEM})
	}
	return json.Marshal(storedConfig{
		Remotes: s.Remotes, VerifyX509Name: s.VerifyX509Name, CAPEM: s.CAPEM,
		TLSKeyMode: s.TLSKeyMode, KeyDirection: s.KeyDirection,
		Cipher: s.Cipher, Auth: s.Auth, TunMTU: s.TunMTU,
		UserAuth: s.UserAuth, OnDemand: s.OnDemand, Extra: s.Extra,
	})
}

// List returns every server with its TLS key decrypted.
func (c *Servers) List(ctx context.Context) ([]Server, error) {
	rows, err := c.rows.ListVPNServers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Server, 0, len(rows))
	for _, r := range rows {
		s, err := c.fromRow(r)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// Get returns one server with its TLS key decrypted.
func (c *Servers) Get(ctx context.Context, id int64) (Server, error) {
	r, err := c.rows.GetVPNServer(ctx, id)
	if err != nil {
		return Server{}, err
	}
	return c.fromRow(r)
}

// Create validates and stores a new server.
func (c *Servers) Create(ctx context.Context, s Server, actor string) (int64, error) {
	if err := s.Validate(); err != nil {
		return 0, err
	}
	row, err := c.toRow(s)
	if err != nil {
		return 0, err
	}
	return c.rows.CreateVPNServer(ctx, row, actor)
}

// Update validates and replaces a server's settings. The slug is taken from the
// stored row, whatever the caller passed. An empty TLSKey with a key mode set
// keeps the stored key, so an edit form never has to show it.
func (c *Servers) Update(ctx context.Context, s Server, actor string) error {
	current, err := c.Get(ctx, s.ID)
	if err != nil {
		return err
	}
	// The kind decides which profile replaces the one on a device; it stays.
	s.Slug, s.Kind = current.Slug, current.Kind
	if s.IsIKEv2() || s.IsWiFi() {
		s.TLSKeyMode, s.TLSKey = TLSKeyNone, ""
	}
	if s.TLSKeyMode != TLSKeyNone && s.TLSKey == "" {
		s.TLSKey = current.TLSKey
	}
	if err := s.Validate(); err != nil {
		return err
	}
	row, err := c.toRow(s)
	if err != nil {
		return err
	}
	if row.SealedKey == nil {
		row.SealedKey = []byte{} // mode none: clear any stored key
	}
	return c.rows.UpdateVPNServer(ctx, row, actor)
}

// Delete removes a server.
func (c *Servers) Delete(ctx context.Context, id int64, actor string) error {
	return c.rows.DeleteVPNServer(ctx, id, actor)
}

func (c *Servers) toRow(s Server) (sqlite.VPNServerRow, error) {
	cfg, err := toConfig(s)
	if err != nil {
		return sqlite.VPNServerRow{}, err
	}
	row := sqlite.VPNServerRow{ID: s.ID, Name: s.Name, Slug: s.Slug, Config: cfg}
	if s.TLSKeyMode != TLSKeyNone && !s.IsIKEv2() && !s.IsWiFi() {
		if row.SealedKey, err = c.sealKey(s.Slug, s.TLSKey); err != nil {
			return sqlite.VPNServerRow{}, err
		}
	}
	return row, nil
}
