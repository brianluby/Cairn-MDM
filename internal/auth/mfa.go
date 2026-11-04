package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

var ErrMFA = errors.New("MFA authorization unavailable or expired")
var ErrMFACode = errors.New("code or invitation not accepted; after five failures wait 15 minutes")

// MFAStore owns confirmation, replay protection and recovery in one transaction.
// The caller must supply an independent, protected 32-byte encryption key.
type MFAStore struct {
	db       *sql.DB
	sessions *SessionStore
	seal     cipher.AEAD
	now      func() time.Time
}

func NewMFAStore(db *sql.DB, sessions *SessionStore, key []byte) (*MFAStore, error) {
	if len(key) != 32 {
		return nil, errors.New("MFA requires a 32-byte encryption key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &MFAStore{db: db, sessions: sessions, seal: a, now: time.Now}, nil
}
func localSubject(p string) string {
	if strings.HasPrefix(p, "local:") {
		return strings.TrimPrefix(p, "local:")
	}
	return ""
}
func mfaPrincipal(id Identity) string {
	if id.Provider == "local" && len(id.SubjectID) == 64 {
		return "local:" + id.SubjectID
	}
	if id.Provider == "ldap" && id.Directory != nil && id.Directory.DirectoryID != "" {
		raw, err := hex.DecodeString(id.Directory.ObjectID)
		if err == nil && len(raw) == 16 {
			return "ldap:" + hashToken(id.Directory.DirectoryID+"\x00"+strings.ToLower(id.Directory.ObjectID))
		}
	}
	// OIDC needs a retained issuer+subject; names/email are never factor keys.
	return ""
}
func (m *MFAStore) encrypt(p string, raw []byte) []byte {
	nonce := make([]byte, m.seal.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return m.seal.Seal(nonce, nonce, raw, []byte(p))
}
func (m *MFAStore) decrypt(p string, b []byte) ([]byte, error) {
	n := m.seal.NonceSize()
	if len(b) < n {
		return nil, ErrMFA
	}
	return m.seal.Open(nil, b[:n], b[n:], []byte(p))
}
func (m *MFAStore) transaction(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Take the SQLite write lock before reading mutable authorization state.
	if _, err = tx.ExecContext(ctx, `UPDATE mfa_attempts SET failures=failures WHERE 0`); err != nil {
		return err
	}
	err = fn(tx)
	if err != nil && !errors.Is(err, ErrMFACode) {
		return err
	}
	if e := tx.Commit(); e != nil {
		return e
	}
	return err
}
func (m *MFAStore) session(ctx context.Context, tx *sql.Tx, token string, fresh bool) (string, error) {
	var p, role string
	var verified int64
	err := tx.QueryRowContext(ctx, `SELECT auth_subject,role,mfa_verified_at FROM app_sessions WHERE token=? AND unixepoch(expires_at)>?`, hashToken(token), m.now().Unix()).Scan(&p, &role, &verified)
	if err != nil || p == "" {
		return "", ErrMFA
	}
	if fresh && (verified <= m.now().Add(-5*time.Minute).Unix() || verified > m.now().Unix()) {
		return "", ErrMFA
	}
	if fresh {
		var n int
		err = tx.QueryRowContext(ctx, `SELECT count(*) FROM mfa_factors WHERE principal=?`, p).Scan(&n)
		if err != nil || n != 1 {
			return "", ErrMFA
		}
	}
	return p, nil
}
func (m *MFAStore) checked(ctx context.Context, token string) error {
	_, err := m.sessions.Get(ctx, token)
	return err
}
func auditMFA(ctx context.Context, tx *sql.Tx, actor, target, action string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_log(username,provider,action,target,result,remote) VALUES(?,'cairn-mfa',?,?,'ok','')`, actor, action, target)
	return err
}
func (m *MFAStore) allowed(ctx context.Context, tx *sql.Tx, p string) error {
	var until int64
	err := tx.QueryRowContext(ctx, `SELECT blocked_until FROM mfa_attempts WHERE principal=?`, p).Scan(&until)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if until > m.now().Unix() {
		return ErrMFACode
	}
	return nil
}
func (m *MFAStore) failed(ctx context.Context, tx *sql.Tx, p string) error {
	now := m.now().Unix()
	_, err := tx.ExecContext(ctx, `INSERT INTO mfa_attempts(principal,failures,blocked_until) VALUES(?,1,0)
 ON CONFLICT(principal) DO UPDATE SET failures=CASE WHEN blocked_until>0 AND blocked_until<=? THEN 1 ELSE failures+1 END,
 blocked_until=CASE WHEN blocked_until>0 AND blocked_until<=? THEN 0 WHEN failures>=4 THEN ? ELSE 0 END`, p, now, now, now+900)
	if err != nil {
		return err
	}
	return ErrMFACode
}
func clearAttempts(ctx context.Context, tx *sql.Tx, p string) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM mfa_attempts WHERE principal=?`, p)
	return err
}
func clearFactor(ctx context.Context, tx *sql.Tx, p string) error {
	for _, table := range []string{"mfa_factors", "mfa_recovery", "mfa_setups", "mfa_invitations"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE principal=?`, p); err != nil {
			return err
		}
	}
	return nil
}
func (m *MFAStore) invitation(ctx context.Context, tx *sql.Tx, p string) (string, error) {
	raw := randomToken()
	_, err := tx.ExecContext(ctx, `INSERT INTO mfa_invitations(principal,token_hash,expires_at) VALUES(?,?,?) ON CONFLICT(principal) DO UPDATE SET token_hash=excluded.token_hash,expires_at=excluded.expires_at`, p, hashToken(raw), m.now().Add(15*time.Minute).Unix())
	return raw, err
}

// BootstrapLocal is a host-only procedure. It cannot replace any existing factor
// or run after the first factor is confirmed. The browser has no bootstrap route.
func (m *MFAStore) BootstrapLocal(ctx context.Context, username string) (raw string, err error) {
	err = m.transaction(ctx, func(tx *sql.Tx) error {
		var n int
		if e := tx.QueryRowContext(ctx, `SELECT bootstrap_closed FROM mfa_state WHERE id=1`).Scan(&n); e != nil {
			return e
		}
		if n != 0 {
			return ErrMFA
		}
		var subject string
		if e := tx.QueryRowContext(ctx, `SELECT subject_id FROM app_users WHERE username=? AND role='admin'`, username).Scan(&subject); e != nil {
			return ErrMFA
		}
		// A new host approval invalidates earlier bootstrap invitations and setups.
		if _, e := tx.ExecContext(ctx, `DELETE FROM mfa_invitations`); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, `DELETE FROM mfa_setups`); e != nil {
			return e
		}
		if len(subject) != 64 {
			return ErrMFA
		}
		p := "local:" + subject
		var e error
		raw, e = m.invitation(ctx, tx, p)
		if e != nil {
			return e
		}
		return auditMFA(ctx, tx, "local-host", p, "mfa.bootstrap")
	})
	if err != nil {
		raw = ""
	}
	return
}

// Invite requires the administrator's own fresh factor. reset explicitly revokes
// the target's old factor, recovery codes and sessions in the same transaction.
func (m *MFAStore) Invite(ctx context.Context, token string, target Identity, reset bool) (raw string, err error) {
	if err = m.checked(ctx, token); err != nil {
		return
	}
	p := mfaPrincipal(target)
	if p == "" {
		return "", ErrMFA
	}
	err = m.transaction(ctx, func(tx *sql.Tx) error {
		actor, e := m.session(ctx, tx, token, true)
		if e != nil {
			return e
		}
		var role string
		if e = tx.QueryRowContext(ctx, `SELECT role FROM app_sessions WHERE token=?`, hashToken(token)).Scan(&role); e != nil {
			return e
		}
		if role != "admin" || actor == p {
			return ErrMFA
		}
		if target.Provider == "local" {
			var s string
			if e = tx.QueryRowContext(ctx, `SELECT subject_id FROM app_users WHERE username=?`, target.Username).Scan(&s); e != nil || "local:"+s != p {
				return ErrMFA
			}
		}
		var n int
		if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM mfa_factors WHERE principal=?`, p).Scan(&n); e != nil {
			return e
		}
		if n > 0 && !reset {
			return ErrMFA
		}
		if reset {
			if e = clearFactor(ctx, tx, p); e != nil {
				return e
			}
			if _, e = tx.ExecContext(ctx, `DELETE FROM app_sessions WHERE auth_subject=?`, p); e != nil {
				return e
			}
		}
		// Reissuing approval cancels any pending setup; it cannot reset guessing limits.
		if _, e = tx.ExecContext(ctx, `DELETE FROM mfa_setups WHERE principal=?`, p); e != nil {
			return e
		}
		raw, e = m.invitation(ctx, tx, p)
		if e != nil {
			return e
		}
		action := "mfa.invite"
		if reset {
			action = "mfa.reset"
		}
		return auditMFA(ctx, tx, actor, p, action)
	})
	if err != nil {
		raw = ""
	}
	return
}

type MFASetup struct{ Secret, URI string }

func (m *MFAStore) Begin(ctx context.Context, token, invite string) (out MFASetup, err error) {
	if err = m.checked(ctx, token); err != nil {
		return
	}
	err = m.transaction(ctx, func(tx *sql.Tx) error {
		p, e := m.session(ctx, tx, token, false)
		if e != nil {
			return e
		}
		if e = m.allowed(ctx, tx, p); e != nil {
			return e
		}
		var n int
		if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM mfa_factors WHERE principal=?`, p).Scan(&n); e != nil {
			return e
		}
		if n != 0 {
			return ErrMFA
		}
		res, e := tx.ExecContext(ctx, `DELETE FROM mfa_invitations WHERE principal=? AND token_hash=? AND expires_at>?`, p, hashToken(invite), m.now().Unix())
		if e != nil {
			return e
		}
		n64, e := res.RowsAffected()
		if e != nil {
			return e
		}
		if n64 != 1 {
			return m.failed(ctx, tx, p)
		}
		raw := make([]byte, 20)
		if _, e = rand.Read(raw); e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO mfa_setups(principal,session_hash,secret,expires_at) VALUES(?,?,?,?) ON CONFLICT(principal) DO UPDATE SET session_hash=excluded.session_hash,secret=excluded.secret,expires_at=excluded.expires_at`, p, hashToken(token), m.encrypt(p, raw), m.now().Add(10*time.Minute).Unix())
		if e != nil {
			return e
		}
		out.Secret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
		q := url.Values{"secret": {out.Secret}, "issuer": {"Cairn"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
		var username, provider string
		if e = tx.QueryRowContext(ctx, `SELECT username,provider FROM app_sessions WHERE token=?`, hashToken(token)).Scan(&username, &provider); e != nil {
			return e
		}
		out.URI = "otpauth://totp/" + url.PathEscape("Cairn:"+provider+":"+username) + "?" + q.Encode()
		return auditMFA(ctx, tx, p, p, "mfa.setup-start")
	})
	if err != nil {
		out = MFASetup{}
	}
	return
}

// hotp implements RFC 4226 dynamic truncation; TOTP uses a 30-second counter.
func hotp(secret []byte, counter int64) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(counter))
	h := hmac.New(sha1.New, secret)
	h.Write(b[:])
	sum := h.Sum(nil)
	i := sum[len(sum)-1] & 15
	n := binary.BigEndian.Uint32(sum[i:i+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", n%1000000)
}
func matchTOTP(secret []byte, code string, now, last int64) int64 {
	if len(code) != 6 {
		return -1
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return -1
		}
	}
	// Accept one adjacent step for clock skew, but never reuse an accepted counter.
	for _, c := range []int64{now / 30, now/30 - 1, now/30 + 1} {
		if c >= 0 && c > last && subtle.ConstantTimeCompare([]byte(hotp(secret, c)), []byte(code)) == 1 {
			return c
		}
	}
	return -1
}
func (m *MFAStore) Confirm(ctx context.Context, token, code string) (codes []string, err error) {
	if err = m.checked(ctx, token); err != nil {
		return
	}
	err = m.transaction(ctx, func(tx *sql.Tx) error {
		p, e := m.session(ctx, tx, token, false)
		if e != nil {
			return e
		}
		if e = m.allowed(ctx, tx, p); e != nil {
			return e
		}
		var enc []byte
		if e = tx.QueryRowContext(ctx, `SELECT secret FROM mfa_setups WHERE principal=? AND session_hash=? AND expires_at>?`, p, hashToken(token), m.now().Unix()).Scan(&enc); e != nil {
			return ErrMFA
		}
		raw, e := m.decrypt(p, enc)
		if e != nil {
			return e
		}
		counter := matchTOTP(raw, code, m.now().Unix(), -1)
		if counter < 0 {
			return m.failed(ctx, tx, p)
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO mfa_factors(principal,secret,last_counter) VALUES(?,?,?)`, p, enc, counter); e != nil {
			return e
		}
		for i := 0; i < 10; i++ {
			c := randomToken()[:32]
			if _, e = tx.ExecContext(ctx, `INSERT INTO mfa_recovery(principal,code_hash) VALUES(?,?)`, p, hashToken(c)); e != nil {
				return e
			}
			codes = append(codes, c)
		}
		if _, e = tx.ExecContext(ctx, `DELETE FROM mfa_setups WHERE principal=?`, p); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `DELETE FROM app_sessions WHERE auth_subject=? AND token<>?`, p, hashToken(token)); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE app_sessions SET mfa_verified_at=? WHERE token=?`, m.now().Unix(), hashToken(token)); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE mfa_state SET bootstrap_closed=1 WHERE id=1`); e != nil {
			return e
		}
		if e = clearAttempts(ctx, tx, p); e != nil {
			return e
		}
		return auditMFA(ctx, tx, p, p, "mfa.confirm")
	})
	if err != nil {
		codes = nil
	}
	return
}
func (m *MFAStore) Verify(ctx context.Context, token, code string) error {
	if e := m.checked(ctx, token); e != nil {
		return e
	}
	return m.transaction(ctx, func(tx *sql.Tx) error {
		p, e := m.session(ctx, tx, token, false)
		if e != nil {
			return e
		}
		if e = m.allowed(ctx, tx, p); e != nil {
			return e
		}
		var enc []byte
		var last int64
		if e = tx.QueryRowContext(ctx, `SELECT secret,last_counter FROM mfa_factors WHERE principal=?`, p).Scan(&enc, &last); e != nil {
			return ErrMFA
		}
		raw, e := m.decrypt(p, enc)
		if e != nil {
			return e
		}
		c := matchTOTP(raw, code, m.now().Unix(), last)
		if c < 0 {
			return m.failed(ctx, tx, p)
		}
		if _, e = tx.ExecContext(ctx, `UPDATE mfa_factors SET last_counter=? WHERE principal=?`, c, p); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE app_sessions SET mfa_verified_at=? WHERE token=?`, m.now().Unix(), hashToken(token)); e != nil {
			return e
		}
		if e = clearAttempts(ctx, tx, p); e != nil {
			return e
		}
		return auditMFA(ctx, tx, p, p, "mfa.verify")
	})
}

// Recover consumes one recovery code and revokes ALL old factors/codes. The
// current password-authenticated session can register a replacement; it is not
// MFA-verified until that replacement is confirmed.
func (m *MFAStore) Recover(ctx context.Context, token, code string) (raw string, err error) {
	if err = m.checked(ctx, token); err != nil {
		return
	}
	err = m.transaction(ctx, func(tx *sql.Tx) error {
		p, e := m.session(ctx, tx, token, false)
		if e != nil {
			return e
		}
		if e = m.allowed(ctx, tx, p); e != nil {
			return e
		}
		res, e := tx.ExecContext(ctx, `DELETE FROM mfa_recovery WHERE principal=? AND code_hash=?`, p, hashToken(code))
		if e != nil {
			return e
		}
		n, e := res.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return m.failed(ctx, tx, p)
		}
		if e = clearFactor(ctx, tx, p); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `DELETE FROM app_sessions WHERE auth_subject=? AND token<>?`, p, hashToken(token)); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE app_sessions SET mfa_verified_at=0 WHERE auth_subject=?`, p); e != nil {
			return e
		}
		raw, e = m.invitation(ctx, tx, p)
		if e != nil {
			return e
		}
		if e = clearAttempts(ctx, tx, p); e != nil {
			return e
		}
		return auditMFA(ctx, tx, p, p, "mfa.recover")
	})
	if err != nil {
		raw = ""
	}
	return
}
func (m *MFAStore) Fresh(ctx context.Context, token string) error {
	if e := m.checked(ctx, token); e != nil {
		return e
	}
	return m.transaction(ctx, func(tx *sql.Tx) error { _, e := m.session(ctx, tx, token, true); return e })
}

// LocalIdentity resolves an existing local account for an admin invitation.
func (m *MFAStore) LocalIdentity(ctx context.Context, name string) (Identity, error) {
	id := Identity{Username: name, Provider: "local"}
	err := m.db.QueryRowContext(ctx, `SELECT subject_id FROM app_users WHERE username=?`, name).Scan(&id.SubjectID)
	return id, err
}

// ResetLocalAdmin is an explicit host-recovery procedure for a local admin who
// lost all factors. Host access is the authority; there is no HTTP equivalent.
func (m *MFAStore) ResetLocalAdmin(ctx context.Context, username string) (raw string, err error) {
	err = m.transaction(ctx, func(tx *sql.Tx) error {
		var subject string
		if e := tx.QueryRowContext(ctx, `SELECT subject_id FROM app_users WHERE username=? AND role='admin'`, username).Scan(&subject); e != nil || len(subject) != 64 {
			return ErrMFA
		}
		p := "local:" + subject
		if e := clearFactor(ctx, tx, p); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, `DELETE FROM app_sessions WHERE auth_subject=?`, p); e != nil {
			return e
		}
		var e error
		raw, e = m.invitation(ctx, tx, p)
		if e != nil {
			return e
		}
		return auditMFA(ctx, tx, "local-host", p, "mfa.host-reset")
	})
	if err != nil {
		raw = ""
	}
	return
}
