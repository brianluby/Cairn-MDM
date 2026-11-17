package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/micromdm/nanomdm/cryptoutil"
	"github.com/nickpdawson/cairn-mdm/internal/push"
)

// APNSWriteOptions distinguishes initial import from renewal. The caller must
// verify Apple issuer trust before calling this storage primitive.
type APNSWriteOptions = push.CertificateWriteOptions

// SaveAPNSCertificate commits material, metadata, provider invalidation and audit
// together. Renewal cannot create a topic, shorten validity or select a default.
func (db *DB) SaveAPNSCertificate(ctx context.Context, certPEM, keyPEM []byte, o APNSWriteOptions) (push.CertificateInfo, error) {
	info, err := push.ValidatePair(certPEM, keyPEM, time.Now())
	if err != nil {
		return info, err
	}
	if o.RenewTopic != "" && (o.RenewTopic != info.Topic || o.MakeDefault) {
		return info, errors.New("renewal must match the selected topic and cannot change the default")
	}
	if o.Actor == "" {
		return info, errors.New("an audit actor is required")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return info, err
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return info, err
	}
	defer tx.Rollback()
	// A replay of the same reviewed intent returns its receipt without changing
	// material or selecting the default again, even after a later renewal.
	if o.RequestID != "" {
		var fingerprint, topic, renew string
		var makeDefault bool
		err := tx.QueryRowContext(ctx, `SELECT fingerprint,topic,renew_topic,make_default FROM apns_changes WHERE request_id=?`, o.RequestID).Scan(&fingerprint, &topic, &renew, &makeDefault)
		if err == nil {
			if fingerprint != info.Fingerprint || topic != info.Topic || renew != o.RenewTopic || makeDefault != o.MakeDefault {
				return info, errors.New("request was already installed with a different intent")
			}
			return info, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return info, err
		}
	}
	var previous []byte
	err = tx.QueryRowContext(ctx, `SELECT v FROM nano_kv WHERE bucket='pushcert' AND k=?`, info.Topic+".pem").Scan(&previous)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return info, err
	}
	if o.RenewTopic != "" {
		if !exists {
			return info, errors.New("selected renewal topic does not exist")
		}
		old, err := cryptoutil.DecodePEMCertificate(previous)
		if err != nil {
			return info, fmt.Errorf("existing certificate cannot be read: %w", err)
		}
		if !info.NotAfter.After(old.NotAfter) {
			return info, errors.New("renewed certificate must extend the existing expiry")
		}
	} else if exists {
		return info, errors.New("topic already exists; use renewal with its explicit topic")
	}
	// Preserve the old pair inside this transaction before overwriting it.
	// No recovery material is exposed through the browser API.
	var previousKey []byte
	if exists {
		if err := tx.QueryRowContext(ctx, `SELECT v FROM nano_kv WHERE bucket='pushcert' AND k=?`, info.Topic+".key").Scan(&previousKey); err != nil {
			return info, fmt.Errorf("retain previous key: %w", err)
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO apns_changes(request_id,topic,fingerprint,subject,not_after,renew_topic,make_default,previous_cert,previous_key,actor,provider) VALUES(NULLIF(?,''),?,?,?,?,?,?,?,?,?,?)`, o.RequestID, info.Topic, info.Fingerprint, info.Subject, info.NotAfter.UTC().Format(time.RFC3339), o.RenewTopic, o.MakeDefault, previous, previousKey, o.Actor, o.Provider)
	if err != nil {
		return info, fmt.Errorf("retain APNs recovery record: %w", err)
	}
	for suffix, value := range map[string][]byte{"pem": certPEM, "key": keyPEM, "stale_token": []byte(hex.EncodeToString(nonce[:]))} {
		_, err = tx.ExecContext(ctx, `INSERT INTO nano_kv(bucket,k,v) VALUES('pushcert',?,?) ON CONFLICT(bucket,k) DO UPDATE SET v=excluded.v`, info.Topic+"."+suffix, value)
		if err != nil {
			return info, err
		}
	}
	exp := info.NotAfter.UTC().Format(time.RFC3339)
	_, err = tx.ExecContext(ctx, `INSERT INTO apns_topics(topic,not_after,subject,loaded_at,loaded_by) VALUES(?,?,?,datetime('now'),?) ON CONFLICT(topic) DO UPDATE SET not_after=excluded.not_after,subject=excluded.subject,loaded_at=excluded.loaded_at,loaded_by=excluded.loaded_by`, info.Topic, exp, info.Subject, o.Actor)
	if err != nil {
		return info, err
	}
	var current string
	err = tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE key='apns_topic'`).Scan(&current)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return info, err
	}
	// The first initial import becomes the default. Renewal only updates the
	// cached expiry when the selected topic already IS the default.
	if (o.RenewTopic == "" && (o.MakeDefault || current == "")) || current == info.Topic {
		for k, v := range map[string]string{push.SettingTopic: info.Topic, push.SettingNotAfter: exp} {
			_, err = tx.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=datetime('now')`, k, v)
			if err != nil {
				return info, err
			}
		}
	}
	action := "apns.import"
	if o.RenewTopic != "" {
		action = "apns.renew"
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_log(username,provider,action,target,result) VALUES(?,?,?,?,?)`, o.Actor, o.Provider, action, info.Topic, "sha256="+info.Fingerprint+"; expires="+exp)
	if err != nil {
		return info, err
	}
	return info, tx.Commit()
}

// APNSInstallReceipt returns public metadata only, never recovery keys.
func (db *DB) APNSInstallReceipt(ctx context.Context, requestID string) (*push.InstallReceipt, error) {
	var r push.InstallReceipt
	var expiry, installed string
	err := db.sql.QueryRowContext(ctx, `SELECT topic,fingerprint,subject,not_after,installed_at,actor FROM apns_changes WHERE request_id=?`, requestID).Scan(&r.Topic, &r.Fingerprint, &r.Subject, &expiry, &installed, &r.Actor)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.NotAfter, err = time.Parse(time.RFC3339, expiry)
	if err != nil {
		return nil, err
	}
	r.InstalledAt, err = time.Parse(time.RFC3339, installed)
	if err != nil {
		return nil, err
	}
	return &r, nil
}
