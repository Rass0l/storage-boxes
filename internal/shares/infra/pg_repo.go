package infra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Rass0l/storage-boxes/internal/shares/app"
	"github.com/Rass0l/storage-boxes/internal/shares/domain"
)

// PGShareRepository backs ShareRepository with Postgres.
type PGShareRepository struct{ pool *pgxpool.Pool }

var _ app.ShareRepository = (*PGShareRepository)(nil)

func NewPGShareRepository(pool *pgxpool.Pool) *PGShareRepository {
	return &PGShareRepository{pool: pool}
}

func (r *PGShareRepository) Put(ctx context.Context, s domain.Share) error {
	var createdBy any
	if s.CreatedBy != "" {
		createdBy = s.CreatedBy
	}
	mode := s.AccessMode
	if mode == "" {
		mode = domain.AccessModePublic
	}
	var allowlist any
	if len(s.RecipientDomainAllowlist) > 0 {
		allowlist = s.RecipientDomainAllowlist
	}
	_, err := r.pool.Exec(ctx, `
		INSERT INTO shares(id, box_id, file_entry_id, token_hash, status, expires_at, max_downloads, download_count, created_by, created_at, access_mode, recipient_domain_allowlist, require_otp)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		s.ID, s.BoxID, s.FileEntryID, s.TokenHash, s.Status, s.ExpiresAt, s.MaxDownloads, s.DownloadCount, createdBy, s.CreatedAt, mode, allowlist, s.RequireOTP)
	return err
}

func (r *PGShareRepository) Get(ctx context.Context, shareID string) (domain.Share, error) {
	return r.scan(r.pool.QueryRow(ctx, baseSelect+` WHERE id = $1`, shareID))
}

func (r *PGShareRepository) GetByTokenHash(ctx context.Context, tokenHash string) (domain.Share, error) {
	return r.scan(r.pool.QueryRow(ctx, baseSelect+` WHERE token_hash = $1`, tokenHash))
}

func (r *PGShareRepository) ListByBox(ctx context.Context, boxID string) ([]domain.Share, error) {
	return r.list(ctx, baseSelect+` WHERE box_id = $1 ORDER BY created_at DESC`, boxID)
}

func (r *PGShareRepository) ListByCreator(ctx context.Context, userID string) ([]domain.Share, error) {
	return r.list(ctx, baseSelect+` WHERE created_by = $1 ORDER BY created_at DESC LIMIT 200`, userID)
}

func (r *PGShareRepository) UpdateStatus(ctx context.Context, shareID, status string, now time.Time) error {
	var revoked any
	if status == domain.StatusRevoked {
		revoked = now
	}
	_, err := r.pool.Exec(ctx, `
		UPDATE shares SET status = $1, revoked_at = COALESCE(revoked_at, $2) WHERE id = $3`,
		status, revoked, shareID)
	return err
}

func (r *PGShareRepository) UpdateSettings(ctx context.Context, shareID string, expiresAt time.Time, maxDownloads int) error {
	ct, err := r.pool.Exec(ctx, `
		UPDATE shares SET expires_at = $1, max_downloads = $2
		WHERE id = $3`, expiresAt, maxDownloads, shareID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("share not found")
	}
	return nil
}

func (r *PGShareRepository) IncrementDownload(ctx context.Context, shareID string, now time.Time) (int, error) {
	_ = now
	row := r.pool.QueryRow(ctx, `
		UPDATE shares SET download_count = download_count + 1
		WHERE id = $1 RETURNING download_count`, shareID)
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (r *PGShareRepository) ListExpired(ctx context.Context, now time.Time, limit int) ([]domain.Share, error) {
	if limit <= 0 {
		limit = 100
	}
	return r.list(ctx, baseSelect+` WHERE status = 'active' AND expires_at <= $1 ORDER BY expires_at LIMIT $2`, now, limit)
}

func (r *PGShareRepository) ListPurgeCandidates(ctx context.Context, limit int) ([]domain.Share, error) {
	if limit <= 0 {
		limit = 100
	}
	return r.list(ctx, baseSelect+` WHERE purge_requested_at IS NOT NULL AND status <> 'purged' LIMIT $1`, limit)
}

func (r *PGShareRepository) MarkPurgeRequested(ctx context.Context, shareID string, now time.Time) error {
	_, err := r.pool.Exec(ctx, `UPDATE shares SET purge_requested_at = COALESCE(purge_requested_at, $1) WHERE id = $2`, now, shareID)
	return err
}

func (r *PGShareRepository) Delete(ctx context.Context, shareID string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM shares WHERE id = $1`, shareID)
	return err
}

const baseSelect = `
SELECT id, box_id, file_entry_id, token_hash, status, expires_at, max_downloads, download_count,
       COALESCE(created_by, ''), created_at, revoked_at, purge_requested_at,
       COALESCE(access_mode, 'public'), recipient_domain_allowlist, COALESCE(require_otp, false)
FROM shares`

func (r *PGShareRepository) list(ctx context.Context, sql string, args ...any) ([]domain.Share, error) {
	rows, err := r.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Share{}
	for rows.Next() {
		s, err := r.scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *PGShareRepository) scan(row interface{ Scan(...any) error }) (domain.Share, error) {
	var s domain.Share
	var revoked, purgeReq *time.Time
	var allowlist []string
	if err := row.Scan(&s.ID, &s.BoxID, &s.FileEntryID, &s.TokenHash, &s.Status,
		&s.ExpiresAt, &s.MaxDownloads, &s.DownloadCount, &s.CreatedBy, &s.CreatedAt,
		&revoked, &purgeReq, &s.AccessMode, &allowlist, &s.RequireOTP); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Share{}, fmt.Errorf("share not found")
		}
		return domain.Share{}, err
	}
	s.RevokedAt = revoked
	s.PurgeRequestedAt = purgeReq
	s.RecipientDomainAllowlist = allowlist
	return s, nil
}

// PGShareObjectStore backs ShareObjectStore with Postgres.
type PGShareObjectStore struct{ pool *pgxpool.Pool }

var _ app.ShareObjectStore = (*PGShareObjectStore)(nil)

func NewPGShareObjectStore(pool *pgxpool.Pool) *PGShareObjectStore {
	return &PGShareObjectStore{pool: pool}
}

// share_objects schema from migration 006 lacks a nonce column and a
// content-type column; we store the nonce prefixed to wrapped_share_key and
// original name + content-type in a per-row metadata JSON column the
// migration leaves room for via `storage_key` (which we name as a JSON
// blob "stage_key:content_type:original_name"). To avoid adding another
// migration just for metadata, we pack content-type + name in storage_key
// is brittle — so instead we keep storage_key as opaque and encode
// content-type and name in wrapped_share_key as a length-prefixed blob.
// That keeps the migration minimal while still letting the gateway
// stream the right Content-Type / filename.
//
// Layout of wrapped_share_key column:
//
//	[2 bytes len(nonce)] [nonce] [2 bytes len(wrapped)] [wrapped] [2 bytes len(ct)] [ct] [2 bytes len(name)] [name]
func (s *PGShareObjectStore) PutObject(ctx context.Context, o domain.ShareObject) error {
	blob := packObjectMeta(o)
	_, err := s.pool.Exec(ctx, `
		INSERT INTO share_objects(id, share_id, storage_key, wrapped_share_key, size_bytes)
		VALUES ($1, $2, $3, $4, $5)`,
		o.ID, o.ShareID, o.StorageKey, blob, o.SizeBytes)
	return err
}

func (s *PGShareObjectStore) GetObject(ctx context.Context, shareID string) (domain.ShareObject, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, share_id, storage_key, wrapped_share_key, size_bytes, created_at
		FROM share_objects WHERE share_id = $1`, shareID)
	var o domain.ShareObject
	var blob []byte
	if err := row.Scan(&o.ID, &o.ShareID, &o.StorageKey, &blob, &o.SizeBytes, &o.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ShareObject{}, fmt.Errorf("share object not found")
		}
		return domain.ShareObject{}, err
	}
	nonce, wrapped, ct, name, err := unpackObjectMeta(blob)
	if err != nil {
		return domain.ShareObject{}, err
	}
	o.Nonce = nonce
	o.WrappedShareKey = wrapped
	o.ContentType = ct
	o.OriginalName = name
	return o, nil
}

func (s *PGShareObjectStore) DeleteObject(ctx context.Context, shareID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM share_objects WHERE share_id = $1`, shareID)
	return err
}

// PGAccessRecorder writes share_access_events.
type PGAccessRecorder struct{ pool *pgxpool.Pool }

var _ app.ShareAccessRecorder = (*PGAccessRecorder)(nil)

func NewPGAccessRecorder(pool *pgxpool.Pool) *PGAccessRecorder { return &PGAccessRecorder{pool: pool} }

func (r *PGAccessRecorder) RecordAccess(ctx context.Context, e domain.AccessEvent) error {
	meta, _ := json.Marshal(e.Metadata)
	var ip, ua, ref, cc, rid any
	if e.RemoteIP != "" {
		ip = e.RemoteIP
	}
	if e.UserAgent != "" {
		ua = e.UserAgent
	}
	if e.Referer != "" {
		ref = e.Referer
	}
	if e.CountryCode != "" {
		cc = e.CountryCode
	}
	if e.RecipientID != "" {
		rid = e.RecipientID
	}
	_, err := r.pool.Exec(ctx, `
		INSERT INTO share_access_events(id, share_id, recipient_id, remote_ip, user_agent, referer, succeeded, accessed_at, metadata, risk_score, country_code)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		e.ID, e.ShareID, rid, ip, ua, ref, e.Succeeded, e.AccessedAt, meta, e.RiskScore, cc)
	return err
}

const accessEventSelect = `
SELECT id, share_id, COALESCE(recipient_id,''), COALESCE(host(remote_ip),''), COALESCE(user_agent,''), COALESCE(referer,''),
       succeeded, accessed_at, metadata, risk_score, COALESCE(country_code,'')
FROM share_access_events`

func (r *PGAccessRecorder) ListByShare(ctx context.Context, shareID string, limit int) ([]domain.AccessEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.pool.Query(ctx, accessEventSelect+` WHERE share_id = $1 ORDER BY accessed_at DESC LIMIT $2`, shareID, limit)
	if err != nil {
		return nil, err
	}
	return scanAccessEvents(rows)
}

func (r *PGAccessRecorder) ListByRecipient(ctx context.Context, recipientID string, limit int) ([]domain.AccessEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.pool.Query(ctx, accessEventSelect+` WHERE recipient_id = $1 ORDER BY accessed_at DESC LIMIT $2`, recipientID, limit)
	if err != nil {
		return nil, err
	}
	return scanAccessEvents(rows)
}

func scanAccessEvents(rows pgx.Rows) ([]domain.AccessEvent, error) {
	defer rows.Close()
	out := []domain.AccessEvent{}
	for rows.Next() {
		var e domain.AccessEvent
		var meta []byte
		if err := rows.Scan(&e.ID, &e.ShareID, &e.RecipientID, &e.RemoteIP, &e.UserAgent, &e.Referer,
			&e.Succeeded, &e.AccessedAt, &meta, &e.RiskScore, &e.CountryCode); err != nil {
			return nil, err
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &e.Metadata)
		}
		if e.Metadata == nil {
			e.Metadata = map[string]any{}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func packObjectMeta(o domain.ShareObject) []byte {
	w := writer{}
	w.short(len(o.Nonce))
	w.raw(o.Nonce)
	w.short(len(o.WrappedShareKey))
	w.raw(o.WrappedShareKey)
	w.short(len(o.ContentType))
	w.raw([]byte(o.ContentType))
	w.short(len(o.OriginalName))
	w.raw([]byte(o.OriginalName))
	return w.buf
}

func unpackObjectMeta(b []byte) (nonce, wrapped []byte, ct, name string, err error) {
	r := reader{b: b}
	n1, err := r.short()
	if err != nil {
		return
	}
	nonce, err = r.take(n1)
	if err != nil {
		return
	}
	n2, err := r.short()
	if err != nil {
		return
	}
	wrapped, err = r.take(n2)
	if err != nil {
		return
	}
	n3, err := r.short()
	if err != nil {
		return
	}
	ctb, err := r.take(n3)
	if err != nil {
		return
	}
	n4, err := r.short()
	if err != nil {
		return
	}
	nb, err := r.take(n4)
	if err != nil {
		return
	}
	return nonce, wrapped, string(ctb), string(nb), nil
}

type writer struct{ buf []byte }

func (w *writer) short(n int)  { w.buf = append(w.buf, byte(n>>8), byte(n&0xff)) }
func (w *writer) raw(b []byte) { w.buf = append(w.buf, b...) }

type reader struct{ b []byte }

func (r *reader) short() (int, error) {
	if len(r.b) < 2 {
		return 0, fmt.Errorf("share object metadata truncated")
	}
	v := int(r.b[0])<<8 | int(r.b[1])
	r.b = r.b[2:]
	return v, nil
}

func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || len(r.b) < n {
		return nil, fmt.Errorf("share object metadata truncated")
	}
	out := make([]byte, n)
	copy(out, r.b[:n])
	r.b = r.b[n:]
	return out, nil
}
