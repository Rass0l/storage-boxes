package infra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Rass0l/storage-boxes/internal/vault/app"
	"github.com/Rass0l/storage-boxes/internal/vault/domain"
)

type PGCryptoStore struct{ pool *pgxpool.Pool }

var _ app.CryptoStore = (*PGCryptoStore)(nil)

func NewPGCryptoStore(pool *pgxpool.Pool) *PGCryptoStore { return &PGCryptoStore{pool: pool} }

type kdfParams struct {
	Salt    string `json:"salt_b64"`
	Time    uint32 `json:"t"`
	Memory  uint32 `json:"m"`
	Threads uint8  `json:"p"`
}

type cipherParams struct {
	Nonce string `json:"nonce_b64"`
}

func (s *PGCryptoStore) Put(ctx context.Context, m domain.BoxCryptoMaterial) error {
	kdf, _ := json.Marshal(kdfParams{
		Salt: base64Std(m.KDFSalt), Time: m.KDFTime, Memory: m.KDFMemory, Threads: m.KDFThreads,
	})
	cp, _ := json.Marshal(cipherParams{Nonce: base64Std(m.Nonce)})
	_, err := s.pool.Exec(ctx, `
		INSERT INTO box_crypto_material(
			box_id, crypto_version, kdf_algorithm, kdf_params,
			cipher_algorithm, cipher_params,
			key_wrapping_algorithm, wrapped_box_master_key)
		VALUES ($1, 1, $2, $3, $4, $5, 'aead', $6)
		ON CONFLICT (box_id) DO UPDATE SET
		  kdf_algorithm = EXCLUDED.kdf_algorithm,
		  kdf_params = EXCLUDED.kdf_params,
		  cipher_algorithm = EXCLUDED.cipher_algorithm,
		  cipher_params = EXCLUDED.cipher_params,
		  wrapped_box_master_key = EXCLUDED.wrapped_box_master_key`,
		m.BoxID, m.KDFAlgorithm, kdf, m.CipherAlgo, cp, m.WrappedBMK)
	return err
}

func (s *PGCryptoStore) Get(ctx context.Context, boxID string) (domain.BoxCryptoMaterial, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT box_id, kdf_algorithm, kdf_params,
		       cipher_algorithm, cipher_params, wrapped_box_master_key
		FROM box_crypto_material WHERE box_id = $1`, boxID)
	var m domain.BoxCryptoMaterial
	var kdfRaw, cipherRaw []byte
	if err := row.Scan(&m.BoxID, &m.KDFAlgorithm, &kdfRaw,
		&m.CipherAlgo, &cipherRaw, &m.WrappedBMK); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.BoxCryptoMaterial{}, fmt.Errorf("box crypto material not found")
		}
		return domain.BoxCryptoMaterial{}, err
	}
	var kp kdfParams
	if err := json.Unmarshal(kdfRaw, &kp); err != nil {
		return domain.BoxCryptoMaterial{}, fmt.Errorf("decode kdf params: %w", err)
	}
	var cp cipherParams
	if err := json.Unmarshal(cipherRaw, &cp); err != nil {
		return domain.BoxCryptoMaterial{}, fmt.Errorf("decode cipher params: %w", err)
	}
	m.KDFSalt = fromBase64Std(kp.Salt)
	m.KDFTime = kp.Time
	m.KDFMemory = kp.Memory
	m.KDFThreads = kp.Threads
	m.Nonce = fromBase64Std(cp.Nonce)
	return m, nil
}

func (s *PGCryptoStore) Delete(ctx context.Context, boxID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM box_crypto_material WHERE box_id = $1`, boxID)
	return err
}
