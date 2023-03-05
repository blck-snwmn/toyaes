package toyaes

import ccipher "crypto/cipher"

var _ ccipher.AEAD = (*toyCCM)(nil)

func NewCCM(cipher ccipher.Block) ccipher.AEAD {
	return &toyGCM{cipher: cipher}
}

type toyCCM struct {
	cipher ccipher.Block
}

// NonceSize implements cipher.AEAD
func (*toyCCM) NonceSize() int { return 12 }

// Overhead implements cipher.AEAD
func (*toyCCM) Overhead() int { return 16 }

// Open implements cipher.AEAD
func (ta *toyCCM) Open(dst []byte, nonce []byte, ciphertext []byte, additionalData []byte) ([]byte, error) {
	return nil, nil
}

// Seal implements cipher.AEAD
func (ta *toyCCM) Seal(dst []byte, nonce []byte, plaintext []byte, additionalData []byte) []byte {
	return nil
}
