package toyaes

import (
	ccipher "crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

const size = 16

func genCounter(nonce []byte) [size]byte {
	var counter [size]byte
	copy(counter[:], nonce)
	counter[size-1] = 1
	return counter
}

func incrementCounter(counter [size]byte) [size]byte {
	// nonce は 12バイトな想定
	// counter全体は16バイト
	// 残り4バイトのカウントを増やす
	c := counter[size-4:]
	binary.BigEndian.PutUint32(c, binary.BigEndian.Uint32(c)+1)
	// copy(counter[size-4:], c)
	return counter
}

// 00100001
// x^7 + x^2 + x + 1
var max128 uint128 = uint128{
	lhs: 0xe100000000000000,
	rhs: 0x0000000000000000,
}

func add(lhs, rhs uint128) uint128 {
	return lhs.xor(rhs)
}

func mulg(lhs, rhs uint128) uint128 {
	var sum uint128
	for b := 127; b >= 0; b-- {
		if lhs.rightShift(uint(b)).and(uint128{0, 1}) == (uint128{0, 1}) {
			// lhs >> b & 1 == 1
			sum = add(sum, rhs)
		}
		rhs = rightShift(rhs)
	}
	return sum
}

func rightShift(u uint128) uint128 {
	if u.and(uint128{0, 1}) == (uint128{0, 1}) {
		u = u.rightShift(1)
		return add(u, max128)
	} else {
		return u.rightShift(1)
	}
}

func split(in []byte) <-chan uint128 {
	ch := make(chan uint128)
	go func() {
		defer close(ch)
		for i := 0; i < len(in); i += 16 {
			var out [16]byte
			copy(out[:], in[i:])
			ch <- newUint128(out[:])
		}
	}()
	return ch
}

func ghash(cipherText, additionalData, hk []byte) [16]byte {
	h := newUint128(hk)
	var x uint128
	for v := range split(additionalData) {
		x = mulg(add(x, v), h)
	}
	for v := range split(cipherText) {
		x = mulg(add(x, v), h)
	}

	x = mulg(add(x, uint128{
		uint64(len(additionalData) * 8),
		uint64(len(cipherText) * 8),
	}), h)

	var hashed [16]byte
	pubUint128(hashed[:], x)
	return hashed
}

var _ ccipher.AEAD = (*toyGCM)(nil)

func NewGCM(key []byte) ccipher.AEAD {
	return &toyGCM{cipher: NewToyAES(key)}
}

type toyGCM struct {
	cipher ccipher.Block
}

// NonceSize implements cipher.AEAD
func (*toyGCM) NonceSize() int { return 12 }

// Overhead implements cipher.AEAD
func (*toyGCM) Overhead() int { return 16 }

// Open implements cipher.AEAD
func (ta *toyGCM) Open(dst []byte, nonce []byte, ciphertext []byte, additionalData []byte) ([]byte, error) {
	tags := ciphertext[len(ciphertext)-16:]
	ciphertext = ciphertext[:len(ciphertext)-16]

	hk := make([]byte, 16)
	ta.cipher.Encrypt(hk, make([]byte, 16))

	hash := ghash(ciphertext, additionalData, hk)

	encryptedCounter := make([]byte, 16)
	c := genCounter(nonce)
	ta.cipher.Encrypt(encryptedCounter, c[:])

	expectedTags := make([]byte, len(encryptedCounter[:]))
	subtle.XORBytes(expectedTags, encryptedCounter[:], hash[:])

	if subtle.ConstantTimeCompare(expectedTags, tags) != 1 {
		return nil, errors.New("invalid tags")
	}

	counter := incrementCounter(genCounter(nonce))
	ct := ta.encWitchCounter(ciphertext, nonce, counter)
	return ct, nil
}

// Seal implements cipher.AEAD
func (ta *toyGCM) Seal(dst []byte, nonce []byte, plaintext []byte, additionalData []byte) []byte {
	counter := incrementCounter(genCounter(nonce))
	ct := ta.encWitchCounter(plaintext, nonce, counter)

	hk := make([]byte, 16)
	ta.cipher.Encrypt(hk, make([]byte, 16))

	hash := ghash(ct, additionalData, hk)

	encryptedCounter := make([]byte, 16)
	c := genCounter(nonce)
	ta.cipher.Encrypt(encryptedCounter, c[:])

	tags := make([]byte, len(encryptedCounter[:]))
	subtle.XORBytes(tags, encryptedCounter[:], hash[:])

	ct = append(ct, tags[:]...)
	return ct
}

func (ta *toyGCM) enc(plaintext, nonce []byte) []byte {
	return ta.encWitchCounter(plaintext, nonce, genCounter(nonce))
}

func (ta *toyGCM) encWitchCounter(plaintext, nonce []byte, c [16]byte) []byte {
	blockNum, r := len(plaintext)/size, len(plaintext)%size
	if r != 0 {
		blockNum++
	}
	// plaintext は `size` の倍数であるとは限らないため、
	// plaintext より大きい倍数になるものを暗号化対象にする
	ct := make([]byte, blockNum*size)
	copy(ct, plaintext)

	for i := 0; i < blockNum; i++ {
		start, end := size*i, size*(i+1)
		pt := ct[start:end]

		var mask [size]byte
		ta.cipher.Encrypt(mask[:], c[:])

		out := make([]byte, len(pt))
		subtle.XORBytes(out, pt, mask[:])
		copy(ct[start:end], out)

		c = incrementCounter(c)
	}
	// 事前にもともとの `plaintext`より大きいサイズになっている可能性があるので、削る
	// 暗号化前後でバイト列の長さは変わらない
	return ct[:len(plaintext)]
}
