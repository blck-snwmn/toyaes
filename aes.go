package toyaes

import (
	ccipher "crypto/cipher"
	"encoding/binary"
)

// Kb: word number (paintext)
// Nk: Word number (key)
// Nr: round number
// 1word= 4byte = 32bit
// input is 4*4 byte

func subBytes(state []byte) {
	for i := 0; i < len(state); i++ {
		state[i] = sbox[state[i]]
	}
}

func invSubBytes(state []byte) {
	for i := 0; i < len(state); i++ {
		state[i] = isbox[state[i]]
	}
}

func shiftRows(state []byte) {
	state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
	state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
	state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]
}

func invShiftRows(state []byte) {
	state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
	state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
	state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]
}

func mul(x, y byte) byte {
	sum := byte(0)
	for i := 0; i < 8; i++ {
		if y&1 == 1 {
			sum ^= x // add
		}
		msb := x & 0x80
		x <<= 1
		if msb == 0x80 {
			x ^= 0x1b // add
		}
		y >>= 1
	}
	return sum
}

func mixColumns(state []byte) {
	tmp := make([]byte, 16)
	// add is xor
	for i := 0; i < 4; i++ {
		tmp[i*4] = mul(0x02, state[i*4]) ^ mul(0x03, state[i*4+1]) ^ state[i*4+2] ^ state[i*4+3]
		tmp[i*4+1] = state[i*4] ^ mul(0x02, state[i*4+1]) ^ mul(0x03, state[i*4+2]) ^ state[i*4+3]
		tmp[i*4+2] = state[i*4] ^ state[i*4+1] ^ mul(0x02, state[i*4+2]) ^ mul(0x03, state[i*4+3])
		tmp[i*4+3] = mul(0x03, state[i*4]) ^ state[i*4+1] ^ state[i*4+2] ^ mul(0x02, state[i*4+3])
	}
	copy(state, tmp)
}

func invMixColumns(state []byte) {
	tmp := make([]byte, 16)
	// add is xor
	for i := 0; i < 4; i++ {
		tmp[i*4] = mul(0x0e, state[i*4]) ^ mul(0x0b, state[i*4+1]) ^ mul(0x0d, state[i*4+2]) ^ mul(0x09, state[i*4+3])
		tmp[i*4+1] = mul(0x09, state[i*4]) ^ mul(0x0e, state[i*4+1]) ^ mul(0x0b, state[i*4+2]) ^ mul(0x0d, state[i*4+3])
		tmp[i*4+2] = mul(0x0d, state[i*4]) ^ mul(0x09, state[i*4+1]) ^ mul(0x0e, state[i*4+2]) ^ mul(0x0b, state[i*4+3])
		tmp[i*4+3] = mul(0x0b, state[i*4]) ^ mul(0x0d, state[i*4+1]) ^ mul(0x09, state[i*4+2]) ^ mul(0x0e, state[i*4+3])
	}
	copy(state, tmp)
}

func addRoundKey(state []byte, word []uint32) {
	addrktmp := make([]byte, 16)
	binary.BigEndian.PutUint32(addrktmp[0:4], word[0])
	binary.BigEndian.PutUint32(addrktmp[4:8], word[1])
	binary.BigEndian.PutUint32(addrktmp[8:12], word[2])
	binary.BigEndian.PutUint32(addrktmp[12:16], word[3])
	for i := 0; i < len(state); i++ {
		state[i] ^= addrktmp[i]
	}
}

func nr(word []uint32) int {
	return len(word)/nb - 1
}

func cipher(input, out []byte, word []uint32) {
	if len(input) != 4*nb {
		panic("invalid length")
	}
	if len(out) != 4*nb {
		panic("invalid length")
	}

	nr := nr(word)

	state := make([]byte, 16)
	copy(state, input)

	addRoundKey(state, word[0:nb])
	for i := 1; i < nr; i++ {
		subBytes(state)
		shiftRows(state)
		mixColumns(state)
		addRoundKey(state, word[i*nb:(i+1)*nb]) // (i+1)*nb = i*nb + nb
	}
	subBytes(state)
	shiftRows(state)
	addRoundKey(state, word[nr*nb:(nr+1)*nb]) // (nr+1)*nb = nr*nb + nb

	// result
	copy(out, state)
}

func invCipher(input, out []byte, word []uint32) {
	if len(input) != 4*nb {
		panic("invalid length")
	}
	if len(out) != 4*nb {
		panic("invalid length")
	}

	nr := nr(word)

	state := make([]byte, 16)
	copy(state, input)

	addRoundKey(state, word[nr*nb:(nr+1)*nb]) // (nr+1)*nb = nr*nb + nb
	for i := nr - 1; i > 0; i-- {
		invShiftRows(state)
		invSubBytes(state)
		addRoundKey(state, word[i*nb:(i+1)*nb]) // (i+1)*nb = i*nb + nb
		invMixColumns(state)
	}
	invShiftRows(state)
	invSubBytes(state)
	addRoundKey(state, word[0:nb])
	// result
	copy(out, state)
}

func rotWord(w uint32) uint32 { return w<<8 | w>>24 }

func subWord(w uint32) uint32 {
	sbwtmp := make([]byte, 4)
	binary.BigEndian.PutUint32(sbwtmp, w)
	subBytes(sbwtmp)
	return binary.BigEndian.Uint32(sbwtmp)
}

func keyExpansion(key []byte, word []uint32) {
	nk := len(key) / 4 // 4,6,8
	for i := 0; i < nk; i++ {
		word[i] = binary.BigEndian.Uint32(key[4*i : 4*(i+1)])
	}
	nr := nr(word)
	for i := nk; i < nb*(nr+1); i++ {
		tmp := word[i-1]
		switch {
		case i%nk == 0:
			afterRot := rotWord(tmp)
			afterSub := subWord(afterRot)
			rcon := (uint32(powx[i/nk-1]) << 24) // TODO ここの計算について再確認
			tmp = afterSub ^ rcon
		case nk > 6 && i%nk == 4:
			tmp = subWord(tmp)
		default:
		}
		word[i] = word[i-nk] ^ tmp
	}
}

var _ ccipher.Block = (*toyAES)(nil)

type toyAES struct {
	word []uint32
}

// BlockSize implements cipher.Block
func (*toyAES) BlockSize() int { return 16 }

func NewToyAES(key []byte) *toyAES {
	nk := len(key) / 4 // 4,6,8
	var nr int
	switch nk {
	case 4:
		nr = 10
	case 6:
		nr = 12
	case 8:
		nr = 14
	default:
		panic("invalid key length")
	}
	word := make([]uint32, nb*(nr+1))
	keyExpansion(key, word)
	return &toyAES{
		word: word,
	}
}

func (c *toyAES) Encrypt(dst, src []byte) {
	cipher(src, dst, c.word)
}

func (c *toyAES) Decrypt(dst, src []byte) {
	invCipher(src, dst, c.word)
}
