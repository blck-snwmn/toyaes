package toyaes

import (
	"crypto/aes"
	ccipher "crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"reflect"
	"testing"
)

func Test_genCounter(t *testing.T) {
	nonce := []byte{
		0x00,
		0x01,
		0x02,
		0x03,
		0x04,
		0x05,
		0x06,
		0x07,
		0x08,
		0x09,
		0x0A,
		0x0B,
	}
	c := genCounter(nonce)
	want := [16]byte{
		0x00,
		0x01,
		0x02,
		0x03,
		0x04,
		0x05,
		0x06,
		0x07,
		0x08,
		0x09,
		0x0A,
		0x0B,
		0x00,
		0x00,
		0x00,
		0x01,
	}
	if !reflect.DeepEqual(c, want) {
		t.Errorf("unexpected value. want=%v, got=%v", want, c)
	}
}

func Test_incrementCounter(t *testing.T) {
	nonce := []byte{
		0x00,
		0x01,
		0x02,
		0x03,
		0x04,
		0x05,
		0x06,
		0x07,
		0x08,
		0x09,
		0x0A,
		0x0B,
	}
	t.Run("last 4 bytes is 1 when increment once", func(t *testing.T) {
		c := incrementCounter(genCounter(nonce))
		want := [16]byte{
			0x00,
			0x01,
			0x02,
			0x03,
			0x04,
			0x05,
			0x06,
			0x07,
			0x08,
			0x09,
			0x0A,
			0x0B,
			0x00,
			0x00,
			0x00,
			0x02,
		}
		if !reflect.DeepEqual(c, want) {
			t.Errorf("unexpected value. want=%v, got=%v", want, c)
		}
	})

	t.Run("last 4 bytes is 100 when increment 100 times", func(t *testing.T) {
		c := genCounter(nonce)
		for i := 0; i < 1000; i++ {
			c = incrementCounter(c)
		}
		want := [16]byte{
			0x00,
			0x01,
			0x02,
			0x03,
			0x04,
			0x05,
			0x06,
			0x07,
			0x08,
			0x09,
			0x0A,
			0x0B,
			0x00,
			0x00,
			0x03,
			0xE9,
		}
		if !reflect.DeepEqual(c, want) {
			t.Errorf("unexpected value. want=%v, got=%v", want, c)
		}
	})
}

func Test_enc(t *testing.T) {
	nonce := []byte{
		0x00,
		0xAA,
		0x02,
		0x03,
		0x04,
		0x05,
		0x06,
		0x07,
		0x08,
		0x09,
		0x0A,
		0x0B,
	}
	plaintext := []byte("sample text. this text is test text.")
	key, _ := hex.DecodeString("000102030405060708090A0B0C0E0F101112131415161718191A1B1C1E1F2021")
	gcm := &toyAESGCM{cipher: NewToyAES(key), key: key}
	ct := gcm.enc(plaintext, nonce)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	c := genCounter(nonce)
	ctr := ccipher.NewCTR(block, c[:])
	want := make([]byte, len(plaintext))
	ctr.XORKeyStream(want, plaintext)
	if !reflect.DeepEqual(ct, want) {
		t.Errorf("invalid ciphertext. want=%v, got=%v", want, ct)
	}
}

func Test_encWitchCounter(t *testing.T) {
	nonce := []byte{
		0x00,
		0xAA,
		0x02,
		0x03,
		0x04,
		0x05,
		0x06,
		0x07,
		0x08,
		0x09,
		0x0A,
		0x0B,
	}
	plaintext := []byte("sample text. this text is test text.")
	key, _ := hex.DecodeString("000102030405060708090A0B0C0E0F101112131415161718191A1B1C1E1F2021")
	cc := genCounter(nonce)
	incrementCounter(cc)

	gcm := &toyAESGCM{cipher: NewToyAES(key), key: key}
	ct := gcm.encWitchCounter(plaintext, nonce, cc)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	c := genCounter(nonce)
	incrementCounter(c)
	ctr := ccipher.NewCTR(block, c[:])
	want := make([]byte, len(plaintext))
	ctr.XORKeyStream(want, plaintext)
	if !reflect.DeepEqual(ct, want) {
		t.Errorf("invalid ciphertext. want=%v, got=%v", want, ct)
	}
}

func Test_mulg(t *testing.T) {
	type args struct {
		lhs uint128
		rhs uint128
	}
	tests := []struct {
		name string
		args args
		want uint128
	}{
		{
			"1*1",
			args{
				uint128{0x8000000000000000, 0x0000000000000000},
				uint128{0x8000000000000000, 0x0000000000000000},
			},
			uint128{0x8000000000000000, 0x0000000000000000},
		},
		{
			"0*1",
			args{
				uint128{0x0000000000000000, 0x0000000000000000},
				uint128{0x8000000000000000, 0x0000000000000000},
			},
			uint128{0x0000000000000000, 0x0000000000000000},
		},
		{
			"1*0",
			args{
				uint128{0x8000000000000000, 0x0000000000000000},
				uint128{0x0000000000000000, 0x0000000000000000},
			},
			uint128{0x0000000000000000, 0x0000000000000000},
		},
		{
			"0*0",
			args{
				uint128{0x0000000000000000, 0x0000000000000000},
				uint128{0x0000000000000000, 0x0000000000000000},
			},
			uint128{0x0000000000000000, 0x0000000000000000},
		},
		{
			"overflow: (x+1)*(x^127+1)",
			args{
				uint128{0xC000000000000000, 0x0000000000000000},
				uint128{0x8000000000000000, 0x0000000000000001},
			},
			uint128{0x2100000000000000, 0x0000000000000001},
		},
		{
			"overflow: (x^127+1)*(x+1)",
			args{
				uint128{0x8000000000000000, 0x0000000000000001},
				uint128{0xC000000000000000, 0x0000000000000000},
			},
			uint128{0x2100000000000000, 0x0000000000000001},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mulg(tt.args.lhs, tt.args.rhs); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mul() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSeal(t *testing.T) {
	var (
		key            = make([]byte, 32)
		plaintext      = make([]byte, 32)
		nonce          = make([]byte, 12)
		additionalData = make([]byte, 12)
	)

	for i := 0; i < 1000; i++ {
		rand.Read(key)
		rand.Read(plaintext)
		rand.Read(nonce)
		rand.Read(additionalData)

		aeadm := NewAESGCM(key)
		got := aeadm.Seal(nil, nonce, plaintext, additionalData)

		aesb, _ := aes.NewCipher(key)
		aead, _ := ccipher.NewGCM(aesb)
		want := aead.Seal(nil, nonce, plaintext, additionalData)

		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got =%X, want=%X\n", got, want)
		}
	}
}

func TestOpen(t *testing.T) {
	var (
		key            = make([]byte, 32)
		plaintext      = make([]byte, 32)
		nonce          = make([]byte, 12)
		additionalData = make([]byte, 12)
	)
	for i := 0; i < 1000; i++ {
		rand.Read(key)
		rand.Read(plaintext)
		rand.Read(nonce)
		rand.Read(additionalData)

		aead := NewAESGCM(key)
		ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
		p, err := aead.Open(nil, nonce, ciphertext, additionalData)
		if err != nil {
			t.Fatalf("err=%+v", err)
		}
		if !reflect.DeepEqual(p, plaintext) {
			t.Fatalf("got =%X, want=%X\n", p, plaintext)
		}
	}
}
