package dcnet

import (
	"fmt"
	"strings"
	"testing"

	"decred.org/cspp/chacha20prng"
	"github.com/companyzero/sntrup4591761"
)

func TestPQKX(t *testing.T) {
	seed := make([]byte, 32)
	copy(seed, "TestPQKX")
	prng := chacha20prng.New(seed, 0)

	// 3 peers mixing 2 messages each
	const mcount = 2
	const mtot = 6
	type peer struct {
		pqkx        *PQKX
		ciphertexts [][]*PQCiphertext
	}
	peers := make([]peer, 3)

	// Generate public/secret keys
	publics := make([]*PQPublicKey, 0, mtot)
	for i := range peers {
		peers[i].pqkx = &PQKX{
			Secrets: make([]*PQSecretKey, 0, mcount),
		}
		secrets := &peers[i].pqkx.Secrets
		for j := 0; j < mcount; j++ {
			pk, sk, err := sntrup4591761.GenerateKey(prng)
			if err != nil {
				t.Fatal(err)
			}
			publics = append(publics, pk)
			*secrets = append(*secrets, sk)
		}
	}

	// Broadcast public keys
	for i := range peers {
		peers[i].pqkx.Publics = publics
	}

	// Encapsulate ciphertexts
	for i := range peers {
		start := i * mcount
		ciphertexts, err := peers[i].pqkx.Encapsulate(prng, start)
		if err != nil {
			t.Fatal(err)
		}
		peers[i].ciphertexts = ciphertexts
	}

	// Broadcast ciphertexts
	ciphertexts := make([][]*PQCiphertext, 0, mtot)
	for i := range peers {
		ciphertexts = append(ciphertexts, peers[i].ciphertexts...)
	}

	// Decapsulate ciphertexts
	for i := range peers {
		start := i * mcount
		err := peers[i].pqkx.Decapsulate(ciphertexts, start)
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("Peer %d shared keys:", i)
		t.Log(formatSharedKeys(peers[i].pqkx.SharedKeys))
	}

	t.Logf("%x\n", peers[0].pqkx.SharedKeys[0][1])
	t.Logf("%x\n", peers[0].pqkx.SharedKeys[1][0])
	t.Logf("%x\n", peers[1].pqkx.SharedKeys[0][1])
	t.Logf("%x\n", peers[1].pqkx.SharedKeys[1][0])

	// Ensure that every key pair has a unique shared key.
	type seenBy struct {
		m, k   int
		paired *bool
	}
	seenKeys := make(map[[32]byte]seenBy)
	for i := range peers {
		for j := 0; j < mcount; j++ {
			m := i*mcount + j

			for k := 0; k < mtot; k++ {
				key := &peers[i].pqkx.SharedKeys[j][k]
				if m == k {
					// Shared key here must be zero
					if *key != ([32]byte{}) {
						t.Errorf("identity key is not zero")
					}
					continue
				}

				// Shared key here may not be zero.
				if *key == ([32]byte{}) {
					t.Errorf("non-zero shared key")
					continue
				}

				// If this shared key was already seen, it must
				// be at the corresponding pair position
				// (reverse m and k).
				seen, ok := seenKeys[*key]
				if ok {
					if seen.m != k && seen.k != m {
						t.Errorf("found same shared key in wrong pos")
					}
					*seen.paired = true
					continue
				}

				// Record a newly seen, but unpaired key.
				seenKeys[*key] = seenBy{
					m:      m,
					k:      k,
					paired: new(bool),
				}
			}
		}
	}
	for k, v := range seenKeys {
		if !*v.paired {
			t.Errorf("no matching shared key found for %x", k)
		}
	}
}

func formatSharedKeys(keys [][][32]byte) string {
	b := new(strings.Builder)
	for i := range keys {
		b.WriteString("[")
		for j := range keys[i] {
			if j != 0 {
				b.WriteString(" ")
			}
			fmt.Fprintf(b, "%x", keys[i][j])
		}
		b.WriteString("]\n")
	}
	return b.String()
}
