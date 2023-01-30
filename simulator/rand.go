package main

import (
	"crypto/rand"
	"encoding/binary"
	"math/bits"
)

func randUint32() uint32 {
	b := make([]byte, 4)
	rand.Read(b[:])
	return binary.LittleEndian.Uint32(b)
}

func randUint32n(n uint32) uint32 {
	if n < 2 {
		return 0
	}
	n--
	mask := ^uint32(0) >> bits.LeadingZeros32(n)
	for {
		v := randUint32() & mask
		if v <= n {
			return v
		}
	}
}

func randSliceElem[S ~[]E, E any](s S) E {
	return s[randUint32n(uint32(len(s)))]
}
