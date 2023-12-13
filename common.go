package merkle

import (
	"encoding/hex"
	"hash"

	"golang.org/x/crypto/sha3"
)

const HashLength = 32

type Hash [HashLength]byte

func BytesToHash(b []byte) Hash {
	var h Hash

	size := len(b)
	min := Min(size, HashLength)

	copy(h[HashLength-min:], b[len(b)-min:])

	return h
}

func (h Hash) Bytes() []byte {
	return h[:]
}

func (h Hash) String() string {
	return EncodeToHex(h[:])
}

// KeccakState wraps sha3.state. In addition to the usual hash methods, it also supports
// Read to get a variable amount of data from the hash state. Read is faster than Sum
// because it doesn't copy the internal state, but also modifies the internal state.
type KeccakState interface {
	hash.Hash
	Read([]byte) (int, error)
}

// NewKeccakState creates a new KeccakState
func NewKeccakState() KeccakState {
	return sha3.NewLegacyKeccak256().(KeccakState) //nolint:forcetypeassert
}

// EncodeToHex generates a hex string based on the byte representation, with the '0x' prefix
func EncodeToHex(str []byte) string {
	return "0x" + hex.EncodeToString(str)
}

// Min returns smaller number between provided two
func Min(a, b int) int {
	if a < b {
		return a
	}

	return b
}
