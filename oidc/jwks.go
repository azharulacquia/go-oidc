package oidc

import (
	"context"
	"crypto/rsa"
	"sync"
	"time"

	"github.com/kataras/jwt"
)

// NewStaticKeySet returns a KeySet that can validate JSON web tokens by using static public keys
func NewStaticKeySet(ctx context.Context, publicKey string) *StaticKeySet {
	return newStaticKeySet(ctx, publicKey, time.Now)
}

func newStaticKeySet(ctx context.Context, publicKey string, now func() time.Time) *StaticKeySet {
	if now == nil {
		now = time.Now
	}
	//parse keys
	parsedKey, _ := jwt.ParsePublicKeyRSA([]byte(publicKey))
	return &StaticKeySet{ctx: cloneContext(ctx), now: now, cachedKey: parsedKey}
}

// StaticKeySet is a KeySet implementation that validates JSON web tokens
type StaticKeySet struct {
	ctx     context.Context
	now     func() time.Time

	// guard all other fields
	mu sync.RWMutex

	// A cached key.
	cachedKey *rsa.PublicKey
}

// VerifySignature validates a payload against a signature
func (r *StaticKeySet) VerifySignature(ctx context.Context, token string) ([]byte, error) {
	verifiedToken, err := jwt.Verify(jwt.RS256, r.cachedKey, []byte(token))
	if err != nil {
		return nil, err
	}

	return verifiedToken.Payload, nil
}

