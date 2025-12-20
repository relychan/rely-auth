package jwt

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/relychan/gohttpc"
	"golang.org/x/sync/singleflight"
)

// JWKStore represents a global JWT store structure.
type JWKStore struct {
	// inflight suppresses parallel execution of updateKeys and allows
	// multiple goroutines to wait for its result.
	inflight *singleflight.Group
	// Set of JWKS map.
	jwks map[string]*JWKS
	// The default http client to fetch JWKs.
	httpClient *gohttpc.Client

	locker sync.RWMutex
}

var globalJWKStore = JWKStore{
	inflight:   &singleflight.Group{},
	jwks:       map[string]*JWKS{},
	httpClient: gohttpc.NewClient(),
}

func (j *JWKStore) getJWKs() map[string]*JWKS {
	j.locker.RLock()
	defer j.locker.RUnlock()

	// Return a copy of the internal map to avoid exposing shared mutable state.
	copied := make(map[string]*JWKS, len(j.jwks))

	for k, v := range j.jwks {
		copied[k] = v
	}

	return copied
}

func (j *JWKStore) getJWK(key string) *JWKS {
	j.locker.RLock()
	defer j.locker.RUnlock()

	return j.jwks[key]
}

func (j *JWKStore) setJWK(key string, value *JWKS) {
	j.locker.Lock()
	defer j.locker.Unlock()

	j.jwks[key] = value
}

func (j *JWKStore) deleteJWK(key string) {
	j.locker.Lock()
	defer j.locker.Unlock()

	delete(j.jwks, key)
}

// RegisterJWKS registers a JWK secret key to the global store.
func RegisterJWKS(ctx context.Context, jwksURL string, httpClient *gohttpc.Client) (*JWKS, error) {
	trimmedURL := strings.TrimRight(jwksURL, "/")
	if trimmedURL == "" {
		return nil, ErrJWKsURLRequired
	}

	keyset, err, _ := globalJWKStore.inflight.Do(trimmedURL, func() (any, error) {
		jwk := globalJWKStore.getJWK(trimmedURL)
		if jwk != nil {
			return jwk, nil
		}

		if httpClient == nil {
			httpClient = globalJWKStore.httpClient
		}

		jwk = &JWKS{
			url:        trimmedURL,
			httpClient: httpClient,
			inflight:   globalJWKStore.inflight,
		}

		// fetch JSON web key to validate if the JWK URL is valid.
		_, err := jwk.keysFromRemote(ctx)
		if err != nil {
			return nil, err
		}

		globalJWKStore.setJWK(trimmedURL, jwk)

		return jwk, nil
	})
	if err != nil {
		return nil, err
	}

	result, ok := keyset.(*JWKS)
	if !ok {
		return nil, ErrGetJWKsFailed
	}

	return result, nil
}

// GetJWKSCount gets the current number of JWKS instances from the global store.
func GetJWKSCount() int {
	return len(globalJWKStore.getJWKs())
}

// ReloadJWKS reload JSON web key sets from the global store.
func ReloadJWKS(ctx context.Context) error {
	errs := []error{}

	for _, jwk := range globalJWKStore.getJWKs() {
		_, err := jwk.keysFromRemoteInflight(ctx)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// ResetJWKStore clears all existing JSON web keys from the global store.
func ResetJWKStore() {
	globalJWKStore.locker.Lock()
	defer globalJWKStore.locker.Unlock()

	globalJWKStore.jwks = map[string]*JWKS{}
}

// UnregisterJWKS removes a JSON web key set from the global store if exists.
func UnregisterJWKS(key string) {
	globalJWKStore.deleteJWK(key)
}
