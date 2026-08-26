//go:build !linux

package devicepki

import "errors"

type Store struct{}

func NewStore() (*Store, error) {
	return nil, errors.New("secure device certificate storage is unavailable")
}
func (*Store) Save(Credential) error {
	return errors.New("secure device certificate storage is unavailable")
}
func (*Store) Load(string) (Credential, error) { return Credential{}, ErrNotFound }
func (*Store) Delete(string) error             { return nil }
