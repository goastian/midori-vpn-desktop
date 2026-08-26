//go:build linux

package devicepki

import (
	"errors"
	"fmt"
	"sync"

	"github.com/godbus/dbus/v5"
)

const (
	secretServiceName       = "org.freedesktop.secrets"
	secretServicePath       = dbus.ObjectPath("/org/freedesktop/secrets")
	secretServiceIface      = "org.freedesktop.Secret.Service"
	secretDefaultCollection = dbus.ObjectPath("/org/freedesktop/secrets/aliases/default")
	secretCollectionIface   = "org.freedesktop.Secret.Collection"
	secretItemIface         = "org.freedesktop.Secret.Item"
)

type secretValue struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// Store persists private device credentials exclusively in Secret Service.
// It intentionally has no plaintext or locally decryptable file fallback.
type Store struct {
	mu      sync.Mutex
	conn    *dbus.Conn
	service dbus.BusObject
	session dbus.ObjectPath
}

func NewStore() (*Store, error) {
	conn, err := dbus.SessionBus()
	if err != nil {
		return nil, fmt.Errorf("connect to Secret Service session bus: %w", err)
	}
	store := &Store{conn: conn, service: conn.Object(secretServiceName, secretServicePath)}
	var output dbus.Variant
	if err := store.service.Call(secretServiceIface+".OpenSession", 0, "plain", dbus.MakeVariant("")).Store(&output, &store.session); err != nil {
		return nil, fmt.Errorf("open Secret Service session: %w", err)
	}
	if store.session == "" || store.session == "/" {
		return nil, errors.New("secret service returned no session")
	}
	return store, nil
}

func credentialAttrs(serverID string) map[string]string {
	return map[string]string{"service": "midorivpn", "type": "device-certificate", "server-id": serverID}
}

func (s *Store) Save(credential Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	plaintext, err := encodeCredential(credential)
	if err != nil {
		return err
	}
	secret := secretValue{Session: s.session, Parameters: []byte{}, Value: plaintext, ContentType: "application/json"}
	properties := map[string]dbus.Variant{
		secretItemIface + ".Label":      dbus.MakeVariant("MidoriVPN device certificate"),
		secretItemIface + ".Attributes": dbus.MakeVariant(credentialAttrs(credential.ServerID)),
	}
	collection := s.conn.Object(secretServiceName, secretDefaultCollection)
	var item, prompt dbus.ObjectPath
	if err := collection.Call(secretCollectionIface+".CreateItem", 0, properties, secret, true).Store(&item, &prompt); err != nil {
		return fmt.Errorf("save device credential in Secret Service: %w", err)
	}
	return requireNoPrompt(prompt)
}

func (s *Store) Load(serverID string) (Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items, err := s.searchUnlockedItems(serverID)
	if err != nil {
		return Credential{}, err
	}
	if len(items) == 0 {
		return Credential{}, ErrNotFound
	}
	var secrets map[dbus.ObjectPath]secretValue
	if err := s.service.Call(secretServiceIface+".GetSecrets", 0, items, s.session).Store(&secrets); err != nil {
		return Credential{}, fmt.Errorf("read device credential from Secret Service: %w", err)
	}
	for _, item := range items {
		secret, ok := secrets[item]
		if !ok || len(secret.Value) == 0 {
			continue
		}
		credential, err := decodeCredential(secret.Value)
		if err != nil {
			return Credential{}, fmt.Errorf("decode device credential: %w", err)
		}
		return credential, nil
	}
	return Credential{}, ErrNotFound
}

func (s *Store) Delete(serverID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlocked, locked, err := s.searchItems(serverID)
	if err != nil {
		return err
	}
	for _, item := range append(unlocked, locked...) {
		var prompt dbus.ObjectPath
		if err := s.conn.Object(secretServiceName, item).Call(secretItemIface+".Delete", 0).Store(&prompt); err != nil {
			return fmt.Errorf("delete device credential from Secret Service: %w", err)
		}
		if err := requireNoPrompt(prompt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) searchUnlockedItems(serverID string) ([]dbus.ObjectPath, error) {
	unlocked, locked, err := s.searchItems(serverID)
	if err != nil || len(locked) == 0 {
		return unlocked, err
	}
	var unlockedAfter []dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := s.service.Call(secretServiceIface+".Unlock", 0, locked).Store(&unlockedAfter, &prompt); err != nil {
		return nil, fmt.Errorf("unlock device credential: %w", err)
	}
	if err := requireNoPrompt(prompt); err != nil {
		return nil, err
	}
	return append(unlocked, unlockedAfter...), nil
}

func (s *Store) searchItems(serverID string) ([]dbus.ObjectPath, []dbus.ObjectPath, error) {
	var unlocked, locked []dbus.ObjectPath
	err := s.service.Call(secretServiceIface+".SearchItems", 0, credentialAttrs(serverID)).Store(&unlocked, &locked)
	if err != nil {
		err = fmt.Errorf("search device credential in Secret Service: %w", err)
	}
	return unlocked, locked, err
}

func requireNoPrompt(prompt dbus.ObjectPath) error {
	if prompt == "" || prompt == "/" {
		return nil
	}
	return fmt.Errorf("secret service prompt required: %s", prompt)
}
