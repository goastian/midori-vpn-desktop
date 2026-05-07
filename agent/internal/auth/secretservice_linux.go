//go:build linux

package auth

import (
	"encoding/json"
	"errors"
	"fmt"

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

var secretAttrs = map[string]string{
	"service": "midorivpn",
	"type":    "oauth-tokens",
}

type secretServiceStore struct {
	conn    *dbus.Conn
	service dbus.BusObject
	session dbus.ObjectPath
}

type secretValue struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

func newSecretServiceStore() Store {
	conn, err := dbus.SessionBus()
	if err != nil {
		return nil
	}
	store := &secretServiceStore{
		conn:    conn,
		service: conn.Object(secretServiceName, secretServicePath),
	}
	if err := store.openSession(); err != nil {
		return nil
	}
	return store
}

func (s *secretServiceStore) openSession() error {
	var output dbus.Variant
	var session dbus.ObjectPath
	if err := s.service.Call(secretServiceIface+".OpenSession", 0, "plain", dbus.MakeVariant("")).Store(&output, &session); err != nil {
		return err
	}
	if session == "" || session == "/" {
		return errors.New("secret service returned no session")
	}
	s.session = session
	return nil
}

func (s *secretServiceStore) Save(t Tokens) error {
	if t.IsZero() {
		return fmt.Errorf("auth: refusing to save empty tokens")
	}
	plaintext, err := json.Marshal(t)
	if err != nil {
		return err
	}

	secret := secretValue{
		Session:     s.session,
		Parameters:  []byte{},
		Value:       plaintext,
		ContentType: "application/json",
	}
	properties := map[string]dbus.Variant{
		secretItemIface + ".Label":      dbus.MakeVariant("MidoriVPN OAuth tokens"),
		secretItemIface + ".Attributes": dbus.MakeVariant(secretAttrs),
	}

	collection := s.conn.Object(secretServiceName, secretDefaultCollection)
	var item dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := collection.Call(secretCollectionIface+".CreateItem", 0, properties, secret, true).Store(&item, &prompt); err != nil {
		return err
	}
	return requireNoPrompt(prompt)
}

func (s *secretServiceStore) Load() (Tokens, error) {
	items, err := s.searchUnlockedItems()
	if err != nil {
		return Tokens{}, err
	}
	if len(items) == 0 {
		return Tokens{}, ErrNotFound
	}

	var secrets map[dbus.ObjectPath]secretValue
	if err := s.service.Call(secretServiceIface+".GetSecrets", 0, items, s.session).Store(&secrets); err != nil {
		return Tokens{}, err
	}
	for _, item := range items {
		secret, ok := secrets[item]
		if !ok || len(secret.Value) == 0 {
			continue
		}
		var t Tokens
		if err := json.Unmarshal(secret.Value, &t); err != nil {
			return Tokens{}, err
		}
		if t.IsZero() {
			return Tokens{}, ErrNotFound
		}
		return t, nil
	}
	return Tokens{}, ErrNotFound
}

func (s *secretServiceStore) Clear() error {
	unlocked, locked, err := s.searchItems()
	if err != nil {
		return err
	}
	items := append(unlocked, locked...)
	for _, item := range items {
		var prompt dbus.ObjectPath
		obj := s.conn.Object(secretServiceName, item)
		if err := obj.Call(secretItemIface+".Delete", 0).Store(&prompt); err != nil {
			return err
		}
		if err := requireNoPrompt(prompt); err != nil {
			return err
		}
	}
	return nil
}

func (*secretServiceStore) Backend() string { return "secret-service" }

func (s *secretServiceStore) searchUnlockedItems() ([]dbus.ObjectPath, error) {
	unlocked, locked, err := s.searchItems()
	if err != nil {
		return nil, err
	}
	if len(locked) == 0 {
		return unlocked, nil
	}

	var unlockedAfter []dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := s.service.Call(secretServiceIface+".Unlock", 0, locked).Store(&unlockedAfter, &prompt); err != nil {
		return nil, err
	}
	if err := requireNoPrompt(prompt); err != nil {
		return nil, err
	}
	return append(unlocked, unlockedAfter...), nil
}

func (s *secretServiceStore) searchItems() ([]dbus.ObjectPath, []dbus.ObjectPath, error) {
	var unlocked []dbus.ObjectPath
	var locked []dbus.ObjectPath
	err := s.service.Call(secretServiceIface+".SearchItems", 0, secretAttrs).Store(&unlocked, &locked)
	return unlocked, locked, err
}

func requireNoPrompt(prompt dbus.ObjectPath) error {
	if prompt == "" || prompt == "/" {
		return nil
	}
	return fmt.Errorf("secret service prompt required: %s", prompt)
}
