package deviceidentity

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unicode"
)

const (
	stateSchemaVersion = 1
	stateFilename      = "device-identity.json"
	stateMaxBytes      = 16 << 10
	fingerprintContext = "midorivpn-adapter-v1"

	DeviceTypeDesktop = "desktop"
)

type AdapterKind string

const (
	AdapterKindEthernet AdapterKind = "ethernet"
	AdapterKindWiFi     AdapterKind = "wifi"
)

type Identity struct {
	ClientInstanceID string
	ReportedName     string
	Alias            string
	DeviceType       string
	AdapterReference string
	AdapterKind      AdapterKind
}

func (i Identity) DisplayName() string {
	if i.Alias != "" {
		return i.Alias
	}
	return i.ReportedName
}

type persistedState struct {
	SchemaVersion    int    `json:"schema_version"`
	ClientInstanceID string `json:"client_instance_id"`
	LocalHMACKey     string `json:"local_hmac_key"`
	ReportedName     string `json:"reported_name"`
	Alias            string `json:"alias,omitempty"`
}

type dependencies struct {
	hostname      func() (string, error)
	interfaces    func() ([]net.Interface, error)
	defaultRoutes func() []string
	classify      func(string) (AdapterKind, bool)
	random        io.Reader
}

type Store struct {
	mu               sync.Mutex
	path             string
	clientInstanceID string
	reportedName     string
	alias            string
	localHMACKey     [32]byte
	deps             dependencies
}

func New() (*Store, error) {
	dir, err := defaultStateDir()
	if err != nil {
		return nil, err
	}
	return open(dir, productionDependencies())
}

func open(dir string, deps dependencies) (*Store, error) {
	if err := ensurePrivateDir(dir); err != nil {
		return nil, fmt.Errorf("prepare device identity directory: %w", err)
	}

	store := &Store{
		path: filepath.Join(dir, stateFilename),
		deps: deps,
	}
	if err := store.loadOrCreate(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) Current() (Identity, error) {
	s.mu.Lock()
	if hostname, err := s.deps.hostname(); err == nil {
		reportedName := sanitizeReportedName(hostname)
		if reportedName != s.reportedName {
			previous := s.reportedName
			s.reportedName = reportedName
			if err := s.saveLocked(); err != nil {
				s.reportedName = previous
				s.mu.Unlock()
				return Identity{}, fmt.Errorf("persist updated device hostname: %w", err)
			}
		}
	}

	identity := Identity{
		ClientInstanceID: s.clientInstanceID,
		ReportedName:     s.reportedName,
		Alias:            s.alias,
		DeviceType:       DeviceTypeDesktop,
	}
	key := s.localHMACKey
	s.mu.Unlock()

	adapter, ok := selectAdapter(s.deps)
	if ok {
		identity.AdapterKind = adapter.kind
		identity.AdapterReference = adapterReference(key[:], adapter.hardwareAddr)
	}
	return identity, nil
}

func (s *Store) SetAlias(alias string) error {
	alias = sanitizeAlias(alias)

	s.mu.Lock()
	defer s.mu.Unlock()
	if alias == s.alias {
		return nil
	}
	previous := s.alias
	s.alias = alias
	if err := s.saveLocked(); err != nil {
		s.alias = previous
		return fmt.Errorf("persist device alias: %w", err)
	}
	return nil
}

func (s *Store) loadOrCreate() error {
	state, err := readState(s.path)
	if err == nil {
		key, decodeErr := base64.RawURLEncoding.DecodeString(state.LocalHMACKey)
		if decodeErr != nil || len(key) != len(s.localHMACKey) {
			return errors.New("device identity contains an invalid local HMAC key")
		}
		if !validUUIDv4(state.ClientInstanceID) {
			return errors.New("device identity contains an invalid client instance ID")
		}
		if state.SchemaVersion != stateSchemaVersion {
			return fmt.Errorf("unsupported device identity schema version %d", state.SchemaVersion)
		}
		if state.ReportedName == "" || state.ReportedName != sanitizeReportedName(state.ReportedName) {
			return errors.New("device identity contains an invalid reported name")
		}
		if state.Alias != sanitizeAlias(state.Alias) {
			return errors.New("device identity contains an invalid alias")
		}

		s.clientInstanceID = state.ClientInstanceID
		s.reportedName = state.ReportedName
		s.alias = state.Alias
		copy(s.localHMACKey[:], key)
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("load device identity: %w", err)
	}

	clientInstanceID, err := newUUIDv4(s.deps.random)
	if err != nil {
		return fmt.Errorf("generate client instance ID: %w", err)
	}
	if _, err := io.ReadFull(s.deps.random, s.localHMACKey[:]); err != nil {
		return fmt.Errorf("generate local device identity key: %w", err)
	}
	hostname, err := s.deps.hostname()
	if err != nil {
		hostname = ""
	}
	s.clientInstanceID = clientInstanceID
	s.reportedName = sanitizeReportedName(hostname)
	if err := s.saveLocked(); err != nil {
		return fmt.Errorf("create device identity: %w", err)
	}
	return nil
}

func (s *Store) saveLocked() error {
	state := persistedState{
		SchemaVersion:    stateSchemaVersion,
		ClientInstanceID: s.clientInstanceID,
		LocalHMACKey:     base64.RawURLEncoding.EncodeToString(s.localHMACKey[:]),
		ReportedName:     s.reportedName,
		Alias:            s.alias,
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeFileAtomic(s.path, data)
}

func defaultStateDir() (string, error) {
	if stateHome := os.Getenv("XDG_STATE_HOME"); stateHome != "" {
		if !filepath.IsAbs(stateHome) {
			return "", errors.New("XDG_STATE_HOME must be an absolute path")
		}
		return filepath.Join(stateHome, "midorivpn"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home directory: %w", err)
	}
	return filepath.Join(home, ".local", "state", "midorivpn"), nil
}

func productionDependencies() dependencies {
	return dependencies{
		hostname:      os.Hostname,
		interfaces:    net.Interfaces,
		defaultRoutes: systemDefaultRouteInterfaces,
		classify:      classifySystemInterface,
		random:        rand.Reader,
	}
}

func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("device identity path is not a directory")
	}
	return os.Chmod(dir, 0o700)
}

func readState(path string) (persistedState, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return persistedState{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return persistedState{}, errors.New("device identity file is not a regular file")
	}
	if info.Size() > stateMaxBytes {
		return persistedState{}, errors.New("device identity file is too large")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return persistedState{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return persistedState{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state persistedState
	if err := decoder.Decode(&state); err != nil {
		return persistedState{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return persistedState{}, errors.New("device identity file contains trailing data")
		}
		return persistedState{}, err
	}
	return state, nil
}

func writeFileAtomic(path string, data []byte) (returnErr error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".device-identity-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	closed := false
	defer func() {
		_ = os.Remove(tmpName)
	}()
	defer func() {
		if !closed {
			if closeErr := tmp.Close(); returnErr == nil && closeErr != nil {
				returnErr = closeErr
			}
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	closed = true
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	dirFile, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer dirFile.Close()
	return dirFile.Sync()
}

func newUUIDv4(reader io.Reader) (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(reader, value[:]); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func validUUIDv4(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' || value != strings.ToLower(value) {
		return false
	}
	compact := strings.ReplaceAll(value, "-", "")
	decoded, err := hex.DecodeString(compact)
	if err != nil || len(decoded) != 16 {
		return false
	}
	return decoded[6]&0xf0 == 0x40 && decoded[8]&0xc0 == 0x80
}

func sanitizeReportedName(value string) string {
	value = strings.TrimSpace(value)
	var builder strings.Builder
	separator := false
	for _, r := range value {
		allowed := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-'
		if !allowed {
			separator = builder.Len() > 0
			continue
		}
		if separator && builder.Len() < 64 {
			builder.WriteByte('-')
		}
		separator = false
		if builder.Len() >= 64 {
			break
		}
		builder.WriteRune(r)
	}
	result := strings.Trim(builder.String(), ".-_")
	if result == "" {
		return "linux-desktop"
	}
	return result
}

func sanitizeAlias(value string) string {
	value = strings.TrimSpace(value)
	var builder strings.Builder
	space := false
	count := 0
	for _, r := range value {
		if unicode.IsSpace(r) {
			space = builder.Len() > 0
			continue
		}
		if unicode.IsControl(r) {
			continue
		}
		if count >= 64 {
			break
		}
		if space {
			builder.WriteByte(' ')
			space = false
			count++
			if count >= 64 {
				break
			}
		}
		builder.WriteRune(r)
		count++
	}
	return strings.TrimSpace(builder.String())
}

type selectedAdapter struct {
	name         string
	kind         AdapterKind
	hardwareAddr net.HardwareAddr
}

func selectAdapter(deps dependencies) (selectedAdapter, bool) {
	interfaces, err := deps.interfaces()
	if err != nil {
		return selectedAdapter{}, false
	}
	candidates := make([]selectedAdapter, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || ignoredInterfaceName(iface.Name) || !validHardwareAddr(iface.HardwareAddr) {
			continue
		}
		kind, physical := deps.classify(iface.Name)
		if !physical || kind != AdapterKindEthernet && kind != AdapterKindWiFi {
			continue
		}
		candidates = append(candidates, selectedAdapter{
			name:         iface.Name,
			kind:         kind,
			hardwareAddr: append(net.HardwareAddr(nil), iface.HardwareAddr...),
		})
	}
	if len(candidates) == 0 {
		return selectedAdapter{}, false
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].name < candidates[j].name })
	byName := make(map[string]selectedAdapter, len(candidates))
	for _, candidate := range candidates {
		byName[candidate.name] = candidate
	}
	for _, name := range deps.defaultRoutes() {
		if candidate, ok := byName[name]; ok {
			return candidate, true
		}
	}
	return candidates[0], true
}

func validHardwareAddr(address net.HardwareAddr) bool {
	if len(address) != 6 || address[0]&1 != 0 {
		return false
	}
	allZero := true
	allFF := true
	for _, value := range address {
		allZero = allZero && value == 0
		allFF = allFF && value == 0xff
	}
	return !allZero && !allFF
}

func ignoredInterfaceName(name string) bool {
	name = strings.ToLower(name)
	prefixes := []string{
		"lo", "wg", "tun", "tap", "tailscale", "zt", "veth", "virbr", "docker",
		"podman", "cni", "br-", "bridge", "dummy", "ifb", "ip6tnl", "sit", "gre",
		"gretap", "erspan", "vxlan", "geneve", "bond", "bnep", "pan", "wwan", "rmnet",
	}
	for _, prefix := range prefixes {
		if name == prefix || strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func adapterReference(key []byte, hardwareAddr net.HardwareAddr) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(fingerprintContext))
	_, _ = mac.Write(hardwareAddr)
	return "net-v1:" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
