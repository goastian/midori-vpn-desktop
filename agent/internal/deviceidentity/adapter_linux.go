package deviceidentity

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const sysClassNet = "/sys/class/net"

func classifySystemInterface(name string) (AdapterKind, bool) {
	if name == "" || filepath.Base(name) != name || ignoredInterfaceName(name) {
		return "", false
	}
	classPath := filepath.Join(sysClassNet, name)
	resolved, err := filepath.EvalSymlinks(classPath)
	if err != nil || strings.Contains(filepath.ToSlash(resolved), "/virtual/net/") {
		return "", false
	}
	deviceInfo, err := os.Stat(filepath.Join(classPath, "device"))
	if err != nil || !deviceInfo.IsDir() {
		return "", false
	}
	if wirelessInfo, err := os.Stat(filepath.Join(classPath, "wireless")); err == nil && wirelessInfo.IsDir() {
		return AdapterKindWiFi, true
	}
	typeValue, err := os.ReadFile(filepath.Join(classPath, "type"))
	if err != nil || strings.TrimSpace(string(typeValue)) != "1" {
		return "", false
	}
	return AdapterKindEthernet, true
}

type routeCandidate struct {
	name   string
	metric uint64
}

func systemDefaultRouteInterfaces() []string {
	routes := make([]routeCandidate, 0, 4)
	if file, err := os.Open("/proc/net/route"); err == nil {
		routes = append(routes, parseIPv4DefaultRoutes(file)...)
		_ = file.Close()
	}
	if file, err := os.Open("/proc/net/ipv6_route"); err == nil {
		routes = append(routes, parseIPv6DefaultRoutes(file)...)
		_ = file.Close()
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].metric == routes[j].metric {
			return routes[i].name < routes[j].name
		}
		return routes[i].metric < routes[j].metric
	})

	seen := make(map[string]struct{}, len(routes))
	result := make([]string, 0, len(routes))
	for _, route := range routes {
		if _, ok := seen[route.name]; ok {
			continue
		}
		seen[route.name] = struct{}{}
		result = append(result, route.name)
	}
	return result
}

func parseIPv4DefaultRoutes(reader io.Reader) []routeCandidate {
	return scanDefaultRoutes(reader, func(fields []string) (routeCandidate, bool) {
		if len(fields) < 8 || fields[1] != "00000000" || fields[7] != "00000000" {
			return routeCandidate{}, false
		}
		flags, err := strconv.ParseUint(fields[3], 16, 64)
		if err != nil || flags&1 == 0 {
			return routeCandidate{}, false
		}
		metric, err := strconv.ParseUint(fields[6], 10, 64)
		if err != nil {
			return routeCandidate{}, false
		}
		return routeCandidate{name: fields[0], metric: metric}, true
	})
}

func parseIPv6DefaultRoutes(reader io.Reader) []routeCandidate {
	return scanDefaultRoutes(reader, func(fields []string) (routeCandidate, bool) {
		if len(fields) < 10 || fields[0] != strings.Repeat("0", 32) || fields[1] != "00" {
			return routeCandidate{}, false
		}
		flags, err := strconv.ParseUint(fields[8], 16, 64)
		if err != nil || flags&1 == 0 {
			return routeCandidate{}, false
		}
		metric, err := strconv.ParseUint(fields[5], 16, 64)
		if err != nil {
			return routeCandidate{}, false
		}
		return routeCandidate{name: fields[9], metric: metric}, true
	})
}

func scanDefaultRoutes(reader io.Reader, parse func([]string) (routeCandidate, bool)) []routeCandidate {
	scanner := bufio.NewScanner(reader)
	routes := make([]routeCandidate, 0, 2)
	for scanner.Scan() {
		if route, ok := parse(strings.Fields(scanner.Text())); ok {
			routes = append(routes, route)
		}
	}
	return routes
}
