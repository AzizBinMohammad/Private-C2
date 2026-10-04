package platform

type PlatformCapabilities struct {
	Transports []string
	Features   []string
	ImplantModes []string
}

var supportMatrix = map[string]map[string]PlatformCapabilities{
	"windows": {
		"amd64": {
			Transports:   []string{"mtls", "https", "http", "dns", "wireguard"},
			Features:     []string{"shell", "filesystem", "process", "network", "registry", "service", "screen", "pivoting", "injection"},
			ImplantModes: []string{"session", "beacon"},
		},
		"arm64": {
			Transports:   []string{"mtls", "https", "http", "dns", "wireguard"},
			Features:     []string{"shell", "filesystem", "process", "network", "registry", "service", "screen", "pivoting"},
			ImplantModes: []string{"session", "beacon"},
		},
		"386": {
			Transports:   []string{"mtls", "https", "http", "dns", "wireguard"},
			Features:     []string{"shell", "filesystem", "process", "network", "registry", "service", "screen"},
			ImplantModes: []string{"session", "beacon"},
		},
	},
	"linux": {
		"amd64": {
			Transports:   []string{"mtls", "https", "http", "dns", "wireguard"},
			Features:     []string{"shell", "filesystem", "process", "network", "pivoting", "injection"},
			ImplantModes: []string{"session", "beacon"},
		},
		"arm64": {
			Transports:   []string{"mtls", "https", "http", "dns", "wireguard"},
			Features:     []string{"shell", "filesystem", "process", "network", "pivoting"},
			ImplantModes: []string{"session", "beacon"},
		},
		"386": {
			Transports:   []string{"mtls", "https", "http", "dns"},
			Features:     []string{"shell", "filesystem", "process", "network"},
			ImplantModes: []string{"session", "beacon"},
		},
		"mips": {
			Transports:   []string{"mtls", "https", "http"},
			Features:     []string{"shell", "filesystem", "process", "network"},
			ImplantModes: []string{"session", "beacon"},
		},
		"mipsle": {
			Transports:   []string{"mtls", "https", "http"},
			Features:     []string{"shell", "filesystem", "process", "network"},
			ImplantModes: []string{"session", "beacon"},
		},
		"riscv64": {
			Transports:   []string{"mtls", "https", "http"},
			Features:     []string{"shell", "filesystem", "process", "network"},
			ImplantModes: []string{"session", "beacon"},
		},
	},
	"darwin": {
		"amd64": {
			Transports:   []string{"mtls", "https", "http", "dns", "wireguard"},
			Features:     []string{"shell", "filesystem", "process", "network", "screen", "pivoting"},
			ImplantModes: []string{"session", "beacon"},
		},
		"arm64": {
			Transports:   []string{"mtls", "https", "http", "dns", "wireguard"},
			Features:     []string{"shell", "filesystem", "process", "network", "screen", "pivoting"},
			ImplantModes: []string{"session", "beacon"},
		},
	},
	"freebsd": {
		"amd64": {
			Transports:   []string{"mtls", "https", "http"},
			Features:     []string{"shell", "filesystem", "process", "network"},
			ImplantModes: []string{"session", "beacon"},
		},
		"arm64": {
			Transports:   []string{"mtls", "https", "http"},
			Features:     []string{"shell", "filesystem", "process", "network"},
			ImplantModes: []string{"session", "beacon"},
		},
	},
	"ios": {
		"arm64": {
			Transports:   []string{"https", "dns"},
			Features:     []string{"shell", "filesystem", "network"},
			ImplantModes: []string{"beacon"},
		},
	},
	"android": {
		"arm64": {
			Transports:   []string{"https", "dns"},
			Features:     []string{"shell", "filesystem", "network"},
			ImplantModes: []string{"beacon"},
		},
		"arm": {
			Transports:   []string{"https", "dns"},
			Features:     []string{"shell", "filesystem", "network"},
			ImplantModes: []string{"beacon"},
		},
	},
}

func GetCapabilities(os, arch string) (PlatformCapabilities, bool) {
	archMap, ok := supportMatrix[os]
	if !ok {
		return PlatformCapabilities{}, false
	}
	caps, ok := archMap[arch]
	return caps, ok
}

func SupportedOperatingSystems() []string {
	result := make([]string, 0, len(supportMatrix))
	for os := range supportMatrix {
		result = append(result, os)
	}
	return result
}

func SupportedArchitectures(os string) []string {
	archMap, ok := supportMatrix[os]
	if !ok {
		return nil
	}
	result := make([]string, 0, len(archMap))
	for arch := range archMap {
		result = append(result, arch)
	}
	return result
}
