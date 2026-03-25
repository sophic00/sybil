package risk

import "strings"

type FingerprintSummary struct {
	IdentityClass     string
	ReputationState   string
	ApplicationFamily string
	LibraryFamily     string
	OSFamily          string
	DeviceClass       string
}

func SummarizeFingerprint(record *FingerprintRecord, lookupErr error, lookupEnabled bool) FingerprintSummary {
	if lookupErr != nil {
		return FingerprintSummary{
			IdentityClass:     "unknown",
			ReputationState:   "lookup_error",
			ApplicationFamily: "unknown",
			LibraryFamily:     "unknown",
			OSFamily:          "unknown",
			DeviceClass:       "unknown",
		}
	}
	if !lookupEnabled {
		return FingerprintSummary{
			IdentityClass:     "unknown",
			ReputationState:   "lookup_disabled",
			ApplicationFamily: "unknown",
			LibraryFamily:     "unknown",
			OSFamily:          "unknown",
			DeviceClass:       "unknown",
		}
	}
	if record == nil {
		return FingerprintSummary{
			IdentityClass:     "unknown",
			ReputationState:   "unknown",
			ApplicationFamily: "unknown",
			LibraryFamily:     "unknown",
			OSFamily:          "unknown",
			DeviceClass:       "unknown",
		}
	}

	app := strings.ToLower(strings.TrimSpace(record.Application))
	lib := strings.ToLower(strings.TrimSpace(record.Library))
	device := strings.ToLower(strings.TrimSpace(record.Device))
	osName := strings.ToLower(strings.TrimSpace(record.OS))
	ua := strings.ToLower(strings.TrimSpace(record.UserAgentString))
	notes := strings.ToLower(strings.TrimSpace(record.Notes))

	summary := FingerprintSummary{
		ApplicationFamily: classifyApplicationFamily(app, ua, notes),
		LibraryFamily:     classifyLibraryFamily(lib, ua),
		OSFamily:          classifyOSFamily(osName, ua),
		DeviceClass:       classifyDeviceClass(device, ua),
		ReputationState:   "known_unverified",
		IdentityClass:     "known_unverified",
	}

	if record.Verified {
		summary.ReputationState = "verified"
		summary.IdentityClass = "verified_known"
	}

	if isBrowser(app, ua) {
		if record.Verified {
			summary.IdentityClass = "verified_browser"
		} else {
			summary.IdentityClass = "browser"
		}
	}

	if isAutomation(app, lib, ua) {
		summary.IdentityClass = "automation"
	}
	if isVPN(app, notes) {
		summary.IdentityClass = "vpn"
	}
	if isMobileApp(summary.DeviceClass, app, ua) {
		summary.IdentityClass = "mobile_app"
	}
	if isMalwareLike(app, notes) {
		summary.IdentityClass = "malware_like"
		summary.ReputationState = "suspicious"
	}

	return summary
}

func classifyApplicationFamily(app, ua, notes string) string {
	switch {
	case containsAny(app, "chrome", "chromium") || containsAny(ua, "chrome/", "chromium"):
		return "chrome"
	case containsAny(app, "firefox") || containsAny(ua, "firefox/"):
		return "firefox"
	case containsAny(app, "safari") || containsAny(ua, "safari/"):
		return "safari"
	case containsAny(app, "edge") || containsAny(ua, "edg/"):
		return "edge"
	case containsAny(app, "curl") || containsAny(ua, "curl/"):
		return "curl"
	case containsAny(app, "python") || containsAny(ua, "python", "requests"):
		return "python"
	case containsAny(app, "go", "golang") || containsAny(ua, "go-http-client"):
		return "go"
	case containsAny(app, "java", "okhttp") || containsAny(ua, "java", "okhttp"):
		return "java"
	case containsAny(app, "node") || containsAny(ua, "node", "axios"):
		return "node"
	case containsAny(app, "powershell", "wget"):
		return "cli"
	case containsAny(app, "vpn", "wireguard", "openvpn") || containsAny(notes, "vpn"):
		return "vpn"
	case containsAny(app, "android", "ios"):
		return "mobile"
	case app == "":
		return "unknown"
	default:
		return "other"
	}
}

func classifyLibraryFamily(lib, ua string) string {
	switch {
	case containsAny(lib, "boringssl"):
		return "boringssl"
	case containsAny(lib, "openssl"):
		return "openssl"
	case containsAny(lib, "schannel"):
		return "schannel"
	case containsAny(lib, "nss"):
		return "nss"
	case containsAny(lib, "rustls"):
		return "rustls"
	case containsAny(lib, "go") || containsAny(ua, "go-http-client"):
		return "go_tls"
	case containsAny(lib, "java", "okhttp") || containsAny(ua, "okhttp"):
		return "java_tls"
	case lib == "":
		return "unknown"
	default:
		return "other"
	}
}

func classifyOSFamily(osName, ua string) string {
	switch {
	case containsAny(osName, "windows") || containsAny(ua, "windows"):
		return "windows"
	case containsAny(osName, "mac", "darwin") || containsAny(ua, "mac os x"):
		return "macos"
	case containsAny(osName, "linux") || containsAny(ua, "linux"):
		return "linux"
	case containsAny(osName, "ios") || containsAny(ua, "iphone", "ipad", "ios"):
		return "ios"
	case containsAny(osName, "android") || containsAny(ua, "android"):
		return "android"
	case osName == "":
		return "unknown"
	default:
		return "other"
	}
}

func classifyDeviceClass(device, ua string) string {
	switch {
	case containsAny(device, "mobile", "phone", "tablet") || containsAny(ua, "mobile"):
		return "mobile"
	case containsAny(device, "desktop", "laptop"):
		return "desktop"
	case containsAny(device, "server", "vm"):
		return "server"
	case containsAny(device, "iot", "printer", "embedded"):
		return "embedded"
	case device == "":
		return "unknown"
	default:
		return "other"
	}
}

func isBrowser(app, ua string) bool {
	return containsAny(app, "chrome", "chromium", "firefox", "safari", "edge", "opera") ||
		containsAny(ua, "chrome/", "firefox/", "safari/", "edg/", "opr/")
}

func isAutomation(app, lib, ua string) bool {
	return containsAny(app, "curl", "wget", "python", "requests", "httpx", "go", "java", "okhttp", "node", "powershell", "bot") ||
		containsAny(lib, "go", "okhttp", "python", "openssl", "rustls") ||
		containsAny(ua, "curl/", "python", "go-http-client", "okhttp", "axios", "wget", "powershell")
}

func isVPN(app, notes string) bool {
	return containsAny(app, "vpn", "wireguard", "openvpn", "tailscale", "surfshark", "nordvpn", "softether") ||
		containsAny(notes, "vpn", "proxy")
}

func isMobileApp(deviceClass, app, ua string) bool {
	return deviceClass == "mobile" || containsAny(app, "android", "ios") || containsAny(ua, "cfnetwork", "dalvik")
}

func isMalwareLike(app, notes string) bool {
	return containsAny(app, "malware", "cobalt strike", "sliver", "icedid", "qakbot", "pikabot", "darkgate", "lumma", "evilginx") ||
		containsAny(notes, "malware", "dropper", "c2", "beacon")
}

func containsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if candidate != "" && strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}
