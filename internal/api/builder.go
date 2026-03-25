package api

import (
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/sophic00/sybil/internal/risk"
	"github.com/sophic00/sybil/internal/stream"
	"github.com/sophic00/sybil/internal/tlshello"
)

func BuildObservation(event stream.Event, assessment *risk.Assessment, observedAt time.Time) (RequestObservation, bool) {
	if assessment == nil || event.Hello == nil || event.Hello.Type != tlshello.ClientHello || event.JA4 == nil {
		return RequestObservation{}, false
	}

	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	} else {
		observedAt = observedAt.UTC()
	}

	lookup := assessment.Lookup
	fingerprint := strings.TrimSpace(event.JA4.Fingerprint)
	if lookup != nil && strings.TrimSpace(lookup.JA4FingerprintString) != "" {
		fingerprint = strings.TrimSpace(lookup.JA4FingerprintString)
	}

	return RequestObservation{
		Timestamp:        observedAt,
		SourceIP:         event.NetFlow.Src().String(),
		DestinationIP:    event.NetFlow.Dst().String(),
		JA4Fingerprint:   strings.TrimSpace(event.JA4.Fingerprint),
		Fingerprint:      fingerprint,
		FingerprintKind:  "ja4",
		ThreatScore:      assessment.Score,
		Verdict:          verdictFromAssessment(*assessment),
		MatchedSignature: matchedSignature(assessment),
		Label:            fingerprintLabel(assessment),
	}, true
}

func verdictFromAssessment(assessment risk.Assessment) string {
	switch {
	case assessment.Action == risk.ActionChallenge, assessment.Action == risk.ActionBlock, assessment.Score >= 90:
		return "malicious"
	case assessment.Action == risk.ActionDelay, assessment.Action == risk.ActionRateLimit, assessment.Score >= 70:
		return "suspicious"
	default:
		return "clean"
	}
}

func matchedSignature(assessment *risk.Assessment) string {
	if assessment == nil || assessment.Lookup == nil {
		return ""
	}

	notes := strings.TrimSpace(assessment.Lookup.Notes)
	if notes != "" {
		return trimText(notes, 120)
	}

	if assessment.Summary.IdentityClass == "malware_like" {
		if app := strings.TrimSpace(assessment.Lookup.Application); app != "" {
			return trimText(app, 120)
		}
	}

	return ""
}

func fingerprintLabel(assessment *risk.Assessment) string {
	if assessment == nil {
		return "Unknown JA4 Client"
	}

	if assessment.Lookup != nil {
		app := strings.TrimSpace(assessment.Lookup.Application)
		osName := strings.TrimSpace(assessment.Lookup.OS)
		if app != "" && osName != "" {
			return trimText(fmt.Sprintf("%s (%s)", app, osName), 80)
		}
		if app != "" {
			return trimText(app, 80)
		}
		if ua := strings.TrimSpace(assessment.Lookup.UserAgentString); ua != "" && len(ua) <= 80 {
			return ua
		}
		if lib := strings.TrimSpace(assessment.Lookup.Library); lib != "" {
			return trimText(lib, 80)
		}
	}

	if app := humanizeIdentifier(assessment.Summary.ApplicationFamily); app != "" && app != "Unknown" {
		if osName := humanizeIdentifier(assessment.Summary.OSFamily); osName != "" && osName != "Unknown" {
			return trimText(fmt.Sprintf("%s (%s)", app, osName), 80)
		}
		return app
	}
	if lib := humanizeIdentifier(assessment.Summary.LibraryFamily); lib != "" && lib != "Unknown" {
		return lib
	}
	if ident := humanizeIdentifier(assessment.Summary.IdentityClass); ident != "" && ident != "Unknown" {
		return ident
	}

	return "Unknown JA4 Client"
}

func humanizeIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == '_' || r == '-' || unicode.IsSpace(r)
	})
	if len(parts) == 0 {
		return ""
	}

	for i, part := range parts {
		if part == "" {
			continue
		}
		if strings.EqualFold(part, "ios") {
			parts[i] = "iOS"
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + strings.ToLower(part[1:])
	}

	return strings.Join(parts, " ")
}

func trimText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if value == "" || limit <= 0 || len(value) <= limit {
		return value
	}
	if limit <= 3 {
		return value[:limit]
	}
	return value[:limit-3] + "..."
}
