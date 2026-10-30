package enrichment

import (
	"strings"

	"github.com/Rass0l/storage-boxes/internal/audit/domain"
)

// RiskScorer converts request attributes into a numeric risk score 0–100 and
// an associated severity bucket. Pluggable, but the default
// HeuristicRiskScorer covers the signals this codebase actually cares about:
// empty or bot-ish User-Agent, missing IP, elevated download counts.
type RiskScorer interface {
	Score(attrs map[string]string) (int, string)
}

type HeuristicRiskScorer struct{}

var _ RiskScorer = HeuristicRiskScorer{}

func (HeuristicRiskScorer) Score(attrs map[string]string) (int, string) {
	score := 0
	ua := strings.ToLower(attrs["user_agent"])
	switch {
	case ua == "":
		score += 30
	case strings.Contains(ua, "curl"), strings.Contains(ua, "wget"),
		strings.Contains(ua, "python-requests"), strings.Contains(ua, "bot"):
		score += 15
	}
	if attrs["remote_ip"] == "" {
		score += 10
	}
	if attrs["new_ip_for_subject"] == "true" {
		score += 20
	}
	if attrs["near_download_cap"] == "true" {
		score += 15
	}
	if score > 100 {
		score = 100
	}
	sev := domain.SeverityInfo
	switch {
	case score >= 70:
		sev = domain.SeverityHigh
	case score >= 40:
		sev = domain.SeverityElevated
	case score >= 20:
		sev = domain.SeverityLow
	}
	return score, sev
}
