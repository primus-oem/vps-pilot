package application

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

func RefreshDigest(plan *ReleasePlan) error {
	if plan == nil {
		return errors.New("release plan is required")
	}
	plan.Digest = ""
	encoded, err := json.Marshal(plan)
	if err != nil {
		return fmt.Errorf("canonicalize release plan: %w", err)
	}
	plan.Digest = fmt.Sprintf("sha256:%x", sha256.Sum256(encoded))
	return nil
}

func ComparisonFingerprint(plan ReleasePlan) (string, error) {
	plan.Diff = ReleaseDiff{}
	plan.Preflight = nil
	plan.Digest = ""
	plan.Risk = comparisonRisk(plan.Risk)
	encoded, err := json.Marshal(plan)
	if err != nil {
		return "", fmt.Errorf("canonicalize release comparison: %w", err)
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(encoded)), nil
}

func BindPreflight(plan *ReleasePlan, evidence []ComposePreflight) error {
	if plan == nil || len(evidence) == 0 {
		return errors.New("release plan and preflight evidence are required")
	}
	plan.Preflight = append([]ComposePreflight(nil), evidence...)
	sort.Slice(plan.Preflight, func(i, j int) bool {
		if plan.Preflight[i].TargetID != plan.Preflight[j].TargetID {
			return plan.Preflight[i].TargetID < plan.Preflight[j].TargetID
		}
		if plan.Preflight[i].Project != plan.Preflight[j].Project {
			return plan.Preflight[i].Project < plan.Preflight[j].Project
		}
		return plan.Preflight[i].File < plan.Preflight[j].File
	})
	plan.Risk = comparisonRisk(plan.Risk)
	return RefreshDigest(plan)
}

func comparisonRisk(summary RiskSummary) RiskSummary {
	findings := make([]RiskFinding, 0, len(summary.Findings))
	for _, finding := range summary.Findings {
		if finding.Code != "compose_config_not_preflighted" {
			findings = append(findings, finding)
		}
	}
	summary.Findings = findings
	summary.Level = "low"
	for _, finding := range findings {
		raiseRisk(&summary, finding.Severity)
	}
	return summary
}

func ManifestDigest(manifest *Manifest) string {
	encoded, _ := json.Marshal(manifest)
	return fmt.Sprintf("sha256:%x", sha256.Sum256(encoded))
}

func HasValidDigest(plan ReleasePlan) bool {
	digest := plan.Digest
	plan.Digest = ""
	encoded, err := json.Marshal(plan)
	if err != nil {
		return false
	}
	return digest == fmt.Sprintf("sha256:%x", sha256.Sum256(encoded))
}
