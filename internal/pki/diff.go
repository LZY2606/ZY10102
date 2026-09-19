package pki

import (
	"crypto/x509"
	"encoding/hex"

	"localpki/internal/model"
)

func extensionName(oid string) string {
	names := map[string]string{
		"2.5.29.14":         "subjectKeyIdentifier",
		"2.5.29.15":         "keyUsage",
		"2.5.29.17":         "subjectAltName",
		"2.5.29.18":         "issuerAltName",
		"2.5.29.19":         "basicConstraints",
		"2.5.29.30":         "nameConstraints",
		"2.5.29.31":         "cRLDistributionPoints",
		"2.5.29.32":         "certificatePolicies",
		"2.5.29.35":         "authorityKeyIdentifier",
		"2.5.29.37":         "extKeyUsage",
		"1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
	}
	if name, ok := names[oid]; ok {
		return name
	}
	return "custom"
}

func diffExtensions(before, after *x509.Certificate) []model.ExtensionDiff {
	beforeMap := map[string]pkixExtensionView{}
	afterMap := map[string]pkixExtensionView{}
	for _, ext := range before.Extensions {
		view := pkixExtensionView{OID: ext.Id.String(), Critical: ext.Critical, Value: ext.Value}
		beforeMap[view.OID] = view
	}
	for _, ext := range after.Extensions {
		view := pkixExtensionView{OID: ext.Id.String(), Critical: ext.Critical, Value: ext.Value}
		afterMap[view.OID] = view
	}
	ids := map[string]bool{}
	for id := range beforeMap {
		ids[id] = true
	}
	for id := range afterMap {
		ids[id] = true
	}
	out := []model.ExtensionDiff{}
	for id := range ids {
		b, hasBefore := beforeMap[id]
		a, hasAfter := afterMap[id]
		diff := model.ExtensionDiff{OID: id, Name: extensionName(id)}
		diff.CriticalBefore, diff.CriticalAfter = b.Critical, a.Critical
		diff.BeforeHex, diff.AfterHex = hex.EncodeToString(b.Value), hex.EncodeToString(a.Value)
		switch {
		case hasBefore && !hasAfter:
			diff.Change = "removed"
		case !hasBefore && hasAfter:
			diff.Change = "added"
		case b.Critical != a.Critical || hex.EncodeToString(b.Value) != hex.EncodeToString(a.Value):
			diff.Change = "changed"
		default:
			diff.Change = "unchanged"
		}
		out = append(out, diff)
	}
	sortDiffs(out)
	return out
}

type pkixExtensionView struct {
	OID      string
	Critical bool
	Value    []byte
}

func sortDiffs(diffs []model.ExtensionDiff) {
	for i := 0; i < len(diffs); i++ {
		for j := i + 1; j < len(diffs); j++ {
			if diffs[j].OID < diffs[i].OID {
				diffs[i], diffs[j] = diffs[j], diffs[i]
			}
		}
	}
}
