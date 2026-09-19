package pki

import (
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"

	"localpki/internal/model"
)

type identitySet struct {
	dns    []string
	emails []string
	ips    []net.IP
	uris   []string
}

type Constraints struct {
	PermittedDNSDomains     []string
	ExcludedDNSDomains      []string
	PermittedIPRanges       []*net.IPNet
	ExcludedIPRanges        []*net.IPNet
	PermittedEmailAddresses []string
	ExcludedEmailAddresses  []string
	PermittedURIDomains     []string
	ExcludedURIDomains      []string
}

func identityFromCertificate(c *x509.Certificate) identitySet {
	dns := append([]string{}, c.DNSNames...)
	if c.Subject.CommonName != "" && looksDNS(c.Subject.CommonName) && !containsString(dns, c.Subject.CommonName) {
		dns = append(dns, c.Subject.CommonName)
	}
	return identitySet{dns: dns, emails: append([]string{}, c.EmailAddresses...), ips: append([]net.IP{}, c.IPAddresses...), uris: urlsToStrings(c.URIs)}
}

func urlsToStrings(values []*url.URL) []string {
	out := []string{}
	for _, u := range values {
		out = append(out, u.String())
	}
	return out
}

func looksDNS(value string) bool {
	return strings.Contains(value, ".") && net.ParseIP(value) == nil && !strings.Contains(value, " ")
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

func buildNameConstraints(nc model.NameConstraints) (*Constraints, error) {
	permittedIPs, excludedIPs, err := parseConstraintIPs(nc.PermittedIPNet, nc.ExcludedIPNet)
	if err != nil {
		return nil, err
	}
	for _, domain := range append(append([]string{}, nc.PermittedDNS...), nc.ExcludedDNS...) {
		if domain == "" || strings.ContainsAny(domain, " /") {
			return nil, fmt.Errorf("invalid DNS constraint %q", domain)
		}
	}
	return &Constraints{
		PermittedDNSDomains:     nc.PermittedDNS,
		ExcludedDNSDomains:      nc.ExcludedDNS,
		PermittedIPRanges:       permittedIPs,
		ExcludedIPRanges:        excludedIPs,
		PermittedEmailAddresses: nc.PermittedEmail,
		ExcludedEmailAddresses:  nc.ExcludedEmail,
		PermittedURIDomains:     nc.PermittedURI,
		ExcludedURIDomains:      nc.ExcludedURI,
	}, nil
}

func parseConstraintIPs(permitted, excluded []string) ([]*net.IPNet, []*net.IPNet, error) {
	parse := func(values []string) ([]*net.IPNet, error) {
		out := []*net.IPNet{}
		for _, value := range values {
			_, network, err := net.ParseCIDR(value)
			if err != nil {
				return nil, fmt.Errorf("invalid IP constraint %q: %w", value, err)
			}
			out = append(out, network)
		}
		return out, nil
	}
	a, err := parse(permitted)
	if err != nil {
		return nil, nil, err
	}
	b, err := parse(excluded)
	if err != nil {
		return nil, nil, err
	}
	return a, b, nil
}

func nameConstraintsFromCert(c *x509.Certificate) *Constraints {
	if len(c.PermittedDNSDomains)+len(c.ExcludedDNSDomains)+len(c.PermittedIPRanges)+len(c.ExcludedIPRanges)+len(c.PermittedEmailAddresses)+len(c.ExcludedEmailAddresses)+len(c.PermittedURIDomains)+len(c.ExcludedURIDomains) == 0 {
		return nil
	}
	return &Constraints{
		PermittedDNSDomains: c.PermittedDNSDomains, ExcludedDNSDomains: c.ExcludedDNSDomains,
		PermittedIPRanges: c.PermittedIPRanges, ExcludedIPRanges: c.ExcludedIPRanges,
		PermittedEmailAddresses: c.PermittedEmailAddresses, ExcludedEmailAddresses: c.ExcludedEmailAddresses,
		PermittedURIDomains: c.PermittedURIDomains, ExcludedURIDomains: c.ExcludedURIDomains,
	}
}

func validateNameConstraints(names identitySet, parent *x509.Certificate) error {
	nc := nameConstraintsFromCert(parent)
	if nc == nil {
		return nil
	}
	for _, name := range names.dns {
		normalized := strings.TrimPrefix(strings.ToLower(name), "*.")
		if len(nc.PermittedDNSDomains) > 0 && !anyDomain(normalized, nc.PermittedDNSDomains, dnsInTree) {
			return fmt.Errorf("DNS name %q is outside permitted DNS constraints", name)
		}
		if anyDomain(normalized, nc.ExcludedDNSDomains, dnsInTree) {
			return fmt.Errorf("DNS name %q matches an excluded DNS constraint", name)
		}
	}
	for _, ip := range names.ips {
		if len(nc.PermittedIPRanges) > 0 && !anyIP(ip, nc.PermittedIPRanges) {
			return fmt.Errorf("IP %s is outside permitted IP constraints", ip)
		}
		for _, network := range nc.ExcludedIPRanges {
			if network.Contains(ip) {
				return fmt.Errorf("IP %s matches an excluded IP constraint", ip)
			}
		}
	}
	for _, email := range names.emails {
		if len(nc.PermittedEmailAddresses) > 0 && !anyDomain(email, nc.PermittedEmailAddresses, emailInTree) {
			return fmt.Errorf("email %q is outside permitted email constraints", email)
		}
		if anyDomain(email, nc.ExcludedEmailAddresses, emailInTree) {
			return fmt.Errorf("email %q matches an excluded email constraint", email)
		}
	}
	for _, uri := range names.uris {
		if len(nc.PermittedURIDomains) > 0 && !anyDomain(uri, nc.PermittedURIDomains, uriInTree) {
			return fmt.Errorf("URI %q is outside permitted URI constraints", uri)
		}
		if anyDomain(uri, nc.ExcludedURIDomains, uriInTree) {
			return fmt.Errorf("URI %q matches an excluded URI constraint", uri)
		}
	}
	return nil
}

func anyDomain(value string, constraints []string, match func(string, string) bool) bool {
	for _, constraint := range constraints {
		if match(value, constraint) {
			return true
		}
	}
	return false
}

func anyIP(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func validateChildConstraints(child model.NameConstraints, parent *x509.Certificate) error {
	parentNC := nameConstraintsFromCert(parent)
	if parentNC == nil {
		return nil
	}
	for _, domain := range child.PermittedDNS {
		if len(parentNC.PermittedDNSDomains) > 0 && !anyDomain(domain, parentNC.PermittedDNSDomains, dnsInTree) {
			return fmt.Errorf("child permitted DNS %q escapes parent permitted namespace", domain)
		}
		if anyDomain(domain, parentNC.ExcludedDNSDomains, dnsInTree) {
			return fmt.Errorf("child permitted DNS %q overlaps parent excluded namespace", domain)
		}
	}
	_, childExcluded, err := parseConstraintIPs(nil, child.ExcludedIPNet)
	if err != nil {
		return err
	}
	childPermitted, _, err := parseConstraintIPs(child.PermittedIPNet, nil)
	if err != nil {
		return err
	}
	for _, network := range childPermitted {
		if len(parentNC.PermittedIPRanges) > 0 && !networkInAny(network, parentNC.PermittedIPRanges) {
			return fmt.Errorf("child permitted network %s escapes parent permitted namespace", network)
		}
	}
	_ = childExcluded
	return nil
}

func networkInAny(child *net.IPNet, parents []*net.IPNet) bool {
	for _, parent := range parents {
		if networkContains(parent, child) {
			return true
		}
	}
	return false
}

func networkContains(outer, inner *net.IPNet) bool {
	outerOnes, _ := outer.Mask.Size()
	innerOnes, _ := inner.Mask.Size()
	return outerOnes <= innerOnes && outer.Contains(inner.IP)
}
