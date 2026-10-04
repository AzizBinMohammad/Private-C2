package engagement

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type Scope struct {
	CIDRRanges    []string
	Hostnames     []string
	Domains       []string
	ExcludedHosts []string
	parsedNets    []*net.IPNet
}

func NewScope(cidrs, hostnames, domains, excluded []string) (*Scope, error) {
	s := &Scope{
		CIDRRanges:    cidrs,
		Hostnames:     hostnames,
		Domains:       domains,
		ExcludedHosts: excluded,
	}

	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		s.parsedNets = append(s.parsedNets, network)
	}

	return s, nil
}

func (s *Scope) Contains(target string) (bool, string) {
	for _, excluded := range s.ExcludedHosts {
		if strings.EqualFold(target, excluded) {
			return false, "target is explicitly excluded"
		}
	}

	if ip := net.ParseIP(target); ip != nil {
		for _, network := range s.parsedNets {
			if network.Contains(ip) {
				return true, ""
			}
		}
	}

	for _, hostname := range s.Hostnames {
		if strings.EqualFold(target, hostname) {
			return true, ""
		}
	}

	for _, domain := range s.Domains {
		if strings.HasSuffix(strings.ToLower(target), "."+strings.ToLower(domain)) ||
			strings.EqualFold(target, domain) {
			return true, ""
		}
	}

	return false, fmt.Sprintf("target %q is not within engagement scope", target)
}

type TimeWindow struct {
	Start        time.Time
	End          time.Time
	AllowedHours []string
	Timezone     *time.Location
}

func (tw *TimeWindow) IsActive() (bool, string) {
	now := time.Now()
	if tw.Timezone != nil {
		now = now.In(tw.Timezone)
	}

	if now.Before(tw.Start) {
		return false, "engagement has not started"
	}
	if now.After(tw.End) {
		return false, "engagement has ended"
	}

	return true, ""
}
