// Package denyip - middleware for denying request based on IP.
package denyip

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

//go:embed blocklist_net_ua.ipset
var builtinBlacklistStr string

var builtinBlacklist = map[string][]string{
	"blocklist_net_ua.ipset": strings.Split(builtinBlacklistStr, "\n"),
}

const (
	xForwardedFor  = "X-Forwarded-For"
	CfConnectingIP = "Cf-Connecting-Ip"
)

// Checker allows to check that addresses are in a denied IPs.
type Checker struct {
	denyIPs    []*net.IP
	denyIPsNet []*net.IPNet
}

// Config the plugin configuration.
type Config struct {
	BuiltinLists []string `json:"builtinLists,omitempty"`
	IPDenyList   []string `json:"ipDenyList,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// DenyIP plugin.
type denyIP struct {
	next    http.Handler
	checker *Checker
	name    string
}

// New creates a new DenyIP plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	checker, err := NewChecker(config.IPDenyList, config.BuiltinLists)
	if err != nil {
		return nil, err
	}

	return &denyIP{
		checker: checker,
		next:    next,
		name:    name,
	}, nil
}

func (a *denyIP) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	reqIPAddr := a.GetRemoteIP(req)
	reqIPAddrLenOffset := len(reqIPAddr) - 1

	for i := reqIPAddrLenOffset; i >= 0; i-- {
		isBlocked, err := a.checker.Contains(reqIPAddr[i])
		if err != nil {
			log.Printf("%v", err)
		}

		if isBlocked {
			log.Printf("denyIP: request denied [%s]", reqIPAddr[i])
			rw.WriteHeader(http.StatusForbidden)

			return
		}
	}

	a.next.ServeHTTP(rw, req)
}

// GetRemoteIP returns a list of IPs that are associated with this request.
func (a *denyIP) GetRemoteIP(req *http.Request) []string {
	var ipList []string

	if cfConnectingIP := req.Header.Get(CfConnectingIP); cfConnectingIP != "" {
		ipList = append(ipList, cfConnectingIP)
		return ipList
	}

	log.Printf("no %v header found, fallback to x-forwarded-for: %s", CfConnectingIP, req.Header.Get(xForwardedFor))

	xff := req.Header.Get(xForwardedFor)
	xffs := strings.Split(xff, ",")

	for i := len(xffs) - 1; i >= 0; i-- {
		xffsTrim := strings.TrimSpace(xffs[i])

		if len(xffsTrim) > 0 {
			ipList = append(ipList, xffsTrim)
		}
	}

	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		remoteAddrTrim := strings.TrimSpace(req.RemoteAddr)
		if len(remoteAddrTrim) > 0 {
			ipList = append(ipList, remoteAddrTrim)
		}
	} else {
		ipTrim := strings.TrimSpace(ip)
		if len(ipTrim) > 0 {
			ipList = append(ipList, ipTrim)
		}
	}

	return ipList
}

// NewChecker builds a new Checker given a list of CIDR-Strings to denied IPs.
func NewChecker(deniedIPs []string, builtinLists []string) (*Checker, error) {
	if len(builtinLists) > 0 {
		for _, list := range builtinLists {
			if builtinBlacklist[list] != nil {
				deniedIPs = append(deniedIPs, builtinBlacklist[list]...)
				log.Printf("denyIP: using builtin list %s", list)
			}
		}
	}

	if len(deniedIPs) == 0 {
		return nil, errors.New("no denied IPs provided")
	}

	checker := &Checker{}

	for _, ipMask := range deniedIPs {
		if ipAddr := net.ParseIP(ipMask); ipAddr != nil {
			checker.denyIPs = append(checker.denyIPs, &ipAddr)
		} else {
			_, ipAddr, err := net.ParseCIDR(ipMask)
			if err != nil {
				return nil, fmt.Errorf("parsing CIDR denied IPs %s: %w", ipAddr, err)
			}
			checker.denyIPsNet = append(checker.denyIPsNet, ipAddr)
		}
	}

	log.Printf("init done, total denied IPs: %d, ips: %v, ips_net: %v", len(checker.denyIPs)+len(checker.denyIPsNet))
	return checker, nil
}

// Contains checks if provided address is in the denied IPs.
func (ip *Checker) Contains(addr string) (bool, error) {
	if len(addr) == 0 {
		return false, errors.New("empty IP address")
	}

	ipAddr, err := parseIP(addr)
	if err != nil {
		return false, fmt.Errorf("denyipo Checker unable to parse address: %s: %w", addr, err)
	}

	return ip.ContainsIP(ipAddr), nil
}

// ContainsIP checks if provided address is in the denied IPs.
func (ip *Checker) ContainsIP(addr net.IP) bool {
	for _, deniedIP := range ip.denyIPs {
		if deniedIP.Equal(addr) {
			return true
		}
	}

	for _, denyNet := range ip.denyIPsNet {
		if denyNet.Contains(addr) {
			return true
		}
	}

	return false
}

func parseIP(addr string) (net.IP, error) {
	userIP := net.ParseIP(addr)
	if userIP == nil {
		return nil, fmt.Errorf("unable parse IP from address %s", addr)
	}

	return userIP, nil
}
