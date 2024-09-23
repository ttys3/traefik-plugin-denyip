// Package main - middleware for denying request based on IP.
package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/http-wasm/http-wasm-guest-tinygo/handler"
	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
)

//go:embed blocklist_net_ua.ipset
var builtinBlacklistStr string

var builtinBlacklist = map[string][]string{
	"blocklist_net_ua.ipset": blocklist_net_uaList,
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
type DenyIP struct {
	checker *Checker
	name    string
}

func main() {
	var config Config
	err := json.Unmarshal(handler.Host.GetConfig(), &config)
	handler.Host.Log(api.LogLevelDebug, fmt.Sprintf("DenyIP config: %s", string(handler.Host.GetConfig())))
	if err != nil {
		handler.Host.Log(api.LogLevelError, fmt.Sprintf("DenyIP Could not decode config %v", err))
		os.Exit(1)
	}
	handler.Host.Log(api.LogLevelDebug, fmt.Sprintf("DenyIP config decoded: %v", config))

	mw, err := New(config)
	if err != nil {
		handler.Host.Log(api.LogLevelError, fmt.Sprintf("DenyIP Could not load config %v", err))
		os.Exit(1)
	}
	handler.HandleRequestFn = mw.handleRequest
}

// New creates a new DenyIP plugin.
func New(config Config) (*DenyIP, error) {
	checker, err := NewChecker(config.IPDenyList, config.BuiltinLists)
	if err != nil {
		return nil, err
	}

	return &DenyIP{
		checker: checker,
	}, nil
}

func (a *DenyIP) handleRequest(req api.Request, rw api.Response) (next bool, reqCtx uint32) {
	reqIPAddr := a.GetRemoteIP(req)
	reqIPAddrLenOffset := len(reqIPAddr) - 1

	for i := reqIPAddrLenOffset; i >= 0; i-- {
		isBlocked, err := a.checker.Contains(reqIPAddr[i])
		if err != nil {
			handler.Host.Log(api.LogLevelError, fmt.Sprintf("DenyIP: error checking IP: %v", err))
		}

		if isBlocked {
			handler.Host.Log(api.LogLevelInfo, fmt.Sprintf("DenyIP: request denied [%s]", reqIPAddr[i]))

			rw.SetStatusCode(http.StatusForbidden)
			next = false
			return
		}
	}

	next = true
	return
}

// GetRemoteIP returns a list of IPs that are associated with this request.
func (a *DenyIP) GetRemoteIP(req api.Request) []string {
	var ipList []string

	if cfConnectingIP, _ := req.Headers().Get(CfConnectingIP); cfConnectingIP != "" {
		ipList = append(ipList, cfConnectingIP)
		return ipList
	}

	xff, ok := req.Headers().Get(xForwardedFor)
	if !ok || xff == "" {
		return ipList
	}

	handler.Host.Log(api.LogLevelDebug, fmt.Sprintf("DenyIP no %v header found, fallback to x-forwarded-for: %s", CfConnectingIP, xff))

	xffs := strings.Split(xff, ",")

	for i := len(xffs) - 1; i >= 0; i-- {
		xffsTrim := strings.TrimSpace(xffs[i])

		if len(xffsTrim) > 0 {
			ipList = append(ipList, xffsTrim)
		}
	}

	ip, _, err := net.SplitHostPort(req.GetSourceAddr())
	if err != nil {
		remoteAddrTrim := strings.TrimSpace(req.GetSourceAddr())
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
	handler.Host.Log(api.LogLevelDebug, fmt.Sprintf("DenyIP NewChecker begin, deniedIPs: %v, builtinLists: %v", deniedIPs, builtinLists))
	if len(builtinLists) > 0 {
		for _, list := range builtinLists {
			if builtinBlacklist[list] != nil {
				deniedIPs = append(deniedIPs, builtinBlacklist[list]...)
				handler.Host.Log(api.LogLevelDebug, fmt.Sprintf("DenyIP: using builtin list %s", list))
			}
		}
	}

	if len(deniedIPs) == 0 {
		return nil, errors.New("DenyIP: no denied IPs provided")
	}

	checker := &Checker{}

	for _, ipMask := range deniedIPs {
		if ipAddr := net.ParseIP(ipMask); ipAddr != nil {
			checker.denyIPs = append(checker.denyIPs, &ipAddr)
		} else {
			_, ipAddr, err := net.ParseCIDR(ipMask)
			if err != nil {
				return nil, fmt.Errorf("DenyIP: parsing CIDR denied IPs %s: %w", ipAddr, err)
			}
			checker.denyIPsNet = append(checker.denyIPsNet, ipAddr)
		}
	}

	handler.Host.Log(api.LogLevelDebug, fmt.Sprintf("DenyIP init done, total denied IPs: %d, ips: %v, ips_net: %v",
		len(checker.denyIPs)+len(checker.denyIPsNet), len(checker.denyIPs), len(checker.denyIPsNet)))
	return checker, nil
}

// Contains checks if provided address is in the denied IPs.
func (ip *Checker) Contains(addr string) (bool, error) {
	if len(addr) == 0 {
		return false, errors.New("DenyIP: got empty client IP address")
	}

	ipAddr, err := parseIP(addr)
	if err != nil {
		return false, fmt.Errorf("DenyIP Checker unable to parse address: %s: %w", addr, err)
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
		return nil, fmt.Errorf("DenyIP: unable parse IP from address %s", addr)
	}

	return userIP, nil
}
