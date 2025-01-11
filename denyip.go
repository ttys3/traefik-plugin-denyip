// Package main - middleware for denying request based on IP.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/http-wasm/http-wasm-guest-tinygo/handler"
	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
	"github.com/redis/go-redis/v9"
)

const (
	xForwardedFor          = "X-Forwarded-For"
	CfConnectingIP         = "CF-Connecting-IP"
	DefaultMaxSubnetRanges = 100
)

// Checker allows to check that addresses are in a denied IPs.
type Checker struct {
	rdb             *redis.Client
	keyPrefix       string
	maxSubnetRanges int
	hasSubnets      bool
}

// Config the plugin configuration.
type Config struct {
	Enabled string `json:"enabled,omitempty"`
	Redis   struct {
		Addr            string `json:"addr"`
		Password        string `json:"password"`
		DB              int    `json:"db"`
		KeyPrefix       string `json:"keyPrefix"`
		MaxSubnetRanges int    `json:"maxSubnetRanges"`
	} `json:"redis"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// DenyIP plugin.
type DenyIP struct {
	checker *Checker
	enabled bool
}

func main() {
	var config Config
	err := json.Unmarshal(handler.Host.GetConfig(), &config)
	if err != nil {
		handler.Host.Log(api.LogLevelError, fmt.Sprintf("DenyIP Could not decode config %v,config=%s", err, string(handler.Host.GetConfig())))
		os.Exit(1)
	}
	handler.Host.Log(api.LogLevelDebug, fmt.Sprintf("DenyIP config decoded success: %v", config))

	mw, err := New(config)
	if err != nil {
		handler.Host.Log(api.LogLevelError, fmt.Sprintf("DenyIP Could not load config %v", err))
		os.Exit(1)
	}
	handler.Host.Log(api.LogLevelInfo, fmt.Sprintf("DenyIP plugin loaded with config: %v", config))
	handler.HandleRequestFn = mw.handleRequest
}

// New creates a new DenyIP plugin.
func New(config Config) (*DenyIP, error) {
	checker, err := NewChecker(config)
	if err != nil {
		return nil, err
	}

	enabled, _ := strconv.ParseBool(config.Enabled)

	return &DenyIP{
		checker: checker,
		enabled: enabled,
	}, nil
}

func (a *DenyIP) handleRequest(req api.Request, rw api.Response) (next bool, reqCtx uint32) {
	if !a.enabled {
		next = true
		return
	}

	reqIPAddr := a.GetRemoteIP(req)
	if len(reqIPAddr) == 0 {
		handler.Host.Log(api.LogLevelError, fmt.Sprintf("DenyIP: unable to get remote IP: %v", req.GetSourceAddr()))
		next = false
		return
	}

	reqIPAddrLenOffset := len(reqIPAddr) - 1

	for i := reqIPAddrLenOffset; i >= 0; i-- {
		isBlocked, err := a.checker.Contains(reqIPAddr[i])
		if err != nil {
			handler.Host.Log(api.LogLevelError, fmt.Sprintf("DenyIP: error checking IP: %v", err))
		}

		if isBlocked {
			handler.Host.Log(api.LogLevelInfo, fmt.Sprintf("DenyIP: request denied [%s] %s %s [%s] source=%s",
				reqIPAddr[i], req.GetProtocolVersion(), req.GetMethod(), req.GetURI(), req.GetSourceAddr()))

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

// New creates Checker with Redis connection
func NewChecker(config Config) (*Checker, error) {
	handler.Host.Log(api.LogLevelDebug, "DenyIP: initializing Redis checker")

	rdb := redis.NewClient(&redis.Options{
		Addr:     config.Redis.Addr,
		Password: config.Redis.Password,
		DB:       config.Redis.DB,
	})

	// Test Redis connection
 ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
 defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("DenyIP: Redis connection failed: %w", err)
	}

	maxRanges := config.Redis.MaxSubnetRanges
	if maxRanges <= 0 {
		maxRanges = DefaultMaxSubnetRanges
	}

	// Check if subnet ranges exist
	rangeKey := makeSubnetRangesKey(config.Redis.KeyPrefix)
	count, err := rdb.ZCard(ctx, rangeKey).Result()
	if err != nil {
		return nil, fmt.Errorf("DenyIP: failed to check subnet ranges: %w", err)
	}

	return &Checker{
		rdb:             rdb,
		keyPrefix:       config.Redis.KeyPrefix,
		maxSubnetRanges: maxRanges,
		hasSubnets:      count > 0,
	}, nil
}

// Helper functions for IP/subnet conversion
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func cidrToRange(cidr string) (uint32, uint32, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, 0, err
	}

	// Convert IP to uint32
	ipStart := ipToUint32(ipNet.IP)

	// Calculate the end IP of the range
	ones, bits := ipNet.Mask.Size()
	ipRange := uint32(1<<(bits-ones) - 1)
	ipEnd := ipStart | ipRange

	return ipStart, ipEnd, nil
}

func makeIPKey(prefix, ip string) string {
	return fmt.Sprintf("%s:ip:%s", prefix, ip)
}

func makeSubnetRangesKey(prefix string) string {
	return fmt.Sprintf("%s:subnet", prefix)
}

// StoreSubnet stores subnet in Redis with proper score range
func (ip *Checker) StoreSubnet(ctx context.Context, cidr string) error {
	start, end, err := cidrToRange(cidr)
	if err != nil {
		return fmt.Errorf("failed to convert CIDR: %w", err)
	}

	key := makeSubnetRangesKey(ip.keyPrefix)
	member := fmt.Sprintf("%d:%d:%s", start, end, cidr)

	return ip.rdb.ZAdd(ctx, key, redis.Z{
		Score:  float64(start),
		Member: member,
	}).Err()
}

// Contains checks if IP is blocked
func (ip *Checker) Contains(addr string) (bool, error) {
	if len(addr) == 0 {
		return false, errors.New("DenyIP: got empty client IP address")
	}

	ipAddr, err := parseIP(addr)
	if err != nil {
		return false, fmt.Errorf("DenyIP: unable to parse address %s: %w", addr, err)
	}

	ctx := context.Background()

	// 1. First check exact IP match (O(1))
	key := makeIPKey(ip.keyPrefix, ipAddr.String())
	exists, err := ip.rdb.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("DenyIP: Redis check failed: %w", err)
	}
	if exists == 1 {
		return true, nil
	}

	// Skip subnet check if no subnets are configured
	if !ip.hasSubnets {
		return false, nil
	}

	// 2. Check subnets using sorted set range query
	ipInt := ipToUint32(ipAddr)

	// Get only the last few ranges that could contain this IP
	// Use ZREVRANGEBYSCORE to get ranges in descending order
	// and LIMIT to get only a small number of results
	rangeKey := makeSubnetRangesKey(ip.keyPrefix)
	ranges, err := ip.rdb.ZRangeByScore(ctx, rangeKey, &redis.ZRangeBy{
		Min:    "0",
		Max:    fmt.Sprintf("%d", ipInt),
		Offset: 0,
		Count:  int64(ip.maxSubnetRanges),
	}).Result()
	if err != nil {
		return false, fmt.Errorf("DenyIP: Redis subnet check failed: %w", err)
	}

	// Check if IP falls within any of the returned ranges
	for _, r := range ranges {
		parts := strings.Split(r, ":")
		if len(parts) != 3 {
			continue
		}

		// Since ZRangeByScore already ensures that start IP <= current IP (based on score),
		// we only need to check if the current IP is within the end range.
		// This eliminates redundant start IP comparison and improves performance.
		end, _ := strconv.ParseUint(parts[1], 10, 32)

		if ipInt <= uint32(end) {
			return true, nil
		}
	}

	return false, nil
}

func parseIP(addr string) (net.IP, error) {
	userIP := net.ParseIP(addr)
	if userIP == nil {
		return nil, fmt.Errorf("DenyIP: unable parse IP from address %s", addr)
	}

	return userIP, nil
}
