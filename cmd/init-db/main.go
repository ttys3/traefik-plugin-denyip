package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/redis/go-redis/v9"
)

type Config struct {
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	KeyPrefix     string
	InputFile     string
}

func main() {
	config := parseFlags()

	// Initialize Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr:     config.RedisAddr,
		Password: config.RedisPassword,
		DB:       config.RedisDB,
	})

	// Test connection
	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	// Read and process input file
	data, err := os.ReadFile(config.InputFile)
	if err != nil {
		log.Fatalf("Failed to read input file: %v", err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if err := processLine(ctx, rdb, config.KeyPrefix, line); err != nil {
			log.Printf("Error processing line %q: %v", line, err)
		}
	}

	log.Println("Database initialization completed")
}

func processLine(ctx context.Context, rdb *redis.Client, keyPrefix, line string) error {
	// Check if it's a CIDR notation
	if strings.Contains(line, "/") {
		return storeSubnet(ctx, rdb, keyPrefix, line)
	}
	return storeIP(ctx, rdb, keyPrefix, line)
}

func storeIP(ctx context.Context, rdb *redis.Client, keyPrefix, ip string) error {
	// Validate IP
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	key := fmt.Sprintf("%s:ip:%s", keyPrefix, ip)
	return rdb.Set(ctx, key, "1", 0).Err()
}

func storeSubnet(ctx context.Context, rdb *redis.Client, keyPrefix, cidr string) error {
	start, end, err := cidrToRange(cidr)
	if err != nil {
		return fmt.Errorf("failed to convert CIDR: %w", err)
	}

	// Store in sorted set
	key := fmt.Sprintf("%s:subnet_ranges", keyPrefix)
	member := fmt.Sprintf("%d:%d:%s", start, end, cidr)

	return rdb.ZAdd(ctx, key, redis.Z{
		Score:  float64(start),
		Member: member,
	}).Err()
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

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func parseFlags() Config {
	var config Config

	flag.StringVar(&config.RedisAddr, "redis-addr", "localhost:6379", "Redis server address")
	flag.StringVar(&config.RedisPassword, "redis-password", "", "Redis password")
	flag.IntVar(&config.RedisDB, "redis-db", 0, "Redis database number")
	flag.StringVar(&config.KeyPrefix, "key-prefix", "denyip", "Key prefix for Redis keys")
	flag.StringVar(&config.InputFile, "input", "", "Input file containing IPs and CIDRs")

	flag.Parse()

	if config.InputFile == "" {
		log.Fatal("Input file is required")
	}

	return config
}
