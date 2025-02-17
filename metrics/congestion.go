package metrics

import (
	"fmt"
	"math"
	"os/exec"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

// Constants as per the reference algorithm
const (
	maxUser        = 1000.0
	maxConnections = 65535.0
	maxMemoryUsage = 0.9               // 90%
	minMemoryLeft  = 100 * 1024 * 1024 // 100M in bytes
	scoreMin       = 0.0
	scoreMax       = 10.0
	normalizeConst = 4.0 // Normalization constant
	thresholdValue = 9.0 // Threshold to decide score calculation method
)

// Weights for each parameter
var weights = map[string]float64{
	"User":        0.1,
	"Bandwidth":   0.3,
	"Memory":      0.3,
	"Connections": 0.3,
}

// limit2score transforms a parameter value into a score based on its limit
func limit2score(value, limit float64) float64 {
	// Avoid division by zero
	if limit == 0 {
		return scoreMax
	}
	// Calculate the score using the arctangent function
	score := (scoreMax*2/math.Pi)*math.Atan((value/limit)*normalizeConst) + 2
	// Cap the score at scoreMax
	if score > scoreMax {
		return scoreMax
	}
	return score
}

// CalculateLoadScore calculates the server load score based on the provided parameters
func CalculateLoadScore(users, connections, currentBandwidth, maxBandwidth, memoryUsage, memoryLeft float64) float64 {
	// Check if MemoryLeft is below the minimum threshold
	if memoryLeft < minMemoryLeft {
		return scoreMax
	}

	// Calculate individual scores
	scoreUser := limit2score(users, maxUser)
	scoreConnections := limit2score(connections, maxConnections)
	scoreBandwidth := limit2score(currentBandwidth, maxBandwidth)
	scoreMemory := limit2score(memoryUsage, maxMemoryUsage)

	// Collect all scores
	scores := map[string]float64{
		"User":        scoreUser,
		"Connections": scoreConnections,
		"Bandwidth":   scoreBandwidth,
		"Memory":      scoreMemory,
	}

	// Check if all scores are below the thresholdValue
	allBelowThreshold := true
	for _, score := range scores {
		if score >= thresholdValue {
			allBelowThreshold = false
			break
		}
	}

	var finalScore float64
	if allBelowThreshold {
		// Calculate weighted sum
		weightedSum := 0.0
		for key, score := range scores {
			weightedSum += score * weights[key]
		}
		// Normalize the weighted sum to ensure it's within 0-10
		finalScore = math.Min(math.Max(weightedSum, scoreMin), scoreMax)
	} else {
		// Set final score to the maximum individual score
		finalScore = scoreMin
		for _, score := range scores {
			if score > finalScore {
				finalScore = score
			}
		}
	}

	return finalScore
}

func GetMemoryStats() (usagePercent float64, memoryLeft float64, err error) {
	v, err := mem.VirtualMemory()
	if err != nil {
		return 0, 0, err
	}

	return v.UsedPercent / 100, float64(v.Available), nil
}

func getDefaultRouteInterface() (string, error) {
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "dev") {
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "dev" && i+1 < len(parts) {
					return parts[i+1], nil
				}
			}
		}
	}

	return "", fmt.Errorf("no default route interface found")
}

func GetConnectionsCount() (float64, error) {
	tcpConnections, err := net.Connections("tcp")
	if err != nil {
		return 0, fmt.Errorf("failed to get connections: %w", err)
	}

	connections := len(tcpConnections)

	udpConnections, err := net.Connections("udp")
	if err != nil {
		return 0, fmt.Errorf("failed to get connections: %w", err)
	}
	for _, conn := range udpConnections {
		if conn.Raddr.IP != "" && conn.Raddr.IP != "0.0.0.0" {
			connections++
		}
	}

	return float64(connections), nil
}

func GetDownloadBandwidth() (float64, error) {
	iface, err := getDefaultRouteInterface()
	if err != nil {
		return 0, fmt.Errorf("failed to get default interface: %w", err)
	}

	counters1, err := net.IOCounters(true)
	if err != nil {
		return 0, fmt.Errorf("failed to get IO counters: %w", err)
	}

	time.Sleep(100 * time.Millisecond)

	counters2, err := net.IOCounters(true)
	if err != nil {
		return 0, fmt.Errorf("failed to get IO counters: %w", err)
	}

	for i := range counters1 {
		if counters1[i].Name == iface {
			bytesRecv1 := counters1[i].BytesRecv
			bytesRecv2 := counters2[i].BytesRecv
			return float64(bytesRecv2-bytesRecv1) * 10, nil
		}
	}

	return 0, fmt.Errorf("interface %s not found", iface)
}
