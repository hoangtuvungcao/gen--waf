package hostprofile

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
)

type Profile struct {
	CPUCores int `json:"cpu_cores"`
	MemoryMB int `json:"memory_mb"`
}

func Detect() Profile {
	return Profile{
		CPUCores: runtime.NumCPU(),
		MemoryMB: detectMemoryMB(),
	}
}

func detectMemoryMB() int {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}

		kb, err := strconv.Atoi(fields[1])
		if err != nil {
			return 0
		}
		return kb / 1024
	}

	return 0
}
