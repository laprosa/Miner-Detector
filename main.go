package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type ProcessMemoryCounters struct {
	Cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
	PrivateUsage               uintptr // This is the private bytes
}

func main() {
	// Define the process names to filter
	targetProcesses := []string{"svchost.exe", "conhost.exe", "nslookup.exe", "cmd.exe", "dwm.exe", "notepad.exe", "explorer.exe"}
	thresholdGB := 1.5 // Memory threshold in GB

	handle, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		fmt.Printf("Failed to create process snapshot: %v\n", err)
		return
	}
	defer windows.CloseHandle(handle)

	var procEntry windows.ProcessEntry32
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))

	if err := windows.Process32First(handle, &procEntry); err != nil {
		fmt.Printf("Failed to retrieve first process: %v\n", err)
		return
	}

	for {
		processName := windows.UTF16ToString(procEntry.ExeFile[:])
		for _, target := range targetProcesses {
			if processName == target {
				checkProcessMemory(procEntry.ProcessID, processName, thresholdGB)
			}
		}

		err := windows.Process32Next(handle, &procEntry)
		if err != nil {
			break
		}
	}
}

func checkProcessMemory(pid uint32, processName string, thresholdGB float64) {
	handle, _ := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	defer windows.CloseHandle(handle)

	var memCounters ProcessMemoryCounters
	memCounters.Cb = uint32(unsafe.Sizeof(memCounters))
	proc := syscall.NewLazyDLL("psapi.dll").NewProc("GetProcessMemoryInfo")

	ret, _, _ := proc.Call(uintptr(handle), uintptr(unsafe.Pointer(&memCounters)), uintptr(memCounters.Cb))
	if ret == 0 {
		fmt.Printf("Failed to get memory info for %s (PID: %d):\n", processName, pid)
		return
	}

	privateBytesGB := float64(memCounters.PrivateUsage) / (1024 * 1024 * 1024)
	if privateBytesGB > thresholdGB {
		fmt.Printf("Process: %s (PID: %d) exceeds threshold with %.2f GB\n", processName, pid, privateBytesGB)
	}
}
