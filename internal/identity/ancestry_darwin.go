//go:build darwin

package identity

/*
#include <libproc.h>
#include <stdlib.h>
#include <sys/proc_info.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Resolve walks the ancestry chain for pid up to MaxDepth using libproc.
func Resolve(pid int) (Identity, error) {
	id := Identity{PID: pid}
	current := pid
	for depth := 0; depth < MaxDepth+1 && current > 0; depth++ {
		exe, err := pathForPid(current)
		if err != nil {
			return id, fmt.Errorf("pidpath(%d): %w", current, err)
		}
		if depth == 0 {
			id.Exe = exe
		}
		id.Chain = append(id.Chain, exe)
		// pid 1 is launchd — terminal ancestor, no need to query its parent
		if current == 1 {
			break
		}
		ppid, err := parentOf(current)
		if err != nil {
			return id, fmt.Errorf("parentOf(%d): %w", current, err)
		}
		if ppid == current || ppid == 0 {
			break
		}
		current = ppid
	}
	id.Compute()
	return id, nil
}

func pathForPid(pid int) (string, error) {
	buf := make([]byte, C.PROC_PIDPATHINFO_MAXSIZE)
	n := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if n <= 0 {
		return "", fmt.Errorf("proc_pidpath returned %d", int(n))
	}
	return string(buf[:n]), nil
}

func parentOf(pid int) (int, error) {
	var info C.struct_proc_bsdinfo
	n := C.proc_pidinfo(C.int(pid), C.PROC_PIDTBSDINFO, 0, unsafe.Pointer(&info), C.int(C.PROC_PIDTBSDINFO_SIZE))
	if n != C.int(C.PROC_PIDTBSDINFO_SIZE) {
		return 0, fmt.Errorf("proc_pidinfo returned %d", int(n))
	}
	return int(info.pbi_ppid), nil
}
