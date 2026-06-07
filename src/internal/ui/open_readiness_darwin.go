//go:build darwin && cgo

package ui

/*
#cgo LDFLAGS: -framework Foundation
#include <stdlib.h>

int pcngCheckOpenedPathReadiness(char *path, char **errorOut);
void pcngFreeCString(char *s);
*/
import "C"

import (
	"context"
	"errors"
	"unsafe"
)

func defaultOpenedPathReadiness(ctx context.Context, paths []string) openedPathReadinessResult {
	result := make(openedPathReadinessResult, 0, len(paths))
	for _, path := range paths {
		if ctx.Err() != nil {
			return result
		}
		cpath := C.CString(path)
		var cerr *C.char
		code := int(C.pcngCheckOpenedPathReadiness(cpath, &cerr))
		C.free(unsafe.Pointer(cpath))
		item := openedPathReadiness{Path: path, State: openedPathStateFromDarwinCode(code)}
		if cerr != nil {
			item.Err = errors.New(C.GoString(cerr))
			C.pcngFreeCString(cerr)
		}
		result = append(result, item)
	}
	return result
}
