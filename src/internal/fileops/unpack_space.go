package fileops

import (
	"fmt"
	"math"
	"os"
)

func requiredAdditionalBytesForExtraction(desiredSizes map[string]int64) (int64, error) {
	var required int64
	for path, desiredSize := range desiredSizes {
		existingSize, err := existingExtractionFileSize(path)
		if err != nil {
			return 0, err
		}
		if desiredSize <= existingSize {
			continue
		}

		delta := desiredSize - existingSize
		if required > math.MaxInt64-delta {
			return 0, fmt.Errorf("required extraction size exceeds int64 max")
		}
		required += delta
	}
	return required, nil
}

func existingExtractionFileSize(path string) (int64, error) {
	info, err := os.Lstat(path)
	switch {
	case os.IsNotExist(err):
		return 0, nil
	case err != nil:
		return 0, err
	case info.Mode()&os.ModeSymlink != 0:
		return 0, fmt.Errorf("refusing to stat symlink during extraction: %s", path)
	case info.IsDir():
		return 0, fmt.Errorf("path exists as directory: %s", path)
	default:
		return info.Size(), nil
	}
}
