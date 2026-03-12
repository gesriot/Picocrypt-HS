package volume

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

func selectionRoots(req *EncryptRequest) []string {
	var roots []string

	for _, folder := range req.OnlyFolders {
		roots = append(roots, filepath.Dir(folder))
	}
	for _, file := range req.OnlyFiles {
		roots = append(roots, filepath.Dir(file))
	}

	if len(roots) == 0 {
		for _, path := range req.InputFiles {
			roots = append(roots, filepath.Dir(path))
		}
	}

	return roots
}

func commonPathRoot(paths []string) (string, error) {
	if len(paths) == 0 {
		return "", errors.New("no input roots")
	}

	root := filepath.Clean(paths[0])
	for _, path := range paths[1:] {
		path = filepath.Clean(path)
		for {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return "", fmt.Errorf("compute common root: %w", err)
			}
			if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
				break
			}

			parent := filepath.Dir(root)
			if parent == root {
				break
			}
			root = parent
		}
	}

	return root, nil
}

func buildZipEntryNames(req *EncryptRequest) (string, map[string]string, error) {
	if len(req.InputFiles) == 0 {
		return "", nil, errors.New("no input files")
	}

	commonRoot, err := commonPathRoot(selectionRoots(req))
	if err != nil {
		return "", nil, err
	}

	entryNames := make(map[string]string, len(req.InputFiles))
	for _, path := range req.InputFiles {
		rel, err := filepath.Rel(commonRoot, path)
		if err != nil {
			return "", nil, fmt.Errorf("build zip path for %s: %w", path, err)
		}
		rel = filepath.Clean(rel)
		if !filepath.IsLocal(rel) {
			return "", nil, fmt.Errorf("non-local archive path %q for %s", rel, path)
		}
		entryNames[path] = filepath.ToSlash(rel)
	}

	return commonRoot, entryNames, nil
}
