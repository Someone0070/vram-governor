// Command package-controller-archive creates a deterministic-permission tar.gz
// from a staged controller bundle. It is intentionally standard-library-only.
package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: package-controller-archive STAGE_ROOT PACKAGE_NAME ARCHIVE")
		os.Exit(2)
	}
	if err := packageArchive(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func packageArchive(stageRoot, packageName, archivePath string) error {
	packageRoot := filepath.Join(stageRoot, packageName)
	output, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	gzipWriter := gzip.NewWriter(output)
	tarWriter := tar.NewWriter(gzipWriter)
	closeAll := func() error {
		if err := tarWriter.Close(); err != nil {
			return err
		}
		if err := gzipWriter.Close(); err != nil {
			return err
		}
		return output.Close()
	}

	err = filepath.Walk(packageRoot, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(stageRoot, path)
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(relative)
		header.Uid, header.Gid = 0, 0
		header.Uname, header.Gname = "root", "root"
		if info.IsDir() {
			header.Mode = 0o755
			header.Name += "/"
		} else if strings.HasSuffix(info.Name(), ".sh") || info.Name() == "vram-governor-controller" {
			header.Mode = 0o755
		} else {
			header.Mode = 0o644
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tarWriter, input)
		closeErr := input.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if err != nil {
		_ = tarWriter.Close()
		_ = gzipWriter.Close()
		_ = output.Close()
		_ = os.Remove(archivePath)
		return err
	}
	return closeAll()
}
