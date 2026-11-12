//go:build linux

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Hold the directory open so a path replacement cannot redirect session I/O.
// os.Root confines all operations; final file opens also reject symlinks.
func openRuntimeDir() (*os.Root, error) {
	path := os.Getenv("XDG_RUNTIME_DIR")
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("XDG_RUNTIME_DIR must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("XDG_RUNTIME_DIR must be a real directory")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	info, err = root.Stat(".")
	if err == nil {
		if !info.IsDir() || info.Mode().Perm() != 0o700 {
			err = fmt.Errorf("XDG_RUNTIME_DIR must have mode 0700")
		}
	}
	if err == nil {
		file, openErr := root.Open(".")
		if openErr != nil {
			err = openErr
		} else {
			var stat unix.Stat_t
			err = unix.Fstat(int(file.Fd()), &stat)
			file.Close()
			if err == nil && stat.Uid != uint32(os.Getuid()) {
				err = fmt.Errorf("XDG_RUNTIME_DIR must be owned by the current user")
			}
		}
	}
	if err != nil {
		root.Close()
		return nil, err
	}
	return root, nil
}

func writeRuntimeFile(name string, body []byte) (string, error) {
	root, err := openRuntimeDir()
	if err != nil {
		return "", err
	}
	defer root.Close()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	tmp := ".midorivpn-" + hex.EncodeToString(nonce[:])
	file, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", err
	}
	defer root.Remove(tmp)
	_, err = file.Write(body)
	closeErr := file.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	if err := root.Rename(tmp, name); err != nil {
		return "", err
	}
	return filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), name), nil
}

func readRuntimeToken() (string, error) {
	root, err := openRuntimeDir()
	if err != nil {
		return "", err
	}
	defer root.Close()
	file, err := root.OpenFile("midorivpn-agent.token", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return "", err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 || stat.Size != 65 {
		return "", fmt.Errorf("invalid running agent token file")
	}
	var body [65]byte
	if _, err := file.ReadAt(body[:], 0); err != nil {
		return "", err
	}
	if _, err := hex.DecodeString(string(body[:64])); err != nil || body[64] != '\n' {
		return "", fmt.Errorf("invalid running agent token")
	}
	return string(body[:64]), nil
}
