//go:build !linux

package store

func checkStorePath(path string, directory bool) error {
	return nil
}
