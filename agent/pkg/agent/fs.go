package agent

import (
	"fmt"
	"os"
	"path"
	"sync"
)

type IFileSystem interface {
	Append(filename string, content string) error
}

type FileSystem struct {
	mutex sync.Mutex
}

func (f *FileSystem) Append(filename string, content string) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	filepath := path.Dir(filename)

	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		os.Mkdir(filepath, 0755)
	}

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("failed to open %s\n", filename)
		return err
	}
	defer file.Close()

	fmt.Fprintln(file, content)
	return nil
}
