package acl

import (
	"bufio"
	"os"
	"strings"
	"unicode"
)

type FileDI struct {
	file string
	set  *Set
}

func (d *FileDI) Init() error {
	var strs []string
	if _, err := os.Stat(d.file); err != nil {
		return err
	}

	f, err := os.OpenFile(d.file, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var count = 0
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		line = strings.TrimFunc(line, func(r rune) bool {
			return !unicode.IsGraphic(r)
		})
		if line == "" {
			continue
		}
		count++
		strs = append(strs, line)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(strs) == 0 {
		return nil
	}
	d.set = NewSet(strs)
	return nil
}

func (d *FileDI) Match(host *HostInfo) bool {
	if d.set == nil {
		return false
	}
	return d.set.Has(host.Name)
}

func (d *FileDI) Size() int {
	if d.set == nil {
		return 0
	}
	return d.set.Size()
}

func newFileDI(file string) (*FileDI, error) {
	suffix := file[5:]
	fi := &FileDI{
		file: suffix,
	}
	err := fi.Init()
	if err != nil {
		return nil, err
	}
	return fi, nil
}
