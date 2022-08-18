//go:build mage
// +build mage

package main

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"go/build"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/magefile/mage/mg"

	"github.com/livekit/livekit-server/version"
)

const (
	goChecksumFile = ".checksumgo"
	imageName      = "livekit/livekit-server"
)

// Default target to run when none is specified
// If not set, running mage will list available targets
var Default = Build
var checksummer = NewChecksummer(".", goChecksumFile, ".go", ".mod")

func init() {
	checksummer.IgnoredPaths = []string{
		"pkg/service/wire_gen.go",
		"pkg/rtc/types/typesfakes",
	}
}

// explicitly reinstall all deps
func Deps() error {
	return installTools(true)
}

// builds LiveKit server
func Build() error {
	mg.Deps(generateWire)
	if !checksummer.IsChanged() {
		fmt.Println("up to date")
		return nil
	}

	fmt.Println("building...")
	if err := os.MkdirAll("bin", 0755); err != nil {
		return err
	}
	cmd := exec.Command("go", "build", "-o", "../../bin/livekit-server")
	cmd.Dir = "cmd/server"
	connectStd(cmd)
	if err := cmd.Run(); err != nil {
		return err
	}

	checksummer.WriteChecksum()
	return nil
}

// builds binary that runs on linux amd64
func BuildLinux() error {
	mg.Deps(generateWire)
	if !checksummer.IsChanged() {
		fmt.Println("up to date")
		return nil
	}

	fmt.Println("building...")
	if err := os.MkdirAll("bin", 0755); err != nil {
		return err
	}
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", "../../bin/libLivekit-amd64")
	cmd.Env = []string{
		"GOOS=linux",
		"GOARCH=amd64",
		"HOME=" + os.Getenv("HOME"),
		"GOPATH=" + os.Getenv("GOPATH"),
	}
	cmd.Dir = "cmd/server"
	connectStd(cmd)
	if err := cmd.Run(); err != nil {
		return err
	}

	checksummer.WriteChecksum()
	return nil
}

// builds binary that runs on android arm64
func BuildAndroid() error {
	mg.Deps(generateWire)
	if !checksummer.IsChanged() {
		fmt.Println("up to date")
		return nil
	}

	fmt.Println("building...")
	if err := os.MkdirAll("bin", 0755); err != nil {
		return err
	}
	cmd := exec.Command("go", "build", "-buildmode=c-shared", "-buildvcs=false", "-o", "../../bin/libLivekit64.so") //"-ldflags=-s,-w",
	cmd.Env = []string{
		"CGO_ENABLED=1",
		"NDK=/Users/vickyleu/Develop/Android/SDK/ndk/25.0.8775105/",
		"CC=/Users/vickyleu/Develop/Android/SDK/ndk/25.0.8775105/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android33-clang",
		"CXX=/Users/vickyleu/Develop/Android/SDK/ndk/25.0.8775105/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android33-clang++",
		"GOOS=android",
		"GOARCH=arm64",
		"HOME=" + os.Getenv("HOME"),
		"GOPATH=" + os.Getenv("GOPATH"),
	}
	cmd.Dir = "cmd/server"
	connectStd(cmd)
	if err := cmd.Run(); err != nil {
		return err
	}

	checksummer.WriteChecksum()
	return nil
}

func Deadlock() error {
	if err := installTool("golang.org/x/tools/cmd/goimports", "latest", false); err != nil {
		return err
	}
	if err := run("go get github.com/sasha-s/go-deadlock"); err != nil {
		return err
	}
	if err := pipe("grep -rl sync.Mutex ./pkg", "xargs sed -i  -e s/sync.Mutex/deadlock.Mutex/g"); err != nil {
		return err
	}
	if err := pipe("grep -rl sync.RWMutex ./pkg", "xargs sed -i  -e s/sync.RWMutex/deadlock.RWMutex/g"); err != nil {
		return err
	}
	if err := pipe("grep -rl deadlock.Mutex\\|deadlock.RWMutex ./pkg", "xargs goimports -w"); err != nil {
		return err
	}
	if err := run("go mod tidy"); err != nil {
		return err
	}
	return nil
}

func Sync() error {
	if err := pipe("grep -rl deadlock.Mutex ./pkg", "xargs sed -i  -e s/deadlock.Mutex/sync.Mutex/g"); err != nil {
		return err
	}
	if err := pipe("grep -rl deadlock.RWMutex ./pkg", "xargs sed -i  -e s/deadlock.RWMutex/sync.RWMutex/g"); err != nil {
		return err
	}
	if err := pipe("grep -rl sync.Mutex\\|sync.RWMutex ./pkg", "xargs goimports -w"); err != nil {
		return err
	}
	if err := run("go mod tidy"); err != nil {
		return err
	}
	return nil
}

// builds and publish snapshot docker image
func PublishDocker() error {
	// don't publish snapshot versions as latest or minor version
	if !strings.Contains(version.Version, "SNAPSHOT") {
		return errors.New("Cannot publish non-snapshot versions")
	}

	versionImg := fmt.Sprintf("%s:v%s", imageName, version.Version)
	cmd := exec.Command("docker", "buildx", "build",
		"--push", "--platform", "linux/amd64,linux/arm64",
		"--tag", versionImg,
		".")
	connectStd(cmd)
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

// run unit tests, skipping integration
func Test() error {
	mg.Deps(generateWire, setULimit)
	cmd := exec.Command("go", "test", "-short", "./...", "-count=1")
	connectStd(cmd)
	return cmd.Run()
}

// run all tests including integration
func TestAll() error {
	mg.Deps(generateWire, setULimit)
	return run("go test ./... -count=1 -timeout=4m -v")
}

// cleans up builds
func Clean() {
	fmt.Println("cleaning...")
	os.RemoveAll("bin")
	os.Remove(goChecksumFile)
}

// regenerate code
func Generate() error {
	mg.Deps(installDeps, generateWire)

	fmt.Println("generating...")
	return run("go generate ./...")
}

// code generation for wiring
func generateWire() error {
	mg.Deps(installDeps)
	if !checksummer.IsChanged() {
		return nil
	}

	fmt.Println("wiring...")

	wire, err := getToolPath("wire")
	if err != nil {
		return err
	}
	cmd := exec.Command(wire)
	cmd.Dir = "pkg/service"
	connectStd(cmd)
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

// implicitly install deps
func installDeps() error {
	return installTools(false)
}

func installTools(force bool) error {
	tools := map[string]string{
		"github.com/google/wire/cmd/wire": "latest",
	}
	for t, v := range tools {
		if err := installTool(t, v, force); err != nil {
			return err
		}
	}
	return nil
}

func installTool(url, version string, force bool) error {
	name := filepath.Base(url)
	if !force {
		_, err := getToolPath(name)
		if err == nil {
			// already installed
			return nil
		}
	}

	fmt.Printf("installing %s %s\n", name, version)
	urlWithVersion := fmt.Sprintf("%s@%s", url, version)
	cmd := exec.Command("go", "install", urlWithVersion)
	connectStd(cmd)
	if err := cmd.Run(); err != nil {
		return err
	}

	// check
	_, err := getToolPath(name)
	return err
}

// helpers

func getToolPath(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	// check under gopath
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		gopath = build.Default.GOPATH
	}
	p := filepath.Join(gopath, "bin", name)
	if _, err := os.Stat(p); err != nil {
		return "", err
	}
	return p, nil
}

func connectStd(cmd *exec.Cmd) {
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
}

// A helper checksum library that generates a fast, non-portable checksum over a directory of files
// it's designed as a quick way to bypass
type Checksummer struct {
	dir          string
	file         string
	checksum     string
	allExts      bool
	extMap       map[string]bool
	IgnoredPaths []string
}

func NewChecksummer(dir string, checksumfile string, exts ...string) *Checksummer {
	c := &Checksummer{
		dir:    dir,
		file:   checksumfile,
		extMap: make(map[string]bool),
	}
	if len(exts) == 0 {
		c.allExts = true
	} else {
		for _, ext := range exts {
			c.extMap[ext] = true
		}
	}

	return c
}

func (c *Checksummer) IsChanged() bool {
	// default changed
	if err := c.computeChecksum(); err != nil {
		log.Println("could not compute checksum", err)
		return true
	}
	// read
	existing, err := c.ReadChecksum()
	if err != nil {
		// may not be there
		return true
	}

	return existing != c.checksum
}

func (c *Checksummer) ReadChecksum() (string, error) {
	b, err := ioutil.ReadFile(filepath.Join(c.dir, c.file))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (c *Checksummer) WriteChecksum() error {
	if err := c.computeChecksum(); err != nil {
		return err
	}
	return ioutil.WriteFile(filepath.Join(c.dir, c.file), []byte(c.checksum), 0644)
}

func (c *Checksummer) computeChecksum() error {
	if c.checksum != "" {
		return nil
	}

	entries := make([]string, 0)
	ignoredMap := make(map[string]bool)
	for _, f := range c.IgnoredPaths {
		ignoredMap[f] = true
	}
	err := filepath.Walk(c.dir, func(path string, info os.FileInfo, err error) error {
		if path == c.dir {
			return nil
		}
		if strings.HasPrefix(info.Name(), ".") || ignoredMap[path] {
			if info.IsDir() {
				return filepath.SkipDir
			} else {
				return nil
			}
		}
		if info.IsDir() {
			entries = append(entries, fmt.Sprintf("%s %d", path, info.ModTime().Unix()))
		} else if c.allExts || c.extMap[filepath.Ext(info.Name())] {
			entries = append(entries, fmt.Sprintf("%s %d %d", path, info.Size(), info.ModTime().Unix()))
		}
		return nil
	})
	if err != nil {
		return err
	}

	sort.Strings(entries)

	h := sha1.New()
	for _, e := range entries {
		h.Write([]byte(e))
	}
	c.checksum = fmt.Sprintf("%x", h.Sum(nil))

	return nil
}

func run(commands ...string) error {
	for _, command := range commands {
		args := strings.Split(command, " ")
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}

func pipe(first, second string) error {
	a1 := strings.Split(first, " ")
	c1 := exec.Command(a1[0], a1[1:]...)

	c1.Stderr = os.Stderr
	p, err := c1.StdoutPipe()
	if err != nil {
		return err
	}

	a2 := strings.Split(second, " ")
	c2 := exec.Command(a2[0], a2[1:]...)

	c2.Stdin = p
	c2.Stdout = os.Stdout
	c2.Stderr = os.Stderr

	if err = c1.Start(); err != nil {
		return err
	}
	if err = c2.Start(); err != nil {
		return err
	}
	if err = c1.Wait(); err != nil {
		return err
	}
	if err = c2.Wait(); err != nil {
		return err
	}
	return nil
}
