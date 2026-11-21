package cloud

// orgmove.go — the stores of a subsystem that are still files while the deployment keeps
// its stores on hanzo-sql, and the walk that moves them.
//
// A store moves when this process first opens it (locus.Use, with CLOUD_SQL_MOVE set),
// so the stores that are asked for move as they are asked for, each in the time its own
// size takes and without the rest waiting. The walk below is for the stores nobody asks
// for: with CLOUD_SQL_MOVE=sweep it opens each one that is still a file, smallest first,
// one at a time across the whole deployment (locus.Slot), and lets go of it; opening is
// moving. It stops when the OrgStore closes, between stores, or inside one: a move that
// is cancelled puts its store back as it found it.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hanzoai/cloud/sdk/locus"
	"github.com/hanzoai/cloud/sdk/principal"
	"github.com/hanzoai/namespace"
)

// onDisk is a store of this subsystem that has a file.
type onDisk struct {
	ns   namespace.Namespace
	size int64
}

// filesOf lists the stores of this subsystem that have a file under the data directory:
// the deployment's own, each org's, and each project's of an org. It reads the layout,
// as Stored does, because "which entities have a file" is a question about the disk.
func (c *OrgStore[T]) filesOf() []onDisk {
	root := filepath.Join(c.dataDir, orgsRoot)
	var out []onDisk
	add := func(ns namespace.Namespace) {
		path, err := namespace.Path(c.dataDir, ns, c.subsystem)
		if err != nil {
			return
		}
		if info, err := os.Stat(path); err == nil {
			out = append(out, onDisk{ns: ns, size: info.Size()})
		}
	}
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		switch {
		case name == "_platform":
			add(namespace.System())
		case strings.HasPrefix(name, "_"):
		default:
			org, err := principal.OrgOnDisk(name)
			if err != nil {
				continue
			}
			add(org)
			groups, _ := os.ReadDir(filepath.Join(root, name, "projects"))
			for _, g := range groups {
				if !g.IsDir() {
					continue
				}
				if group, err := namespace.NewGroup(g.Name()); err == nil {
					add(org.WithGroup(group))
				}
			}
		}
	}
	return out
}

// sweepMoves starts the walk when the deployment asks for it.
func (c *OrgStore[T]) sweepMoves() {
	if mode, err := locus.MoveMode(); err == nil && mode == locus.Sweep {
		c.swept = make(chan struct{})
		go func() {
			defer close(c.swept)
			c.sweep()
		}()
	}
}

// sweepEvery is how often the walk says where it is.
const sweepEvery = 30 * time.Second

func (c *OrgStore[T]) sweep() {
	files := c.filesOf()
	sort.Slice(files, func(i, j int) bool {
		if files[i].size != files[j].size {
			return files[i].size < files[j].size
		}
		return files[i].ns.String() < files[j].ns.String()
	})
	var todo []onDisk
	for _, f := range files {
		if c.stop.Err() != nil {
			return
		}
		if place, err := locus.Where(f.ns, c.subsystem, c.dataDir); err == nil && place == locus.OnFile {
			todo = append(todo, f)
		}
	}
	if len(todo) == 0 {
		return
	}
	var bytes int64
	for _, f := range todo {
		bytes += f.size
	}
	c.say("sql move: sweeping the stores that are still files", "stores", len(todo), "bytes", bytes)
	release, err := locus.Slot(c.stop)
	if err != nil {
		if c.stop.Err() == nil {
			c.warn("sql move: the sweep could not take its place", err)
		}
		return
	}
	defer release()
	began, said := time.Now(), time.Now()
	var moved, kept int
	for i, f := range todo {
		if c.stop.Err() != nil {
			c.say("sql move: the sweep stopped", "moved", moved, "left", len(todo)-i)
			return
		}
		c.visit(f.ns, func(namespace.Namespace, T, error) {})
		if place, err := locus.Where(f.ns, c.subsystem, c.dataDir); err == nil && place == locus.OnServer {
			moved++
		} else {
			kept++
		}
		if time.Since(said) >= sweepEvery {
			said = time.Now()
			c.say("sql move: sweeping", "moved", moved, "stayed_files", kept, "left", len(todo)-i-1, "took", time.Since(began).Round(time.Second))
		}
	}
	c.say("sql move: the sweep is done", "moved", moved, "stayed_files", kept, "took", time.Since(began).Round(time.Second))
}

func (c *OrgStore[T]) say(msg string, kv ...any) {
	if c.log != nil {
		c.log.Info(msg, append([]any{"subsystem", c.subsystem}, kv...)...)
	}
}

func (c *OrgStore[T]) warn(msg string, err error) {
	if c.log != nil {
		c.log.Warn(msg, "subsystem", c.subsystem, "err", fmt.Sprint(err))
	}
}
