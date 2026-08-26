package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/inventory"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

type typeMetrics struct {
	Type     string
	Packages int
	Versions int
	Present  int
	Missing  int
	StorageB int64
	Frozen   int
	Hidden   int
}

// backendMetrics is one storage backend's share of the inventory. Reported
// separately from the per-type table because a full /mnt/bulk is invisible in
// a combined byte count: the aggregate keeps growing while the volume holding
// half of it has no room left.
type backendMetrics struct {
	Name     string
	Present  int
	Missing  int
	StorageB int64
	Errors   int
}

type globalMetrics struct {
	Types      []typeMetrics
	Backends   []backendMetrics
	DepEdges   int
	Orphans    int
	Fetches24h int
	Builds24h  int
	Creates24h int
}

func newDashboardCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status [TYPE]",
		Short: "Show repository status dashboard",
		Long: `Display a summary of the repository state including package inventory,
S3 coverage, storage usage, and recent activity.

  bodega status                    # global dashboard
  bodega status git                # git repo metrics
  bodega status pypi               # pypi repo metrics`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			store, err := loadStore(gf)
			if err != nil {
				return err
			}
			ctx := context.Background()

			// Probe every configured backend, not just an S3 bucket: a
			// local-only install had no coverage numbers at all before.
			var statuses []inventory.EntryStatus
			if stores, err := storage.NewResolver(ctx, cfg); err == nil {
				statuses, _ = inventory.CheckStatus(ctx, stores, store, manifest.AllTypes)
			}

			// Collect audit activity.
			var fetches24h, builds24h, creates24h int
			if cfg.AuditDB != "" {
				db, err := audit.Open(cfg.AuditDB)
				if err == nil {
					defer db.Close()
					since := time.Now().Add(-24 * time.Hour)
					f1, _ := db.Count(ctx, audit.Filter{EventType: audit.EventFetch, Since: since})
					f2, _ := db.Count(ctx, audit.Filter{EventType: audit.EventServeFetch, Since: since})
					b, _ := db.Count(ctx, audit.Filter{EventType: audit.EventBuild, Since: since})
					c, _ := db.Count(ctx, audit.Filter{EventType: audit.EventCreate, Since: since})
					fetches24h, builds24h, creates24h = int(f1)+int(f2), int(b), int(c)
				}
			}

			s3map := make(map[string]bool)
			sizeMap := make(map[string]int64)
			byBackend := make(map[string]*backendMetrics)
			var backendOrder []string
			for _, st := range statuses {
				s3map[st.Type+"/"+st.Name] = st.Present
				if st.Present {
					sizeMap[st.Type] += st.Size
				}
				b, ok := byBackend[st.Backend]
				if !ok {
					b = &backendMetrics{Name: st.Backend}
					byBackend[st.Backend] = b
					backendOrder = append(backendOrder, st.Backend)
				}
				switch {
				case st.Error != "":
					b.Errors++
				case st.Present:
					b.Present++
					b.StorageB += st.Size
				default:
					b.Missing++
				}
			}

			// Collect per-type metrics.
			sort.Strings(backendOrder)
			metrics := globalMetrics{
				DepEdges:   len(store.AllEdges()),
				Orphans:    len(store.Orphans()),
				Fetches24h: fetches24h,
				Builds24h:  builds24h,
				Creates24h: creates24h,
			}
			for _, name := range backendOrder {
				metrics.Backends = append(metrics.Backends, *byBackend[name])
			}

			filterType := ""
			if len(args) > 0 {
				filterType = args[0]
			}

			for _, typ := range manifest.AllTypes {
				if filterType != "" && typ != filterType {
					continue
				}
				tm := typeMetrics{Type: typ}
				for _, name := range store.ListPackages(typ) {
					pm, err := store.GetPackage(ctx, typ, name)
					if err != nil || pm == nil {
						continue
					}
					tm.Packages++
					for _, ve := range pm.Versions {
						tm.Versions++
						if ve.Frozen {
							tm.Frozen++
						}
						if ve.Hidden {
							tm.Hidden++
						}
						key := typ + "/" + ve.VersionedName(pm.Name)
						if s3map[key] {
							tm.Present++
						} else {
							tm.Missing++
						}
					}
				}
				tm.StorageB = sizeMap[typ]
				metrics.Types = append(metrics.Types, tm)
			}

			if filterType != "" {
				printTypeMetrics(metrics)
			} else {
				printGlobalDashboard(metrics)
			}
			return nil
		},
	}
	return cmd
}

func printGlobalDashboard(m globalMetrics) {
	totalPkg, totalVer, totalPresent, totalMissing, totalFrozen, totalHidden := 0, 0, 0, 0, 0, 0
	var totalStorage int64
	for _, t := range m.Types {
		totalPkg += t.Packages
		totalVer += t.Versions
		totalPresent += t.Present
		totalMissing += t.Missing
		totalFrozen += t.Frozen
		totalHidden += t.Hidden
		totalStorage += t.StorageB
	}

	total := totalPresent + totalMissing
	pct := 0
	if total > 0 {
		pct = totalPresent * 100 / total
	}

	w := 52
	fmt.Println(boxTop("bodega status", w))
	fmt.Println(boxEmpty(w))
	fmt.Println(boxRow(w, fmt.Sprintf("  Packages   %-10d Uploaded     %d/%d (%d%%)", totalPkg, totalPresent, total, pct)))
	fmt.Println(boxRow(w, fmt.Sprintf("  Versions   %-10d Storage      %s", totalVer, humanSize(totalStorage))))
	fmt.Println(boxRow(w, fmt.Sprintf("  Frozen     %-10d Hidden       %d", totalFrozen, totalHidden)))
	fmt.Println(boxRow(w, fmt.Sprintf("  Dep Edges  %-10d Orphans      %d", m.DepEdges, m.Orphans)))
	fmt.Println(boxEmpty(w))

	// Per-type table.
	fmt.Println(boxRow(w, "  "+innerTop("By Type", 46)))
	fmt.Println(boxRow(w, fmt.Sprintf("  │ %-9s %4s %4s %4s %-14s │", "TYPE", "PKG", "VER", "UP", "STORAGE")))
	for _, t := range m.Types {
		fmt.Println(boxRow(w, fmt.Sprintf("  │ %-9s %4d %4d %4d %-14s │", t.Type, t.Packages, t.Versions, t.Present, humanSize(t.StorageB))))
	}
	fmt.Println(boxRow(w, "  "+innerBottom(46)))
	fmt.Println(boxEmpty(w))

	// Per-backend table. One volume filling up is the failure a combined
	// storage number cannot show.
	if len(m.Backends) > 0 {
		fmt.Println(boxRow(w, "  "+innerTop("By Backend", 46)))
		fmt.Println(boxRow(w, fmt.Sprintf("  │ %-11s %4s %4s %4s %-13s │", "BACKEND", "UP", "MISS", "ERR", "STORAGE")))
		for _, b := range m.Backends {
			fmt.Println(boxRow(w, fmt.Sprintf("  │ %-11s %4d %4d %4d %-13s │",
				b.Name, b.Present, b.Missing, b.Errors, humanSize(b.StorageB))))
		}
		fmt.Println(boxRow(w, "  "+innerBottom(46)))
		fmt.Println(boxEmpty(w))
	}

	fmt.Println(boxRow(w, fmt.Sprintf("  Activity (24h): %d fetch, %d build, %d create", m.Fetches24h, m.Builds24h, m.Creates24h)))
	fmt.Println(boxEmpty(w))
	fmt.Println(boxBottom(w))
}

func printTypeMetrics(m globalMetrics) {
	for _, t := range m.Types {
		total := t.Present + t.Missing
		pct := 0
		if total > 0 {
			pct = t.Present * 100 / total
		}
		w := 44
		fmt.Println(boxTop(t.Type+" repo", w))
		fmt.Println(boxEmpty(w))
		fmt.Println(boxRow(w, fmt.Sprintf("  Packages   %d", t.Packages)))
		fmt.Println(boxRow(w, fmt.Sprintf("  Versions   %d", t.Versions)))
		fmt.Println(boxRow(w, fmt.Sprintf("  Uploaded   %d/%d (%d%%)", t.Present, total, pct)))
		fmt.Println(boxRow(w, fmt.Sprintf("  Storage    %s", humanSize(t.StorageB))))
		fmt.Println(boxRow(w, fmt.Sprintf("  Frozen     %d", t.Frozen)))
		fmt.Println(boxRow(w, fmt.Sprintf("  Hidden     %d", t.Hidden)))
		fmt.Println(boxEmpty(w))
		fmt.Println(boxBottom(w))
	}
}

// Box drawing helpers.
func boxTop(title string, w int) string {
	t := "─ " + title + " "
	return "╭" + t + strings.Repeat("─", w-len(t)-1) + "╮"
}
func boxBottom(w int) string { return "╰" + strings.Repeat("─", w) + "╯" }
func boxEmpty(w int) string  { return "│" + strings.Repeat(" ", w) + "│" }
func boxRow(w int, content string) string {
	pad := w - len(content)
	if pad < 0 {
		pad = 0
	}
	return "│" + content + strings.Repeat(" ", pad) + "│"
}

func innerTop(title string, w int) string {
	t := "─ " + title + " "
	return "┌" + t + strings.Repeat("─", w-len(t)-1) + "┐"
}
func innerBottom(w int) string { return "└" + strings.Repeat("─", w) + "┘" }

func humanSize(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
