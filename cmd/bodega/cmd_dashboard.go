package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	bos3 "github.com/ravinald/bodega/internal/s3"
)

type typeMetrics struct {
	Type       string
	Packages   int
	Versions   int
	S3Uploaded int
	S3Missing  int
	StorageB   int64
	Frozen     int
	Hidden     int
}

type globalMetrics struct {
	Types      []typeMetrics
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

			// Collect S3 statuses if bucket is configured.
			var statuses []bos3.EntryStatus
			if cfg.Bucket != "" {
				client, err := bos3.NewClient(ctx, cfg.Bucket, cfg.Region)
				if err == nil {
					statuses, _ = bos3.CheckStatus(ctx, client, store, manifest.AllTypes)
				}
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

			// Build S3 lookup maps.
			s3map := make(map[string]bool)
			sizeMap := make(map[string]int64)
			for _, st := range statuses {
				s3map[st.Type+"/"+st.Name] = st.InS3
				if st.InS3 {
					sizeMap[st.Type] += st.SizeS3
				}
			}

			// Collect per-type metrics.
			metrics := globalMetrics{
				DepEdges:   len(store.AllEdges()),
				Orphans:    len(store.Orphans()),
				Fetches24h: fetches24h,
				Builds24h:  builds24h,
				Creates24h: creates24h,
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
							tm.S3Uploaded++
						} else {
							tm.S3Missing++
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
	totalPkg, totalVer, totalS3, totalMissing, totalFrozen, totalHidden := 0, 0, 0, 0, 0, 0
	var totalStorage int64
	for _, t := range m.Types {
		totalPkg += t.Packages
		totalVer += t.Versions
		totalS3 += t.S3Uploaded
		totalMissing += t.S3Missing
		totalFrozen += t.Frozen
		totalHidden += t.Hidden
		totalStorage += t.StorageB
	}

	total := totalS3 + totalMissing
	pct := 0
	if total > 0 {
		pct = totalS3 * 100 / total
	}

	w := 52
	fmt.Println(boxTop("bodega status", w))
	fmt.Println(boxEmpty(w))
	fmt.Println(boxRow(w, fmt.Sprintf("  Packages   %-10d S3 Coverage  %d/%d (%d%%)", totalPkg, totalS3, total, pct)))
	fmt.Println(boxRow(w, fmt.Sprintf("  Versions   %-10d Storage      %s", totalVer, humanSize(totalStorage))))
	fmt.Println(boxRow(w, fmt.Sprintf("  Frozen     %-10d Hidden       %d", totalFrozen, totalHidden)))
	fmt.Println(boxRow(w, fmt.Sprintf("  Dep Edges  %-10d Orphans      %d", m.DepEdges, m.Orphans)))
	fmt.Println(boxEmpty(w))

	// Per-type table.
	fmt.Println(boxRow(w, "  "+innerTop("By Type", 46)))
	fmt.Println(boxRow(w, fmt.Sprintf("  │ %-9s %4s %4s %4s %-14s │", "TYPE", "PKG", "VER", "S3", "STORAGE")))
	for _, t := range m.Types {
		fmt.Println(boxRow(w, fmt.Sprintf("  │ %-9s %4d %4d %4d %-14s │", t.Type, t.Packages, t.Versions, t.S3Uploaded, humanSize(t.StorageB))))
	}
	fmt.Println(boxRow(w, "  "+innerBottom(46)))
	fmt.Println(boxEmpty(w))

	fmt.Println(boxRow(w, fmt.Sprintf("  Activity (24h): %d fetch, %d build, %d create", m.Fetches24h, m.Builds24h, m.Creates24h)))
	fmt.Println(boxEmpty(w))
	fmt.Println(boxBottom(w))
}

func printTypeMetrics(m globalMetrics) {
	for _, t := range m.Types {
		total := t.S3Uploaded + t.S3Missing
		pct := 0
		if total > 0 {
			pct = t.S3Uploaded * 100 / total
		}
		w := 44
		fmt.Println(boxTop(t.Type+" repo", w))
		fmt.Println(boxEmpty(w))
		fmt.Println(boxRow(w, fmt.Sprintf("  Packages   %d", t.Packages)))
		fmt.Println(boxRow(w, fmt.Sprintf("  Versions   %d", t.Versions)))
		fmt.Println(boxRow(w, fmt.Sprintf("  S3         %d/%d (%d%%)", t.S3Uploaded, total, pct)))
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
