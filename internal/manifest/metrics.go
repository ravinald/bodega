package manifest

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

const metricsFile = "metrics.json"

// Metrics holds precomputed repository statistics.
// Updated by build/create/delete operations and cached in metrics.json.
type Metrics struct {
	Global    GlobalMetrics            `json:"global"`
	ByType    map[string]TypeMetrics   `json:"by_type"`
	UpdatedAt string                   `json:"updated_at"`
}

// GlobalMetrics holds aggregate stats across all types.
type GlobalMetrics struct {
	Packages   int   `json:"packages"`
	Versions   int   `json:"versions"`
	Frozen     int   `json:"frozen"`
	Hidden     int   `json:"hidden"`
	DepEdges   int   `json:"dep_edges"`
	Orphans    int   `json:"orphans"`
	StorageB   int64 `json:"storage_bytes,omitempty"`
}

// TypeMetrics holds stats for a single package type.
type TypeMetrics struct {
	Packages   int   `json:"packages"`
	Versions   int   `json:"versions"`
	Frozen     int   `json:"frozen"`
	Hidden     int   `json:"hidden"`
	StorageB   int64 `json:"storage_bytes,omitempty"`
}

// ComputeMetrics builds fresh metrics from the current store state.
func (s *Store) ComputeMetrics(ctx context.Context) *Metrics {
	m := &Metrics{
		ByType:    make(map[string]TypeMetrics),
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	for _, typ := range AllTypes {
		tm := TypeMetrics{}
		for _, name := range s.ListPackages(typ) {
			pm, err := s.GetPackage(ctx, typ, name)
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
				tm.StorageB += ve.ArtifactSize
			}
		}
		m.ByType[typ] = tm
		m.Global.Packages += tm.Packages
		m.Global.Versions += tm.Versions
		m.Global.Frozen += tm.Frozen
		m.Global.Hidden += tm.Hidden
		m.Global.StorageB += tm.StorageB
	}

	m.Global.DepEdges = len(s.AllEdges())
	m.Global.Orphans = len(s.Orphans())

	return m
}

// SaveMetrics computes and persists metrics to the backend.
func (s *Store) SaveMetrics(ctx context.Context) error {
	m := s.ComputeMetrics(ctx)
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal metrics: %w", err)
	}
	data = append(data, '\n')
	b := s.resolveBackend()
	return b.Write(ctx, metricsFile, data)
}

// LoadMetrics reads cached metrics from the backend.
// Returns nil if no metrics file exists yet.
func (s *Store) LoadMetrics(ctx context.Context) (*Metrics, error) {
	b := s.resolveBackend()
	data, err := b.Read(ctx, metricsFile)
	if err != nil {
		return nil, fmt.Errorf("read metrics: %w", err)
	}
	if data == nil {
		return nil, nil
	}
	var m Metrics
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse metrics: %w", err)
	}
	return &m, nil
}
