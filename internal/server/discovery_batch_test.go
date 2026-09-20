package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
)

// batchSink stands in for the audit store so the recorder's loss accounting
// can be driven by a store that refuses, or accepts part of, a batch. No real
// sink does either on demand, and the counters B9 R4 kept apart are only
// checkable against a store that misbehaves.
type batchSink struct {
	mu      sync.Mutex
	batches [][]audit.DiscoveryRow
	reply   func(n int) (int, error)
}

func (s *batchSink) RecordDiscovery(_ context.Context, rows ...audit.DiscoveryRow) (int, error) {
	s.mu.Lock()
	s.batches = append(s.batches, append([]audit.DiscoveryRow(nil), rows...))
	s.mu.Unlock()
	if s.reply != nil {
		return s.reply(len(rows))
	}
	return len(rows), nil
}

// sizes returns the batch sizes the sink was handed, and their total.
func (s *batchSink) sizes() ([]int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []int
	total := 0
	for _, b := range s.batches {
		out = append(out, len(b))
		total += len(b)
	}
	return out, total
}

// runRecorder starts a recorder over sink and returns it with a stop function
// that cancels the worker and waits for it to return.
func runRecorder(t *testing.T, sink discoverySink, logger *slog.Logger) (*DiscoveryRecorder, func()) {
	t.Helper()
	rec := &DiscoveryRecorder{db: sink, logger: logger, ch: make(chan audit.DiscoveryRow, discoveryQueueSize)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { rec.Start(ctx); close(done) }()
	return rec, func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("recorder worker did not return after its context was cancelled")
		}
	}
}

func discoveryRow(i int) audit.DiscoveryRow {
	return audit.DiscoveryRow{
		RegistryType: "apt",
		Host:         "archive.ubuntu.com",
		PatternHint:  "archive.ubuntu.com",
		PkgName:      fmt.Sprintf("pkg-%d", i),
		PkgVersion:   "2.10-3",
		Decision:     audit.DecisionAllowed,
		LastClient:   "10.0.0.9",
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
}

// The drain hands the sink batches, not rows. A serial drain passes this test's
// row count and fails its batch-size assertion, which is the whole difference
// E4 is about.
func TestDiscoveryDrainWritesInBatches(t *testing.T) {
	const rows = 300
	sink := &batchSink{}
	rec, stop := runRecorder(t, sink, discardLogger())
	for i := range rows {
		rec.Record(discoveryRow(i))
	}
	stop()

	sizes, total := sink.sizes()
	if total != rows {
		t.Errorf("sink received %d observations, want %d", total, rows)
	}
	if dropped := rec.dropped.Load(); dropped != 0 {
		t.Errorf("dropped = %d with a queue %d deep and %d rows offered", dropped, discoveryQueueSize, rows)
	}
	biggest := 0
	for _, n := range sizes {
		if n > discoveryBatchSize {
			t.Errorf("batch of %d exceeds discoveryBatchSize %d", n, discoveryBatchSize)
		}
		biggest = max(biggest, n)
	}
	if biggest < 2 {
		t.Errorf("largest batch was %d row(s) in %d writes: the drain is still serial", biggest, len(sizes))
	}
}

// R2: whatever the worker is holding when ctx is done reaches the sink before
// Start returns. The rows go in under the batch size and the context is
// cancelled inside the flush interval, so nothing but the shutdown path can
// have written them.
func TestDiscoveryShutdownFlushesThePartialBatch(t *testing.T) {
	const rows = 5
	sink := &batchSink{}
	rec, stop := runRecorder(t, sink, discardLogger())
	for i := range rows {
		rec.Record(discoveryRow(i))
	}
	stop()

	if _, total := sink.sizes(); total != rows {
		t.Errorf("sink received %d observations after shutdown, want %d", total, rows)
	}
}

// R2, the second half: the summary runs after the shutdown flush, not before
// it. If the order were reversed the counter would still be holding the loss
// when Start returned, and the log would say nothing about it.
func TestDiscoveryShutdownSummarizesAfterTheFinalFlush(t *testing.T) {
	const rows = 3
	var log bytes.Buffer
	sink := &batchSink{reply: func(int) (int, error) { return 0, errors.New("audit sink is not accepting rows") }}
	rec, stop := runRecorder(t, sink, slog.New(slog.NewTextHandler(&log, nil)))
	for i := range rows {
		rec.Record(discoveryRow(i))
	}
	stop()

	if failed := rec.failed.Load(); failed != 0 {
		t.Errorf("failed = %d after shutdown: summarize did not run after the final flush", failed)
	}
	got := log.String()
	if !strings.Contains(got, "rejected by the database") || !strings.Contains(got, "failed=3") {
		t.Errorf("shutdown summary did not report the 3 rejected rows:\n%s", got)
	}
}

// R3: a batch the store refuses is len(batch) failures and no drops. Driven
// through flush directly rather than through the worker, so the whole batch is
// one write and the arithmetic is not at the mercy of where the flush interval
// happened to fall.
func TestDiscoveryRefusedBatchCountsFailedNotDropped(t *testing.T) {
	const rows = 10
	var log bytes.Buffer
	sink := &batchSink{reply: func(int) (int, error) { return 0, errors.New("audit sink is not accepting rows") }}
	rec := &DiscoveryRecorder{db: sink, logger: slog.New(slog.NewTextHandler(&log, nil)), ch: make(chan audit.DiscoveryRow, discoveryQueueSize)}

	batch := make([]audit.DiscoveryRow, 0, rows)
	for i := range rows {
		batch = append(batch, discoveryRow(i))
	}
	if left := rec.flush(context.Background(), batch); len(left) != 0 {
		t.Errorf("flush returned %d rows still buffered, want an emptied batch", len(left))
	}

	if failed := rec.failed.Load(); failed != rows {
		t.Errorf("failed = %d after a refused batch of %d, want %d", failed, rows, rows)
	}
	if dropped := rec.dropped.Load(); dropped != 0 {
		t.Errorf("dropped = %d after a refused batch: a store saying no is not backpressure", dropped)
	}
	if got := log.String(); !strings.Contains(got, "lost=10") {
		t.Errorf("batch failure log does not say how many rows it lost:\n%s", got)
	}
}

// R3, the other half: a batch that lands in part costs the counters only the
// part that did not land, and the log names both numbers.
func TestDiscoveryPartialBatchCountsOnlyTheLostRows(t *testing.T) {
	const rows, landed = 10, 4
	var log bytes.Buffer
	sink := &batchSink{reply: func(int) (int, error) { return landed, errors.New("connection reset mid-batch") }}
	rec := &DiscoveryRecorder{db: sink, logger: slog.New(slog.NewTextHandler(&log, nil)), ch: make(chan audit.DiscoveryRow, discoveryQueueSize)}

	batch := make([]audit.DiscoveryRow, 0, rows)
	for i := range rows {
		batch = append(batch, discoveryRow(i))
	}
	rec.flush(context.Background(), batch)

	if failed := rec.failed.Load(); failed != rows-landed {
		t.Errorf("failed = %d after %d of %d rows landed, want %d", failed, landed, rows, rows-landed)
	}
	got := log.String()
	for _, want := range []string{"applied=4", "lost=6"} {
		if !strings.Contains(got, want) {
			t.Errorf("batch failure log does not carry %q:\n%s", want, got)
		}
	}
}
