// Copyright [2019] LinkedIn Corp. Licensed under the Apache License, Version
// 2.0 (the "License"); you may not use this file except in compliance with the
// License.  You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

package goavro

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// frameInfo describes one on-wire OCF block frame and where it lives.
type frameInfo struct {
	offset     int64 // absolute stream offset of the block count varint
	length     int64 // full frame length including the sync marker
	blockCount int64
	nextOffset int64 // absolute offset immediately after this frame
}

// ocfLayout is the result of building an OCF stream for a test.
type ocfLayout struct {
	stream     []byte
	headerLen  int64
	syncMarker [ocfSyncLength]byte
	frames     []frameInfo
}

// buildTestOCF writes an OCF stream of the given compression, one block per
// values slice, and returns the bytes together with the true frame layout so
// tests can assert block offsets against ground truth.
func buildTestOCF(t *testing.T, compression string, values [][]int64) *ocfLayout {
	t.Helper()
	buf := new(bytes.Buffer)
	ocfw, err := NewOCFWriter(OCFConfig{
		W:               buf,
		Schema:          `{"type":"long"}`,
		CompressionName: compression,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range values {
		if err := ocfw.Append(v); err != nil {
			t.Fatal(err)
		}
	}
	stream := buf.Bytes()

	parsed, headerLen, err := parseOCFHeaderPrefix(stream)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) > 0 && int(headerLen) >= len(stream) {
		t.Fatalf("header length %d consumes whole stream of %d bytes", headerLen, len(stream))
	}

	var frames []frameInfo
	off := headerLen
	for off < int64(len(stream)) {
		pos := off
		count, n, err := readBufferedVarint(stream[pos:])
		if err != nil {
			t.Fatalf("read block count at %d: %s", pos, err)
		}
		pos += n
		size, n, err := readBufferedVarint(stream[pos:])
		if err != nil {
			t.Fatalf("read block size at %d: %s", pos, err)
		}
		pos += n
		frameLen := pos - off + size + ocfSyncLength
		if off+frameLen > int64(len(stream)) {
			t.Fatalf("frame at %d extends past end of stream", off)
		}
		next := off + frameLen
		frames = append(frames, frameInfo{
			offset:     off,
			length:     frameLen,
			blockCount: count,
			nextOffset: next,
		})
		off = next
	}

	return &ocfLayout{
		stream:     stream,
		headerLen:  headerLen,
		syncMarker: parsed.syncMarker,
		frames:     frames,
	}
}

// recordingSink is an OCFBlockSink that records deliveries, optionally fails a
// configurable number of times, and (optionally) validates each delivery
// against the known frame layout.
type recordingSink struct {
	delivered []OCFBlockKey
	records   map[int64][]interface{}
	failNext  int
	layout    *ocfLayout
	err       error
}

func newRecordingSink() *recordingSink {
	return &recordingSink{records: make(map[int64][]interface{}), err: errors.New("sink forced failure")}
}

func (s *recordingSink) AddBlock(key OCFBlockKey, records []interface{}) error {
	if s.failNext > 0 {
		s.failNext--
		return s.err
	}
	if s.layout != nil {
		// Verify the stable key points at a real frame and the record count
		// matches that frame's declared block count.
		idx := int(-1)
		for i, f := range s.layout.frames {
			if f.offset == key.BlockOffset {
				idx = i
				break
			}
		}
		if idx < 0 {
			return fmt.Errorf("unexpected block offset %d not in layout", key.BlockOffset)
		}
		if int64(len(records)) != s.layout.frames[idx].blockCount {
			return fmt.Errorf("block at %d delivered %d records, want %d",
				key.BlockOffset, len(records), s.layout.frames[idx].blockCount)
		}
	}
	s.delivered = append(s.delivered, key)
	copied := make([]interface{}, len(records))
	copy(copied, records)
	s.records[key.BlockOffset] = copied
	return nil
}

// pushInChunks feeds stream to the collector in fixed-size chunks, returning
// the first error encountered.
func pushInChunks(t *testing.T, c *OCFCollector, stream []byte, chunk int) error {
	t.Helper()
	for start := 0; start < len(stream); start += chunk {
		end := start + chunk
		if end > len(stream) {
			end = len(stream)
		}
		if err := c.Push(stream[start:end]); err != nil {
			return err
		}
	}
	return nil
}

// assertAllFramesDelivered verifies every frame in the layout was delivered, in
// order, with matching source epoch and offsets.
func assertAllFramesDelivered(t *testing.T, sink *recordingSink, epoch string, layout *ocfLayout) {
	t.Helper()
	if got, want := len(sink.delivered), len(layout.frames); got != want {
		t.Fatalf("delivered %d blocks, want %d", got, want)
	}
	for i, f := range layout.frames {
		if sink.delivered[i].SourceEpoch != epoch {
			t.Errorf("frame %d source epoch = %q, want %q", i, sink.delivered[i].SourceEpoch, epoch)
		}
		if sink.delivered[i].BlockOffset != f.offset {
			t.Errorf("frame %d offset = %d, want %d", i, sink.delivered[i].BlockOffset, f.offset)
		}
	}
}

func TestOCFCollectorNewValidation(t *testing.T) {
	if _, err := NewOCFCollector(OCFCollectorConfig{}); err == nil {
		t.Fatal("expected error when Sink is nil")
	}
	sink := newRecordingSink()
	if _, err := NewOCFCollector(OCFCollectorConfig{Sink: sink}); err == nil {
		t.Fatal("expected error when SourceEpoch is empty")
	}

	badBookmark := &OCFBookmark{SourceEpoch: "e", Header: []byte("not-an-ocf-header"), NextOffset: 0}
	if _, err := NewOCFCollector(OCFCollectorConfig{Sink: sink, Bookmark: badBookmark}); err == nil {
		t.Fatal("expected error for bookmark with invalid header")
	}

	layout := buildTestOCF(t, CompressionNullLabel, [][]int64{{1, 2}})
	goodBookmark := &OCFBookmark{SourceEpoch: "e", Header: layout.stream[:layout.headerLen], NextOffset: layout.headerLen}
	c, err := NewOCFCollector(OCFCollectorConfig{Sink: sink, Bookmark: goodBookmark})
	if err != nil {
		t.Fatalf("valid bookmark rejected: %s", err)
	}
	if bm := c.Bookmark(); bm.NextOffset != layout.headerLen {
		t.Errorf("resume NextOffset = %d, want %d", bm.NextOffset, layout.headerLen)
	}
}

func TestOCFCollectorDeliversBlocksWithStableOffsets(t *testing.T) {
	layout := buildTestOCF(t, CompressionNullLabel, [][]int64{{1, 2}, {3}, {4, 5, 6}})
	sink := newRecordingSink()
	sink.layout = layout
	const epoch = "stream-1"

	c, err := NewOCFCollector(OCFCollectorConfig{Sink: sink, SourceEpoch: epoch})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Push(layout.stream); err != nil {
		t.Fatal(err)
	}
	if err := c.Finish(); err != nil {
		t.Fatal(err)
	}

	assertAllFramesDelivered(t, sink, epoch, layout)

	// The native values must survive intact.
	first := sink.records[layout.frames[0].offset]
	if len(first) != 2 || first[0].(int64) != 1 || first[1].(int64) != 2 {
		t.Errorf("first block records = %v, want [1 2]", first)
	}

	bm := c.Bookmark()
	wantNext := layout.frames[len(layout.frames)-1].nextOffset
	if bm.NextOffset != wantNext {
		t.Errorf("bookmark NextOffset = %d, want %d", bm.NextOffset, wantNext)
	}
	if !bytes.Equal(bm.Header, layout.stream[:layout.headerLen]) {
		t.Error("bookmark header does not match on-wire header bytes")
	}
	if bm.SourceEpoch != epoch {
		t.Errorf("bookmark SourceEpoch = %q, want %q", bm.SourceEpoch, epoch)
	}
}

func TestOCFCollectorByteByByteAcrossAllBoundaries(t *testing.T) {
	for _, compression := range []string{CompressionNullLabel, CompressionDeflateLabel, CompressionSnappyLabel} {
		compression := compression
		t.Run(compression, func(t *testing.T) {
			layout := buildTestOCF(t, compression, [][]int64{{10, 20}, {30, 40, 50}})
			sink := newRecordingSink()
			sink.layout = layout

			c, err := NewOCFCollector(OCFCollectorConfig{Sink: sink, SourceEpoch: "e"})
			if err != nil {
				t.Fatal(err)
			}
			// A 1-byte chunk splits the header, both varints, the (possibly
			// compressed) body and the sync marker at every byte boundary.
			if err := pushInChunks(t, c, layout.stream, 1); err != nil {
				t.Fatal(err)
			}
			if err := c.Finish(); err != nil {
				t.Fatal(err)
			}
			assertAllFramesDelivered(t, sink, "e", layout)
		})
	}
}

func TestOCFCollectorVariousChunkSizes(t *testing.T) {
	layout := buildTestOCF(t, CompressionDeflateLabel, [][]int64{{1}, {2, 3}, {4, 5, 6, 7}})
	for _, chunk := range []int{1, 2, 3, 5, 7, 64, 4096} {
		chunk := chunk
		t.Run(fmt.Sprintf("chunk-%d", chunk), func(t *testing.T) {
			sink := newRecordingSink()
			sink.layout = layout
			c, err := NewOCFCollector(OCFCollectorConfig{Sink: sink, SourceEpoch: "e"})
			if err != nil {
				t.Fatal(err)
			}
			if err := pushInChunks(t, c, layout.stream, chunk); err != nil {
				t.Fatal(err)
			}
			if err := c.Finish(); err != nil {
				t.Fatal(err)
			}
			assertAllFramesDelivered(t, sink, "e", layout)
		})
	}
}

func TestOCFCollectorIncompleteHeaderAwaitsThenCompletes(t *testing.T) {
	layout := buildTestOCF(t, CompressionNullLabel, [][]int64{{1}})
	sink := newRecordingSink()
	c, err := NewOCFCollector(OCFCollectorConfig{Sink: sink, SourceEpoch: "e"})
	if err != nil {
		t.Fatal(err)
	}
	// Push only part of the header: no block may be delivered and no error yet.
	split := 3
	if err := c.Push(layout.stream[:split]); err != nil {
		t.Fatalf("partial header push returned error: %s", err)
	}
	if len(sink.delivered) != 0 {
		t.Fatalf("delivered %d blocks from a partial header", len(sink.delivered))
	}
	if err := c.Push(layout.stream[split:]); err != nil {
		t.Fatal(err)
	}
	if err := c.Finish(); err != nil {
		t.Fatal(err)
	}
	assertAllFramesDelivered(t, sink, "e", layout)
}

func TestOCFCollectorFinishRejectsIncompleteFrames(t *testing.T) {
	layout := buildTestOCF(t, CompressionNullLabel, [][]int64{{1, 2}, {3}})
	lastFrame := layout.frames[len(layout.frames)-1]

	// Truncate at several points inside the final frame: inside the count
	// varint, inside the body, and inside the sync marker.
	cutPoints := []int64{
		lastFrame.offset + 1,                   // inside block count varint region
		lastFrame.offset + 3,                   // inside block body
		lastFrame.nextOffset - 1,               // one byte short of full sync
		lastFrame.nextOffset - ocfSyncLength/2, // mid sync marker
	}
	for i, cut := range cutPoints {
		sink := newRecordingSink()
		c, err := NewOCFCollector(OCFCollectorConfig{Sink: sink, SourceEpoch: "e"})
		if err != nil {
			t.Fatal(err)
		}
		// Pushing the truncated prefix must not error: the frame is awaited.
		if err := c.Push(layout.stream[:cut]); err != nil {
			t.Fatalf("case %d: truncated Push errored: %s", i, err)
		}
		err = c.Finish()
		if !errors.Is(err, ErrOCFIncompleteFrame) {
			t.Fatalf("case %d: Finish error = %v, want ErrOCFIncompleteFrame", i, err)
		}
		// Only the frames fully before the cut may have been delivered.
		for _, k := range sink.delivered {
			if k.BlockOffset >= cut {
				t.Errorf("case %d: delivered block at %d beyond cut %d", i, k.BlockOffset, cut)
			}
		}
	}
}

func TestOCFCollectorFinishEmptyStreamIsIncompleteNotEOF(t *testing.T) {
	c, err := NewOCFCollector(OCFCollectorConfig{Sink: newRecordingSink(), SourceEpoch: "e"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Finish(); !errors.Is(err, ErrOCFIncompleteFrame) {
		t.Fatalf("Finish on empty stream = %v, want ErrOCFIncompleteFrame", err)
	}
}

func TestOCFCollectorHeaderOnlyFinishOK(t *testing.T) {
	layout := buildTestOCF(t, CompressionNullLabel, nil)
	c, err := NewOCFCollector(OCFCollectorConfig{Sink: newRecordingSink(), SourceEpoch: "e"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Push(layout.stream); err != nil {
		t.Fatal(err)
	}
	if err := c.Finish(); err != nil {
		t.Fatalf("header-only Finish = %s", err)
	}
}

func TestOCFCollectorCorruptBlockLeaksNoRecords(t *testing.T) {
	layout := buildTestOCF(t, CompressionNullLabel, [][]int64{{1, 2}})
	sync := layout.syncMarker

	// Build a frame declaring 3 records but whose third record is an
	// unterminated varint: the first two records decode, the third fails.
	codec := layout // reuse header from a valid stream
	var body []byte
	for _, v := range []int64{7, 8} {
		body, _ = longBinaryFromNative(body, v)
	}
	body = append(body, 0xff) // continuation byte with no terminator -> short buffer
	var frame []byte
	frame, _ = longBinaryFromNative(frame, 3)
	frame, _ = longBinaryFromNative(frame, len(body))
	frame = append(frame, body...)
	frame = append(frame, sync[:]...)

	stream := append(append([]byte(nil), codec.stream[:codec.headerLen]...), frame...)

	sink := newRecordingSink()
	c, err := NewOCFCollector(OCFCollectorConfig{Sink: sink, SourceEpoch: "e"})
	if err != nil {
		t.Fatal(err)
	}
	// Split the corrupt frame to prove the failure is not chunk-dependent.
	if err := pushInChunks(t, c, stream, 3); err == nil {
		t.Fatal("expected decode error for corrupt block, got nil")
	}
	if len(sink.delivered) != 0 {
		t.Fatalf("corrupt block leaked %d delivery/deliveries to the sink", len(sink.delivered))
	}
	// A framing/decoding failure is permanent for the stream.
	if err := c.Push([]byte{0}); !errors.Is(err, c.hardErr) && err == nil {
		t.Fatalf("push after hard error returned nil; hardErr=%v", c.hardErr)
	}
}

func TestOCFCollectorMalformedHeaderIsHardErrorNotAwait(t *testing.T) {
	sink := newRecordingSink()
	c, err := NewOCFCollector(OCFCollectorConfig{Sink: sink, SourceEpoch: "e"})
	if err != nil {
		t.Fatal(err)
	}
	// Bad magic bytes are structurally invalid, not a truncation: Push must
	// fail immediately rather than wait for more bytes.
	if err := c.Push([]byte("Obj\x01BADMAGIC")); err == nil {
		t.Fatal("expected hard error for malformed header, got nil")
	}
	if len(sink.delivered) != 0 {
		t.Fatal("malformed header must not deliver any block")
	}
	// A structural header error is permanent for the stream.
	if err := c.Push([]byte("more")); err == nil {
		t.Fatal("expected the collector to remain in a hard-error state")
	}
}

func TestOCFCollectorOverlongVarintIsHardError(t *testing.T) {
	layout := buildTestOCF(t, CompressionNullLabel, [][]int64{{1}})
	sink := newRecordingSink()
	c, err := NewOCFCollector(OCFCollectorConfig{Sink: sink, SourceEpoch: "e"})
	if err != nil {
		t.Fatal(err)
	}
	// Header, then a block count varint with 11 continuation bytes: this can
	// never encode a valid 64-bit long and is a framing error, not a wait.
	stream := append([]byte(nil), layout.stream[:layout.headerLen]...)
	stream = append(stream, bytes.Repeat([]byte{0x80}, 11)...)
	if err := c.Push(stream); err == nil {
		t.Fatal("expected hard error for overlong varint, got nil")
	}
	if errors.Is(c.hardErr, ErrOCFIncompleteFrame) {
		t.Fatal("overlong varint must be a hard framing error, not an incomplete frame")
	}
}

func TestOCFCollectorSyncMarkerMismatch(t *testing.T) {
	layout := buildTestOCF(t, CompressionNullLabel, [][]int64{{1}})
	bad := append([]byte(nil), layout.stream...)
	// Flip the last byte (final byte of the sync marker).
	bad[len(bad)-1] ^= 0xff

	sink := newRecordingSink()
	c, err := NewOCFCollector(OCFCollectorConfig{Sink: sink, SourceEpoch: "e"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Push(bad); err == nil {
		t.Fatal("expected sync marker mismatch error")
	}
	if len(sink.delivered) != 0 {
		t.Fatal("mismatched-sync block must not reach the sink")
	}
}

func TestOCFCollectorSinkFailureRetrySameKey(t *testing.T) {
	layout := buildTestOCF(t, CompressionNullLabel, [][]int64{{1}, {2, 3}})
	sink := newRecordingSink()
	sink.layout = layout
	sink.failNext = 2 // first two delivery attempts fail

	c, err := NewOCFCollector(OCFCollectorConfig{Sink: sink, SourceEpoch: "e"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Push(layout.stream); err == nil {
		t.Fatal("expected sink error on first Push")
	}
	if len(sink.delivered) != 0 {
		t.Fatal("failed sink must not count as delivered")
	}
	// Bookmark must not have advanced past the header while nothing is acked.
	if bm := c.Bookmark(); bm.NextOffset != layout.headerLen {
		t.Errorf("NextOffset after failed sink = %d, want %d", bm.NextOffset, layout.headerLen)
	}
	// Empty Push retries the same block with the same stable key.
	if err := c.Push(nil); err == nil {
		t.Fatal("expected second forced failure")
	}
	if err := c.Push(nil); err != nil { // third attempt: sink now succeeds
		t.Fatalf("retry delivery failed: %s", err)
	}
	if err := c.Finish(); err != nil {
		t.Fatal(err)
	}
	assertAllFramesDelivered(t, sink, "e", layout)
}

func TestOCFCollectorBookmarkResumeSkipsOldBytes(t *testing.T) {
	layout := buildTestOCF(t, CompressionNullLabel, [][]int64{{1}, {2}, {3}})
	epoch := "resume-epoch"

	// First collector: deliver the first two blocks, then capture a bookmark.
	sink1 := newRecordingSink()
	sink1.layout = layout
	c1, err := NewOCFCollector(OCFCollectorConfig{Sink: sink1, SourceEpoch: epoch})
	if err != nil {
		t.Fatal(err)
	}
	secondFrameEnd := layout.frames[1].nextOffset
	if err := c1.Push(layout.stream[:secondFrameEnd]); err != nil {
		t.Fatal(err)
	}
	bm := c1.Bookmark()
	if bm.NextOffset != secondFrameEnd {
		t.Fatalf("bookmark NextOffset = %d, want %d", bm.NextOffset, secondFrameEnd)
	}

	// Resume: push ONLY bytes at or past the boundary. No rescan of old bytes.
	sink2 := newRecordingSink()
	c2, err := NewOCFCollector(OCFCollectorConfig{
		Sink:     sink2,
		Bookmark: &bm,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pushInChunks(t, c2, layout.stream[secondFrameEnd:], 2); err != nil {
		t.Fatal(err)
	}
	if err := c2.Finish(); err != nil {
		t.Fatal(err)
	}
	if len(sink2.delivered) != 1 {
		t.Fatalf("resumed collector delivered %d blocks, want 1", len(sink2.delivered))
	}
	wantOffset := layout.frames[2].offset
	if got := sink2.delivered[0].BlockOffset; got != wantOffset {
		t.Errorf("resumed block offset = %d, want %d", got, wantOffset)
	}
	if got := sink2.delivered[0].SourceEpoch; got != epoch {
		t.Errorf("resumed block epoch = %q, want %q", got, epoch)
	}
	if bm2 := c2.Bookmark(); bm2.NextOffset != layout.frames[2].nextOffset {
		t.Errorf("final bookmark = %d, want %d", bm2.NextOffset, layout.frames[2].nextOffset)
	}
}

func TestOCFCollectorResumeFromHeaderBoundaryFinishEmpty(t *testing.T) {
	layout := buildTestOCF(t, CompressionNullLabel, [][]int64{{1}})
	bm := OCFBookmark{
		SourceEpoch: "e",
		Header:      layout.stream[:layout.headerLen],
		NextOffset:  layout.headerLen,
	}
	c, err := NewOCFCollector(OCFCollectorConfig{Sink: newRecordingSink(), Bookmark: &bm})
	if err != nil {
		t.Fatal(err)
	}
	// No new bytes and nothing pending: a clean finish at the boundary.
	if err := c.Finish(); err != nil {
		t.Fatalf("Finish at clean boundary = %s", err)
	}
}

func TestOCFCollectorPendingFrameLimitBackPressure(t *testing.T) {
	layout := buildTestOCF(t, CompressionNullLabel, [][]int64{{1}, {2}, {3}})
	sink := newRecordingSink()
	sink.layout = layout
	sink.failNext = 1 << 30 // sink is down for the whole test until reset

	c, err := NewOCFCollector(OCFCollectorConfig{
		Sink:             sink,
		SourceEpoch:      "e",
		MaxPendingFrames: 2,
	})
	if err != nil {
		t.Fatal(err)
	}

	// A fresh collector must receive the header before any block frames.
	if err := c.Push(layout.stream[:layout.headerLen]); err != nil {
		t.Fatalf("header push failed: %s", err)
	}

	// Block 1: validated but sink fails, stays queued.
	if err := c.Push(layout.stream[layout.frames[0].offset:layout.frames[0].nextOffset]); err == nil {
		t.Fatal("expected sink failure for block 1")
	}
	// Block 2: queued behind block 1.
	b2 := layout.stream[layout.frames[1].offset:layout.frames[1].nextOffset]
	if err := c.Push(b2); err == nil {
		t.Fatal("expected sink failure while block 1 is still pending")
	}
	// Block 3: queue is at capacity and the sink is still down. The flush
	// attempt fails on the sink, so the offered bytes are refused and not
	// retained (back-pressure).
	b3 := layout.stream[layout.frames[2].offset:layout.frames[2].nextOffset]
	if err := c.Push(b3); err == nil {
		t.Fatalf("block 3 Push succeeded against a saturated queue and failed sink")
	}
	if len(c.queue) != 2 {
		t.Fatalf("queue length = %d, want 2 (block 3 must not have been retained)", len(c.queue))
	}

	// Recover the sink. The queue is saturated, so first flush the blocks
	// already retained (the refused block 3 bytes were never kept), then replay
	// block 3.
	sink.failNext = 0
	if err := c.Push(nil); err != nil {
		t.Fatalf("flush after sink recovery failed: %s", err)
	}
	if err := c.Push(b3); err != nil {
		t.Fatalf("replay after recovery failed: %s", err)
	}
	if err := c.Finish(); err != nil {
		t.Fatal(err)
	}
	assertAllFramesDelivered(t, sink, "e", layout)
}

func TestOCFCollectorPendingFrameLimitErrorWhenSinkDown(t *testing.T) {
	layout := buildTestOCF(t, CompressionNullLabel, [][]int64{{1}, {2}})
	sink := newRecordingSink()
	sink.failNext = 1 << 30 // sink is down for the whole test until reset

	c, err := NewOCFCollector(OCFCollectorConfig{
		Sink:             sink,
		SourceEpoch:      "e",
		MaxPendingFrames: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Push(layout.stream[:layout.headerLen]); err != nil {
		t.Fatalf("header push failed: %s", err)
	}
	// First block validates, then stalls behind the failing sink.
	b1 := layout.stream[layout.frames[0].offset:layout.frames[0].nextOffset]
	if err := c.Push(b1); err == nil {
		t.Fatal("expected sink failure for block 1")
	}
	// Second block: queue full, the forced flush also fails, so the limit
	// error is surfaced and the bytes are not retained.
	b2 := layout.stream[layout.frames[1].offset:layout.frames[1].nextOffset]
	if err := c.Push(b2); !errors.Is(err, ErrOCFPendingFrameLimit) {
		t.Fatalf("block 2 Push error = %v, want ErrOCFPendingFrameLimit", err)
	}
	if len(c.queue) != 1 {
		t.Fatalf("queue length = %d, want 1 (block 2 must not be retained)", len(c.queue))
	}
	if len(sink.delivered) != 0 {
		t.Fatal("no block may be delivered while the sink is down")
	}

	// Recover: the queue drains, and the refused block can be replayed.
	sink.failNext = 0
	if err := c.Push(nil); err != nil {
		t.Fatalf("flush after recovery failed: %s", err)
	}
	if err := c.Push(b2); err != nil {
		t.Fatalf("replay failed: %s", err)
	}
	if err := c.Finish(); err != nil {
		t.Fatal(err)
	}
	assertAllFramesDelivered(t, sink, "e", layout)
}

func TestOCFCollectorSurfacesSinkErrorDuringLargePush(t *testing.T) {
	layout := buildTestOCF(t, CompressionNullLabel, [][]int64{{1}, {2}, {3}, {4}})
	sink := newRecordingSink()
	sink.failNext = 1 << 30 // sink stays down

	c, err := NewOCFCollector(OCFCollectorConfig{
		Sink:             sink,
		SourceEpoch:      "e",
		MaxPendingFrames: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	// One Push carries the entire stream, forcing drain's internal at-limit
	// flush path. With the sink down that flush must return its error rather
	// than swallow it.
	if err := c.Push(layout.stream); err == nil {
		t.Fatal("expected sink error to surface from a large single Push")
	}
	if len(sink.delivered) != 0 {
		t.Fatal("no block may be delivered while the sink is down")
	}
	if int64(len(c.queue)) > 2 {
		t.Fatalf("queue grew to %d, exceeding MaxPendingFrames=2", len(c.queue))
	}

	// Recover and confirm every block is still delivered exactly once, in order.
	sink.failNext = 0
	if err := c.Push(nil); err != nil {
		t.Fatalf("flush after recovery failed: %s", err)
	}
	if err := c.Finish(); err != nil {
		t.Fatal(err)
	}
	assertAllFramesDelivered(t, sink, "e", layout)
}

func TestOCFCollectorClosedRejectsFurtherInput(t *testing.T) {
	layout := buildTestOCF(t, CompressionNullLabel, [][]int64{{1}})
	c, err := NewOCFCollector(OCFCollectorConfig{Sink: newRecordingSink(), SourceEpoch: "e"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Push(layout.stream); err != nil {
		t.Fatal(err)
	}
	if err := c.Finish(); err != nil {
		t.Fatal(err)
	}
	if err := c.Push(layout.stream); !errors.Is(err, ErrOCFCollectorClosed) {
		t.Errorf("Push after Finish = %v, want ErrOCFCollectorClosed", err)
	}
	if err := c.Finish(); !errors.Is(err, ErrOCFCollectorClosed) {
		t.Errorf("second Finish = %v, want ErrOCFCollectorClosed", err)
	}
}

func TestOCFCollectorDoesNotRetainInputBuffer(t *testing.T) {
	layout := buildTestOCF(t, CompressionNullLabel, [][]int64{{123}})
	sink := newRecordingSink()
	c, err := NewOCFCollector(OCFCollectorConfig{Sink: sink, SourceEpoch: "e"})
	if err != nil {
		t.Fatal(err)
	}
	chunk := append([]byte(nil), layout.stream...)
	if err := c.Push(chunk); err != nil {
		t.Fatal(err)
	}
	// Mutate the caller's buffer after Push. The collector must have copied it.
	for i := range chunk {
		chunk[i] = 0
	}
	if err := c.Finish(); err != nil {
		t.Fatal(err)
	}
	got := sink.records[layout.frames[0].offset]
	if len(got) != 1 || got[0].(int64) != 123 {
		t.Fatalf("record after input mutation = %v, want [123]", got)
	}
}

func TestOCFCollectorPreservesNativeGoTypes(t *testing.T) {
	schema := `{
		"type":"record",
		"name":"Mix",
		"fields":[
			{"name":"s","type":"string"},
			{"name":"l","type":"long"},
			{"name":"d","type":"double"},
			{"name":"b","type":"boolean"},
			{"name":"u","type":["null","string"]}
		]
	}`
	buf := new(bytes.Buffer)
	ocfw, err := NewOCFWriter(OCFConfig{W: buf, Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	datum := map[string]interface{}{
		"s": "hello",
		"l": int64(-99),
		"d": float64(2.5),
		"b": true,
		"u": map[string]interface{}{"string": "tail"},
	}
	if err := ocfw.Append([]interface{}{datum}); err != nil {
		t.Fatal(err)
	}
	stream := buf.Bytes()

	var got interface{}
	sink := OCFBlockSinkFunc(func(_ OCFBlockKey, records []interface{}) error {
		got = records[0]
		return nil
	})
	c, err := NewOCFCollector(OCFCollectorConfig{Sink: sink, SourceEpoch: "e"})
	if err != nil {
		t.Fatal(err)
	}
	if err := pushInChunks(t, c, stream, 4); err != nil {
		t.Fatal(err)
	}
	if err := c.Finish(); err != nil {
		t.Fatal(err)
	}

	rec, ok := got.(map[string]interface{})
	if !ok {
		t.Fatalf("decoded record type = %T, want map[string]interface{}", got)
	}
	if rec["s"] != "hello" {
		t.Errorf("string field = %v (%T), want hello", rec["s"], rec["s"])
	}
	if rec["l"] != int64(-99) {
		t.Errorf("long field = %v (%T), want int64(-99)", rec["l"], rec["l"])
	}
	if rec["d"] != float64(2.5) {
		t.Errorf("double field = %v (%T), want 2.5", rec["d"], rec["d"])
	}
	if rec["b"] != true {
		t.Errorf("boolean field = %v (%T), want true", rec["b"], rec["b"])
	}
	union, ok := rec["u"].(map[string]interface{})
	if !ok || union["string"] != "tail" {
		t.Errorf("union field = %#v, want map with string=tail", rec["u"])
	}
}

func TestOCFCollectorSinkFuncAdapter(t *testing.T) {
	layout := buildTestOCF(t, CompressionNullLabel, [][]int64{{42}})
	var seen int
	sink := OCFBlockSinkFunc(func(key OCFBlockKey, records []interface{}) error {
		seen += len(records)
		return nil
	})
	c, err := NewOCFCollector(OCFCollectorConfig{Sink: sink, SourceEpoch: "e"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Push(layout.stream); err != nil {
		t.Fatal(err)
	}
	if err := c.Finish(); err != nil {
		t.Fatal(err)
	}
	if seen != 1 {
		t.Errorf("sink func saw %d records, want 1", seen)
	}
}
