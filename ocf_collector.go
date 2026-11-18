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
	"io"
)

const (
	// defaultMaxPendingFrames bounds the number of complete, fully validated
	// OCF blocks that may be retained by an OCFCollector while waiting for the
	// sink to accept them. It is a back-pressure guard against unbounded memory
	// growth when the sink keeps failing.
	defaultMaxPendingFrames = 1024

	// maxVarintLength is the largest number of bytes a valid zig-zag encoded
	// 64-bit integer can occupy. A longer run of continuation bytes cannot
	// encode a long and is therefore a hard framing error rather than a
	// truncated frame.
	maxVarintLength = 10
)

var (
	// ErrOCFCollectorClosed is returned when Push or Finish is called after the
	// collector has been closed by a prior Finish call.
	ErrOCFCollectorClosed = errors.New("OCFCollector: collector is closed")

	// ErrOCFIncompleteFrame is returned by Finish when the buffered bytes end in
	// the middle of an OCF header or block (a block count or block size varint,
	// the compressed block body, or the sync marker). A temporarily incomplete
	// frame is never treated as the end of the stream while Push may still
	// deliver more bytes; only Finish upgrades the truncation into an error.
	ErrOCFIncompleteFrame = errors.New("OCFCollector: stream ended with an incomplete frame")

	// ErrOCFPendingFrameLimit is returned by Push when the collector already
	// holds MaxPendingFrames validated blocks that the sink has not accepted and
	// the caller is offering additional bytes. The offered bytes are not
	// retained; retry the same Push once the sink has made progress.
	ErrOCFPendingFrameLimit = errors.New("OCFCollector: pending frame limit reached")
)

// OCFBlockSink receives fully validated OCF blocks. AddBlock is invoked at most
// once per delivery attempt, and only after the complete block has passed
// every framing and decoding check: the block count and block size varints,
// the block body (including decompression), the sync marker, and the
// successful native decoding of every record in the block through the standard
// OCFReader.
//
// AddBlock must be idempotent for a given key: the same (SourceEpoch, Block
// Offset) pair is delivered again, unchanged, whenever a previous attempt
// returned an error. Implementations are expected to treat the key as an
// upsert key so retries never duplicate data.
//
// AddBlock returns nil only after the block has durably landed. The bookmark
// exposed by the collector advances strictly after a nil return, so a non-nil
// error leaves the bookmark untouched and the same block is retried later.
//
// Ownership: the records slice and the native values it contains are freshly
// allocated for each delivery and are not retained by the collector after
// AddBlock returns, so the sink may keep them without copying. The collector
// in turn never shares the caller's Push buffers (it copies every pushed
// chunk), so the two buffer pools are independent.
type OCFBlockSink interface {
	AddBlock(key OCFBlockKey, records []interface{}) error
}

// OCFBlockSinkFunc adapts a plain function to the OCFBlockSink interface.
type OCFBlockSinkFunc func(key OCFBlockKey, records []interface{}) error

// AddBlock implements OCFBlockSink by delegating to the wrapped function.
func (f OCFBlockSinkFunc) AddBlock(key OCFBlockKey, records []interface{}) error {
	return f(key, records)
}

// OCFBlockKey is the stable, deterministic identity of an OCF block. It is the
// same value on every retry of the block, so it is safe to use as an
// idempotency key by the sink.
type OCFBlockKey struct {
	// SourceEpoch identifies the originating byte stream. It is opaque to the
	// collector and is copied verbatim from the configuration or the
	// bookmark used to resume.
	SourceEpoch string

	// BlockOffset is the absolute byte offset, relative to the start of the
	// stream, of the first byte of the block: the first byte of the block
	// count varint.
	BlockOffset int64
}

// String renders the key for logging and diagnostics.
func (k OCFBlockKey) String() string {
	return fmt.Sprintf("{sourceEpoch=%q blockOffset=%d}", k.SourceEpoch, k.BlockOffset)
}

// OCFBookmark is the serializable resume state of an OCFCollector. It contains
// everything required to reopen a stream and continue without rescanning any
// bytes that have already been delivered to the sink.
type OCFBookmark struct {
	// SourceEpoch identifies the originating byte stream and must match the
	// stream the bookmark was created from.
	SourceEpoch string

	// Header is the exact, complete OCF header (magic bytes, metadata and sync
	// marker) as it appeared on the wire. It is required to resume because,
	// after resuming, only bytes at or past NextOffset are fed to the
	// collector, so the header is never seen again.
	Header []byte

	// NextOffset is the absolute stream offset immediately after the last block
	// that the sink has successfully acknowledged. On resume only bytes at or
	// past this offset are pushed; earlier bytes are not re-read or re-scanned.
	NextOffset int64
}

// OCFCollectorConfig configures a new OCFCollector.
type OCFCollectorConfig struct {
	// Sink receives each fully validated block, (required).
	Sink OCFBlockSink

	// SourceEpoch is the opaque identifier of the byte stream being collected,
	// (required for a new stream). It is combined with each block offset to
	// form the stable OCFBlockKey. When resuming, the value from Bookmark is
	// used instead and this field is ignored.
	SourceEpoch string

	// MaxPendingFrames bounds how many complete, validated blocks may be queued
	// while waiting for the sink, (optional). Zero selects
	// defaultMaxPendingFrames. A negative value disables the limit. The limit
	// is independent of MaxBlockSize, which already bounds the size of any
	// single block.
	MaxPendingFrames int64

	// Bookmark, when non-nil, resumes a previously bookmarked stream instead of
	// starting a new one, (optional). The caller must then push only bytes at
	// or past the bookmark's NextOffset; the collector never rescans older
	// bytes.
	Bookmark *OCFBookmark
}

// pendingFrame is a fully validated block awaiting, or in the middle of, sink
// delivery. The original frame bytes have already been released; only the
// decoded records are retained.
type pendingFrame struct {
	key      OCFBlockKey
	records  []interface{}
	frameLen int64 // total on-wire length of the block frame, including sync marker
}

// OCFCollector incrementally assembles an Avro Object Container File from
// arbitrary byte chunks pushed through Push. A chunk may end in the middle of
// the OCF header, a block count or block size varint, a compressed block body,
// or a sync marker; incomplete frames are simply retained until more bytes
// arrive. Push never interprets a temporary lack of data as end of stream.
//
// A block is handed to the sink only once its frame is complete and every
// record it contains has been decoded through the native OCFReader. A block
// whose later records fail decoding therefore never reaches the sink, so a bad
// later record cannot leak the earlier records of the same block. The bookmark
// advances only after the sink acknowledges a block.
//
// OCFCollector is not safe for concurrent use.
type OCFCollector struct {
	sink        OCFBlockSink
	sourceEpoch string
	maxPending  int64

	// header holds the exact on-wire OCF header once it has been fully
	// received and parsed. It is nil until the header frame completes.
	header []byte
	parsed *ocfHeader

	// buf holds pushed bytes that have not yet formed a fully validated block.
	buf []byte

	// baseOffset is the absolute stream offset of buf's first byte.
	baseOffset int64

	// confirmedOffset is the absolute stream offset immediately after the most
	// recently sink-acknowledged block.
	confirmedOffset int64

	// queue holds validated, decoded blocks not yet acknowledged by the sink.
	// Frames are delivered in FIFO order and the queue never grows beyond
	// maxPending entries.
	queue []*pendingFrame

	closed  bool
	hardErr error
}

// NewOCFCollector returns an OCFCollector configured either to begin a new OCF
// stream or to resume a bookmarked one.
func NewOCFCollector(config OCFCollectorConfig) (*OCFCollector, error) {
	if config.Sink == nil {
		return nil, errors.New("cannot create OCFCollector when Sink is nil")
	}

	maxPending := config.MaxPendingFrames
	if maxPending == 0 {
		maxPending = defaultMaxPendingFrames
	}

	c := &OCFCollector{
		sink:       config.Sink,
		maxPending: maxPending,
	}

	if bm := config.Bookmark; bm != nil {
		// Resume: validate the stored header and anchor the buffer at the
		// confirmed boundary. The caller will only supply bytes from here on.
		if bm.SourceEpoch == "" {
			return nil, errors.New("cannot resume OCFCollector from bookmark without SourceEpoch")
		}
		if len(bm.Header) == 0 {
			return nil, errors.New("cannot resume OCFCollector from bookmark without header bytes")
		}
		parsed, consumed, err := parseOCFHeaderPrefix(bm.Header)
		if err != nil {
			return nil, fmt.Errorf("cannot resume OCFCollector from bookmark with invalid header: %s", err)
		}
		if consumed != int64(len(bm.Header)) {
			return nil, fmt.Errorf("cannot resume OCFCollector from bookmark: header has %d trailing byte(s) after OCF header", len(bm.Header)-int(consumed))
		}
		if bm.NextOffset < consumed {
			return nil, fmt.Errorf("cannot resume OCFCollector from bookmark: NextOffset %d precedes end of header %d", bm.NextOffset, consumed)
		}
		c.sourceEpoch = bm.SourceEpoch
		c.header = append([]byte(nil), bm.Header...)
		c.parsed = parsed
		c.baseOffset = bm.NextOffset
		c.confirmedOffset = bm.NextOffset
		return c, nil
	}

	// Fresh stream: the header is expected to arrive (possibly split) via Push.
	if config.SourceEpoch == "" {
		return nil, errors.New("cannot create OCFCollector without SourceEpoch")
	}
	c.sourceEpoch = config.SourceEpoch
	return c, nil
}

// Push appends a chunk of raw OCF bytes, then validates and delivers every
// block that has become complete. The chunk may split the stream at any byte
// boundary, including inside the header, a varint, a compressed body, or the
// sync marker.
//
// The collector copies the chunk, so the caller retains full ownership of p and
// may reuse or free it as soon as Push returns. An empty or nil chunk is
// permitted and simply re-attempts delivery of blocks queued behind a
// previously failing sink.
//
// The first error encountered is returned. Sink errors are retryable: the
// affected block stays queued with its stable key and is delivered again on a
// later Push or Finish. Framing, sync, and decoding errors are permanent for
// the stream and leave the collector in an errored state. When the pending
// frame limit is reached, Push returns ErrOCFPendingFrameLimit without
// retaining p; the same bytes may be pushed again after the sink catches up.
func (c *OCFCollector) Push(p []byte) error {
	if c.closed {
		return ErrOCFCollectorClosed
	}
	if c.hardErr != nil {
		return c.hardErr
	}

	// Back-pressure: when the validated queue is saturated the sink must catch
	// up before more bytes are accepted. Refuse the offered bytes with
	// ErrOCFPendingFrameLimit and do not retain them, so the caller may retry
	// the identical Push after draining (typically via an empty Push, which
	// reaches deliverQueued and surfaces any sink error). An empty Push always
	// proceeds so it can itself trigger a flush.
	if len(p) > 0 && c.atLimit() {
		return fmt.Errorf("%w: %d complete block(s) awaiting sink", ErrOCFPendingFrameLimit, int64(len(c.queue)))
	}

	if len(p) > 0 {
		// Copy the caller's bytes: Push must not retain the input slice.
		c.buf = append(c.buf, p...)
	}

	return c.drain(false)
}

// Finish signals that no further bytes will be pushed. It first re-attempts
// delivery of any block queued behind a failing sink, then verifies that no
// partial frame remains. If the buffered bytes end inside the header or a
// block frame, Finish wraps ErrOCFIncompleteFrame; a temporary end of data is
// never silently accepted as the end of the stream.
//
// After Finish the collector is closed and further Push calls return
// ErrOCFCollectorClosed. A sink error returned by Finish is retryable only by
// reopening from the latest Bookmark, since the collector is now closed.
func (c *OCFCollector) Finish() error {
	if c.closed {
		return ErrOCFCollectorClosed
	}
	c.closed = true

	if c.hardErr != nil {
		return c.hardErr
	}
	if err := c.drain(true); err != nil {
		return err
	}
	if len(c.buf) != 0 {
		c.hardErr = fmt.Errorf("%w: %d buffered byte(s) starting at offset %d do not form a complete header or block",
			ErrOCFIncompleteFrame, len(c.buf), c.baseOffset)
		return c.hardErr
	}
	return nil
}

// Bookmark returns a copy of the current resume state. The returned value may
// be persisted at any time and later passed through OCFCollectorConfig to
// resume. It reflects only blocks the sink has acknowledged, so resuming from
// it never re-delivers an acknowledged block or rescans an earlier byte.
func (c *OCFCollector) Bookmark() OCFBookmark {
	bm := OCFBookmark{
		SourceEpoch: c.sourceEpoch,
		NextOffset:  c.confirmedOffset,
	}
	if c.header != nil {
		bm.Header = append([]byte(nil), c.header...)
	}
	return bm
}

// atLimit reports whether the validated queue has reached its configured cap.
func (c *OCFCollector) atLimit() bool {
	return c.maxPending > 0 && int64(len(c.queue)) >= c.maxPending
}

// drain assembles, validates and delivers as many complete blocks as the
// buffered bytes allow. When finishing is true, an incomplete frame is
// upgraded to ErrOCFIncompleteFrame instead of being awaited.
func (c *OCFCollector) drain(finishing bool) error {
	// Phase 1: assemble the OCF header, which may span several Push calls.
	if c.parsed == nil {
		if len(c.buf) == 0 {
			if finishing {
				c.hardErr = fmt.Errorf("%w: no OCF header received", ErrOCFIncompleteFrame)
				return c.hardErr
			}
			return nil
		}
		parsed, consumed, err := parseOCFHeaderPrefix(c.buf)
		if err != nil {
			if isTruncatedRead(err) {
				if finishing {
					c.hardErr = fmt.Errorf("%w: incomplete OCF header at offset %d: %s", ErrOCFIncompleteFrame, c.baseOffset, err)
					return c.hardErr
				}
				return nil // wait for more header bytes
			}
			c.hardErr = fmt.Errorf("cannot parse OCF header at offset %d: %s", c.baseOffset, err)
			return c.hardErr
		}
		c.header = append([]byte(nil), c.buf[:consumed]...)
		c.parsed = parsed
		c.consume(consumed)
		// Before any block is acknowledged the durable boundary sits at the
		// end of the header, so a bookmark taken at this point resumes there.
		c.confirmedOffset = c.baseOffset
	}

	// Phase 2: turn every complete frame in the buffer into a validated queued
	// block, making room whenever the pending limit would otherwise be
	// exceeded. This keeps the queue at or below maxPending even within a
	// single large Push. The flush here is best-effort: if the sink is still
	// down the queue cannot shrink, so extraction stops and the authoritative
	// flush at the end (or in Push) reports the sink or limit error.
	for {
		if len(c.buf) == 0 {
			break
		}
		if c.atLimit() {
			if err := c.deliverQueued(); err != nil {
				// The sink is still down and the queue could not shrink. Stop
				// extracting and surface the sink error; the buffered frame is
				// retained for a later Push.
				return err
			}
			if c.atLimit() {
				// Defensive: a nil flush cannot leave the queue full, but stop
				// rather than exceed the configured limit if it ever does.
				break
			}
		}

		frameStart := c.baseOffset
		pos := int64(0)

		blockCount, n, err := readBufferedVarint(c.buf[pos:])
		if err != nil {
			return c.awaitOrFail(finishing, "block count", frameStart, err)
		}
		pos += n
		if blockCount <= 0 {
			c.hardErr = fmt.Errorf("cannot decode block at offset %d: block count must be greater than 0, got %d", frameStart, blockCount)
			return c.hardErr
		}
		if blockCount > MaxBlockCount {
			c.hardErr = fmt.Errorf("cannot decode block at offset %d: block count exceeds MaxBlockCount: %d > %d", frameStart, blockCount, MaxBlockCount)
			return c.hardErr
		}

		blockSize, n, err := readBufferedVarint(c.buf[pos:])
		if err != nil {
			return c.awaitOrFail(finishing, "block size", frameStart, err)
		}
		pos += n
		if blockSize <= 0 {
			c.hardErr = fmt.Errorf("cannot decode block at offset %d: block size must be greater than 0, got %d", frameStart, blockSize)
			return c.hardErr
		}
		if blockSize > MaxBlockSize {
			c.hardErr = fmt.Errorf("cannot decode block at offset %d: block size exceeds MaxBlockSize: %d > %d", frameStart, blockSize, MaxBlockSize)
			return c.hardErr
		}

		frameLen := pos + blockSize + ocfSyncLength
		if int64(len(c.buf)) < frameLen {
			// The body and/or sync marker have not arrived yet.
			if finishing {
				c.hardErr = fmt.Errorf("%w: truncated block frame at offset %d: have %d buffered byte(s), need %d",
					ErrOCFIncompleteFrame, frameStart, len(c.buf), frameLen)
				return c.hardErr
			}
			break
		}

		frame := c.buf[:frameLen]
		syncStart := pos + blockSize
		if !bytes.Equal(frame[syncStart:frameLen], c.parsed.syncMarker[:]) {
			c.hardErr = fmt.Errorf("sync marker mismatch at block offset %d: got %x, want %x",
				frameStart, frame[syncStart:frameLen], c.parsed.syncMarker[:])
			return c.hardErr
		}

		// Whole-frame validation through the native OCFReader. The header is
		// prepended so the reader reuses the exact production parsing path,
		// including decompression and every record's NativeFromBinary decode.
		// Only after this succeeds is the frame released from the buffer and
		// exposed to the sink, so a block whose later records are bad never
		// leaks its earlier records.
		records, err := c.decodeFrame(frame, blockCount)
		if err != nil {
			c.hardErr = fmt.Errorf("cannot decode block at offset %d: %s", frameStart, err)
			return c.hardErr
		}

		c.queue = append(c.queue, &pendingFrame{
			key:      OCFBlockKey{SourceEpoch: c.sourceEpoch, BlockOffset: frameStart},
			records:  records,
			frameLen: frameLen,
		})
		c.consume(frameLen)
	}

	// Phase 3: deliver every validated block in order. The first sink error
	// stops the run; the block and all later blocks stay queued.
	return c.deliverQueued()
}

// deliverQueued delivers queued, validated blocks in FIFO order until the queue
// drains or the sink returns an error. On success each block is removed and the
// durable confirmed boundary advances past it.
func (c *OCFCollector) deliverQueued() error {
	for len(c.queue) > 0 {
		frame := c.queue[0]
		if err := c.sink.AddBlock(frame.key, frame.records); err != nil {
			return fmt.Errorf("sink rejected block at offset %d: %s", frame.key.BlockOffset, err)
		}
		c.queue = c.queue[1:]
		c.confirmedOffset = frame.key.BlockOffset + frame.frameLen
	}
	return nil
}

// awaitOrFail maps an incomplete-varint condition inside drain to either a
// wait (more bytes expected) or a hard truncation error (Finish in progress).
func (c *OCFCollector) awaitOrFail(finishing bool, field string, frameStart int64, err error) error {
	if errors.Is(err, io.ErrShortBuffer) {
		if finishing {
			c.hardErr = fmt.Errorf("%w: truncated %s varint at offset %d", ErrOCFIncompleteFrame, field, frameStart)
			return c.hardErr
		}
		return nil
	}
	c.hardErr = fmt.Errorf("cannot read %s varint at offset %d: %s", field, frameStart, err)
	return c.hardErr
}

// consume drops n leading bytes from the buffer and advances the base offset
// by the same amount.
func (c *OCFCollector) consume(n int64) {
	c.baseOffset += n
	remaining := int64(len(c.buf)) - n
	if remaining <= 0 {
		c.buf = c.buf[:0]
		return
	}
	c.buf = append(c.buf[:0], c.buf[n:]...)
}

// decodeFrame runs a complete single-block frame (block count, block size,
// possibly compressed body, and sync marker) through the standard OCFReader
// and returns every decoded record. It fails if the declared block count does
// not match the number of decodable records or the reader errors.
func (c *OCFCollector) decodeFrame(frame []byte, blockCount int64) ([]interface{}, error) {
	combined := make([]byte, 0, len(c.header)+len(frame))
	combined = append(combined, c.header...)
	combined = append(combined, frame...)

	reader, err := NewOCFReader(bytes.NewReader(combined))
	if err != nil {
		return nil, err
	}

	records := make([]interface{}, 0, blockCount)
	for reader.Scan() {
		datum, readErr := reader.Read()
		if readErr != nil {
			return nil, readErr
		}
		records = append(records, datum)
	}
	if err = reader.Err(); err != nil {
		return nil, err
	}
	if int64(len(records)) != blockCount {
		return nil, fmt.Errorf("decoded %d record(s) but block count declares %d", len(records), blockCount)
	}
	return records, nil
}

// parseOCFHeaderPrefix attempts to read a complete OCF header from the leading
// bytes of buf. It returns the parsed header and the number of bytes it
// occupies. A truncated but otherwise plausible prefix yields an error for
// which isTruncatedRead returns true, allowing the caller to await more bytes.
func parseOCFHeaderPrefix(buf []byte) (*ocfHeader, int64, error) {
	reader := bytes.NewReader(buf)
	header, err := readOCFHeader(reader)
	if err != nil {
		return nil, 0, err
	}
	// Derive the header length from how many bytes the reader advanced.
	consumed := int64(len(buf)) - int64(reader.Len())
	return header, consumed, nil
}

// isTruncatedRead reports whether an error from readOCFHeader represents a
// prefix that simply ran out of bytes, rather than structurally invalid data.
// Every short-read path in the OCF header reader surfaces io.EOF or
// io.ErrUnexpectedEOF in its rendered error message.
func isTruncatedRead(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	msg := err.Error()
	return bytes.Contains([]byte(msg), []byte(io.EOF.Error())) ||
		bytes.Contains([]byte(msg), []byte(io.ErrUnexpectedEOF.Error()))
}

// readBufferedVarint decodes a zig-zag encoded long from the front of buf. It
// returns the value and the number of bytes it occupies, or io.ErrShortBuffer
// when buf ends inside the varint (more bytes may complete it), or a hard
// error for an overlong run of continuation bytes.
func readBufferedVarint(buf []byte) (int64, int64, error) {
	var value uint64
	var shift uint
	for i := 0; i < len(buf); i++ {
		b := buf[i]
		value |= uint64(b&intMask) << shift
		if b&intFlag == 0 {
			return int64(value>>1) ^ -int64(value&1), int64(i + 1), nil
		}
		shift += 7
		if i+1 >= maxVarintLength {
			return 0, int64(i + 1), errors.New("varint exceeds maximum length of 10 bytes for a 64-bit integer")
		}
	}
	return 0, 0, io.ErrShortBuffer
}
