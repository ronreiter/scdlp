package ipc

import (
	"encoding/binary"
	"errors"
	"io"
)

// Frame layout: 4-byte BE length || N-byte payload
// Payload: 1-byte tag || JSON body

// MaxFrameSize bounds the on-the-wire frame so a malicious peer cannot
// trigger an unbounded allocation.
const MaxFrameSize = 1 << 20 // 1 MiB

const (
	TagPromptRequest  byte = 0x01
	TagPromptDecision byte = 0x02
	TagAddRule        byte = 0x03
	TagRevokeRule     byte = 0x04
	TagListRequest    byte = 0x05
	TagListResponse   byte = 0x06
	TagStatusRequest  byte = 0x07
	TagStatusResponse byte = 0x08
	TagTailRequest    byte = 0x09
	TagAuditEvent     byte = 0x0A
	TagAck            byte = 0x0B
	TagError          byte = 0x0C
)

var ErrShortRead = errors.New("ipc: short read")

func WriteFrame(w io.Writer, tag byte, body []byte) error {
	hdr := make([]byte, 5)
	binary.BigEndian.PutUint32(hdr[:4], uint32(len(body)+1))
	hdr[4] = tag
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

func ReadFrame(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:4])
	if n == 0 {
		return 0, nil, ErrShortRead
	}
	if n > MaxFrameSize {
		return 0, nil, errors.New("ipc: frame too large")
	}
	body := make([]byte, n-1)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return hdr[4], body, nil
}
