package ipc

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
)

type Server struct {
	path string
	be   Backend
	ln   net.Listener
	wg   sync.WaitGroup
}

func NewServer(path string, be Backend) *Server { return &Server{path: path, be: be} }

func (s *Server) Start() error {
	_ = os.MkdirAll(filepath.Dir(s.path), 0o755)
	_ = os.Remove(s.path)
	ln, err := net.Listen("unix", s.path)
	if err != nil {
		return err
	}
	_ = os.Chmod(s.path, 0o660)
	s.ln = ln
	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

func (s *Server) Stop() {
	if s.ln != nil {
		_ = s.ln.Close()
	}
	s.wg.Wait()
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		s.wg.Add(1)
		go s.handle(c)
	}
}

func (s *Server) handle(c net.Conn) {
	defer s.wg.Done()
	defer c.Close()
	for {
		tag, body, err := ReadFrame(c)
		if err != nil {
			if err != io.EOF {
				// best-effort
			}
			return
		}
		s.dispatch(c, tag, body)
	}
}

func (s *Server) dispatch(c net.Conn, tag byte, body []byte) {
	switch tag {
	case TagAddRule:
		var spec AddRuleSpec
		_ = json.Unmarshal(body, &spec)
		id, err := s.be.AddRule(spec)
		if err != nil {
			writeErr(c, err)
			return
		}
		writeJSON(c, TagAck, struct {
			ID int64 `json:"id"`
		}{ID: id})
	case TagRevokeRule:
		var v struct {
			ID int64 `json:"id"`
		}
		_ = json.Unmarshal(body, &v)
		if err := s.be.RevokeRule(v.ID); err != nil {
			writeErr(c, err)
			return
		}
		writeJSON(c, TagAck, struct{}{})
	case TagListRequest:
		var req ListReq
		_ = json.Unmarshal(body, &req)
		rows, err := s.be.ListRules(req)
		if err != nil {
			writeErr(c, err)
			return
		}
		writeJSON(c, TagListResponse, rows)
	case TagStatusRequest:
		st, err := s.be.Status()
		if err != nil {
			writeErr(c, err)
			return
		}
		writeJSON(c, TagStatusResponse, st)
	case TagTailRequest:
		var req TailReq
		_ = json.Unmarshal(body, &req)
		rows, err := s.be.TailAudit(req)
		if err != nil {
			writeErr(c, err)
			return
		}
		writeJSON(c, TagAuditEvent, rows)
	default:
		writeErr(c, errors.New("unknown tag"))
	}
}

func writeJSON(w io.Writer, tag byte, v any) {
	b, _ := json.Marshal(v)
	_ = WriteFrame(w, tag, b)
}

func writeErr(w io.Writer, err error) {
	_ = WriteFrame(w, TagError, []byte(err.Error()))
}
