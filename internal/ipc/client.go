package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
)

type Client struct{ c net.Conn }

func Dial(path string) (*Client, error) {
	c, err := net.Dial("unix", path)
	if err != nil {
		return nil, err
	}
	return &Client{c: c}, nil
}

func (c *Client) Close() error { return c.c.Close() }

func (c *Client) call(reqTag byte, req any, respTag byte, resp any) error {
	body, _ := json.Marshal(req)
	if err := WriteFrame(c.c, reqTag, body); err != nil {
		return err
	}
	tag, body, err := ReadFrame(c.c)
	if err != nil {
		return err
	}
	if tag == TagError {
		return errors.New(string(body))
	}
	if tag != respTag {
		return errors.New("unexpected tag")
	}
	if resp == nil {
		return nil
	}
	return json.Unmarshal(body, resp)
}

func (c *Client) AddRule(s AddRuleSpec) (int64, error) {
	var out struct {
		ID int64 `json:"id"`
	}
	if err := c.call(TagAddRule, s, TagAck, &out); err != nil {
		return 0, err
	}
	return out.ID, nil
}

func (c *Client) RevokeRule(id int64) error {
	return c.call(TagRevokeRule, struct {
		ID int64 `json:"id"`
	}{id}, TagAck, nil)
}

func (c *Client) ListRules(r ListReq) ([]RuleRow, error) {
	var out []RuleRow
	if err := c.call(TagListRequest, r, TagListResponse, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) Status() (StatusRow, error) {
	var out StatusRow
	if err := c.call(TagStatusRequest, struct{}{}, TagStatusResponse, &out); err != nil {
		return StatusRow{}, err
	}
	return out, nil
}

func (c *Client) TailAudit(ctx context.Context, r TailReq) ([]AuditRow, error) {
	var out []AuditRow
	if err := c.call(TagTailRequest, r, TagAuditEvent, &out); err != nil {
		return nil, err
	}
	return out, nil
}
