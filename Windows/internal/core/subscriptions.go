package core

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

func FetchSubscription(ctx context.Context, address string) ([]Server, error) {
	u, e := url.Parse(address)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return nil, fmt.Errorf("subscriptions require HTTPS without embedded user credentials")
	}
	c := http.Client{Timeout: 30 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if r.URL.Scheme != "https" || len(via) > 5 {
			return fmt.Errorf("unsafe subscription redirect")
		}
		return nil
	}}
	req, e := http.NewRequestWithContext(ctx, "GET", address, nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("User-Agent", "Aster-Windows/0.1.0")
	resp, e := c.Do(req)
	if e != nil {
		return nil, fmt.Errorf("subscription HTTPS request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("subscription returned HTTP %d", resp.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024+1))
	if e != nil {
		return nil, fmt.Errorf("could not read subscription")
	}
	if len(b) > 8*1024*1024 {
		return nil, fmt.Errorf("subscription exceeds 8 MB")
	}
	return Parse(string(b))
}
