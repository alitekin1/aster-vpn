package update

import (
	"aster/windows/internal/buildinfo"
	"context"
	"os"
	"testing"
	"time"
)

func TestPublishedReleaseDownload(t *testing.T) {
	if os.Getenv("ASTER_RELEASE_LIVE_TEST") != "1" {
		t.Skip("opt-in public release test")
	}
	c, e := New(buildinfo.Repository)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			offer, e := c.Check(ctx, "0.1.0", arch)
			if e != nil || !offer.Available {
				t.Fatal("published signed update not discovered", e)
			}
			p, e := c.Download(ctx, offer, t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			b, e := os.ReadFile(p)
			if e != nil || len(b) < 100000 || string(b[:2]) != "MZ" {
				t.Fatal("invalid Windows installer")
			}
			t.Log("Verified public signed release", offer.Version, "for", arch)
		})
	}
}
