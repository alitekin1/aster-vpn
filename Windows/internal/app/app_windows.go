package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"aster/windows/internal/buildinfo"
	"aster/windows/internal/core"
	"aster/windows/internal/packet"
	"aster/windows/internal/platform"
	"aster/windows/internal/update"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"runtime"
)

type Event struct {
	Date    time.Time `json:"date"`
	Message string    `json:"message"`
	Error   bool      `json:"isError"`
}
type Snapshot struct {
	AppVersion   string        `json:"appVersion"`
	Update       *update.Offer `json:"update,omitempty"`
	ActiveServer *core.Server  `json:"activeServer,omitempty"`
	LowPower     bool          `json:"lowPower"`
	State        core.State    `json:"state"`
	Connected    bool          `json:"connected"`
	Busy         bool          `json:"busy"`
	Pending      bool          `json:"pending"`
	Health       string        `json:"health"`
	Verified     bool          `json:"verified"`
	StartedAt    *time.Time    `json:"startedAt"`
	ActiveID     string        `json:"activeID"`
	ActiveMode   string        `json:"activeMode"`
	PublicIP     string        `json:"publicIP"`
	DirectIP     string        `json:"directIP"`
	Stats        packet.Stats  `json:"stats"`
	Logs         []Event       `json:"logs"`
	Result       any           `json:"result"`
	Error        string        `json:"error"`
	Version      uint64        `json:"version"`
	Conflicts    []string      `json:"conflicts"`
}
type App struct {
	updater      *update.Client
	updateOffer  *update.Offer
	activeServer *core.Server
	closeOnce    sync.Once
	mu           sync.Mutex
	op           sync.Mutex
	state        core.State
	path         string
	assetsRoot   string
	bundled      string
	conn         *platform.Tunnel
	busy         bool
	pending      bool
	health       string
	verified     bool
	started      *time.Time
	activeID     string
	activeMode   string
	publicIP     string
	directIP     string
	logs         []Event
	result       any
	lastError    string
	version      uint64
	ctx          context.Context
	cancel       context.CancelFunc
	network      chan struct{}
	callbacks    []*winipcfg.RouteChangeCallback
	Quit         func()
	Export       func(string) error
	Minimize     func()
	shutting     bool
}

func New(data, bundled string) (*App, error) {
	s, e := core.LoadState(filepath.Join(data, "state.dat"))
	if e != nil {
		return nil, fmt.Errorf("saved settings could not be decrypted or loaded; existing data was preserved: %w", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &App{state: s, path: filepath.Join(data, "state.dat"), assetsRoot: filepath.Join(data, "GeoData"), bundled: bundled, ctx: ctx, cancel: cancel, health: "Disconnected", logs: []Event{}, network: make(chan struct{}, 1)}
	_, a.state.DatabaseVersion = core.ActiveAssets(a.assetsRoot, bundled)
	a.updater, e = update.New(buildinfo.Repository)
	if e != nil {
		cancel()
		return nil, e
	}
	a.event("Aster is ready.", false)
	return a, nil
}
func (a *App) event(message string, isError bool) {
	a.logs = append(a.logs, Event{time.Now(), core.Redact(message), isError})
	if len(a.logs) > 500 {
		a.logs = a.logs[len(a.logs)-500:]
	}
	a.version++
}
func (a *App) save() error {
	if e := core.SaveState(a.path, a.state); e != nil {
		return fmt.Errorf("could not save encrypted settings: %w", e)
	}
	a.version++
	return nil
}
func (a *App) Snapshot() Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := Snapshot{AppVersion: buildinfo.Version, Update: a.updateOffer, ActiveServer: a.activeServer, LowPower: platform.LowPower(), State: a.state, Connected: a.conn != nil, Busy: a.busy, Pending: a.pending, Health: a.health, Verified: a.verified, StartedAt: a.started, ActiveID: a.activeID, ActiveMode: a.activeMode, PublicIP: a.publicIP, DirectIP: a.directIP, Logs: a.logs, Result: a.result, Error: a.lastError, Version: a.version, Conflicts: core.Conflicts(a.state.Rules)}
	if a.conn != nil {
		s.Stats = a.conn.Engine.Stats()
	} // Deep-copy under lock; JSON also removes credentials.
	b, _ := json.Marshal(s)
	var copy Snapshot
	_ = json.Unmarshal(b, &copy)
	return copy
}
func (a *App) job(name string, fn func() error) error {
	a.mu.Lock()
	if a.busy || a.shutting {
		a.mu.Unlock()
		return fmt.Errorf("another operation is in progress")
	}
	a.busy = true
	a.lastError = ""
	a.version++
	a.mu.Unlock()
	go func() {
		a.op.Lock()
		e := fn()
		a.op.Unlock()
		a.mu.Lock()
		defer a.mu.Unlock()
		a.busy = false
		if e != nil {
			a.lastError = core.Redact(e.Error())
			a.event(name+": "+a.lastError, true)
		} else {
			a.event(name+" completed.", false)
		}
		a.version++
	}()
	return nil
}
func (a *App) disconnect() {
	a.mu.Lock()
	t := a.conn
	a.conn = nil
	a.started = nil
	a.verified = false
	a.health = "Disconnected"
	a.activeID = ""
	a.activeServer = nil
	a.activeMode = ""
	a.publicIP = ""
	a.directIP = ""
	a.pending = false
	a.version++
	a.mu.Unlock()
	if t != nil {
		t.Close()
	}
}
func (a *App) connect() error {
	a.disconnect()
	a.mu.Lock()
	state := a.state
	a.health = "Connecting"
	a.version++
	a.mu.Unlock()
	assets, _ := core.ActiveAssets(a.assetsRoot, a.bundled)
	t, e := platform.Start(state, assets)
	if e != nil {
		a.mu.Lock()
		a.health = "Disconnected"
		a.mu.Unlock()
		return e
	}
	now := time.Now()
	a.mu.Lock()
	a.conn = t
	a.started = &now
	a.activeID = state.SelectedServerID
	for _, server := range state.Servers {
		if server.ID == state.SelectedServerID {
			copy := server
			a.activeServer = &copy
			break
		}
	}
	a.activeMode = state.Settings.Mode
	a.health = "Checking proxy"
	a.version++
	a.mu.Unlock()
	go func() {
		select {
		case <-a.ctx.Done():
			return
		case e := <-t.Failure:
			if e == nil {
				return
			}
			a.mu.Lock()
			current := a.conn == t
			reconnect := a.state.Settings.Reconnect
			a.mu.Unlock()

			for current {
				err := a.job("Tunnel recovery", func() error {
					a.mu.Lock()
					stillCurrent := a.conn == t
					a.mu.Unlock()
					if !stillCurrent {
						return nil
					}
					a.disconnect()
					if reconnect {
						return a.recoverConnection()
					}
					return fmt.Errorf("VPN adapter stopped; reconnect to restore capture")
				})
				if err == nil {
					break
				}
				timer := time.NewTimer(time.Second)
				select {
				case <-a.ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
				a.mu.Lock()
				current = a.conn == t && !a.shutting
				reconnect = a.state.Settings.Reconnect
				a.mu.Unlock()
			}
		}
	}()
	return a.verify(t)
}
func (a *App) verify(t *platform.Tunnel) error {
	a.mu.Lock()
	tag := "proxy-" + a.activeID
	a.mu.Unlock()
	b, e := t.Engine.Probe(tag)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.conn != t {
		return nil
	}
	if e != nil {
		a.health = "Proxy check failed"
		a.verified = false
		a.event("Tunnel is active, but the proxy HTTPS check failed. Check server credentials or try another server.", true)
		return nil
	}
	var result map[string]string
	_ = json.Unmarshal(b, &result)
	a.publicIP = result["ip"]
	a.verified = result["ip"] != ""
	a.health = "Connected"
	a.version++
	return nil
}
func (a *App) recoverConnection() error {
	e := a.connect()
	if e == nil {
		return nil
	}
	a.mu.Lock()
	failover := a.state.Settings.Failover
	servers := append([]core.Server(nil), a.state.Servers...)
	selected := a.state.SelectedServerID
	a.mu.Unlock()
	if !failover {
		return e
	}
	sort.SliceStable(servers, func(i, j int) bool {
		return servers[i].Latency != nil && (servers[j].Latency == nil || *servers[i].Latency < *servers[j].Latency)
	})
	for _, s := range servers {
		if s.ID == selected {
			continue
		}
		select {
		case <-a.ctx.Done():
			return a.ctx.Err()
		default:
		}
		a.mu.Lock()
		a.state.SelectedServerID = s.ID
		a.mu.Unlock()
		if next := a.connect(); next == nil {
			a.mu.Lock()
			_ = a.save()
			a.mu.Unlock()
			return nil
		}
	}
	a.mu.Lock()
	a.state.SelectedServerID = selected
	a.mu.Unlock()
	return e
}
func (a *App) StartBackground() {
	cb, e := winipcfg.RegisterRouteChangeCallback(func(_ winipcfg.MibNotificationType, row *winipcfg.MibIPforwardRow2) {
		if row.DestinationPrefix.Prefix().Bits() == 0 {
			select {
			case a.network <- struct{}{}:
			default:
			}
		}
	})
	if e == nil {
		a.callbacks = append(a.callbacks, cb)
	}
	go a.maintenance()
	a.mu.Lock()
	auto := a.state.Settings.AutoConnect && a.state.SelectedServerID != ""
	a.mu.Unlock()
	if auto {
		_ = a.job("Auto connect", a.connect)
	}
}
func (a *App) maintenance() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	lastDatabase := time.Now()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-a.network:
			timer := time.NewTimer(2 * time.Second)
			select {
			case <-a.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			for len(a.network) > 0 {
				<-a.network
			}
			a.mu.Lock()
			reconnect := a.conn != nil && a.state.Settings.Reconnect
			busy := a.busy
			a.mu.Unlock()
			if reconnect && busy {
				select {
				case a.network <- struct{}{}:
				default:
				}
				continue
			}
			if reconnect {
				_ = a.job("Network change", a.recoverConnection)
			}
		case <-ticker.C:
			if platform.LowPower() {
				continue
			}
			a.mu.Lock()
			if a.busy || a.shutting {
				a.mu.Unlock()
				continue
			}
			due := ""
			for _, s := range a.state.Subscriptions {
				if s.RefreshHours > 0 && (s.UpdatedAt == nil || time.Since(*s.UpdatedAt) >= time.Duration(s.RefreshHours*float64(time.Hour))) {
					due = s.ID
					break
				}
			}
			update := a.state.Settings.DatabaseAutoUpdate && time.Since(lastDatabase) > 24*time.Hour
			a.mu.Unlock()
			if due != "" {
				id := due
				_ = a.job("Subscription refresh", func() error { return a.refresh(id) })
			} else if update {
				lastDatabase = time.Now()
				_ = a.job("Database update", a.updateAssets)
			}
		}
	}
}
func (a *App) Close() {
	a.closeOnce.Do(func() {
		a.mu.Lock()
		a.shutting = true
		a.mu.Unlock()
		a.cancel()
		for _, cb := range a.callbacks {
			_ = cb.Unregister()
		}
		a.op.Lock()
		defer a.op.Unlock()
		a.disconnect()
	})
}

func (a *App) refresh(id string) error {
	a.mu.Lock()
	var sub core.Subscription
	for _, s := range a.state.Subscriptions {
		if s.ID == id {
			sub = s
		}
	}
	a.mu.Unlock()
	if sub.ID == "" {
		return fmt.Errorf("subscription not found")
	}
	servers, e := core.FetchSubscription(a.ctx, sub.URL)
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.state.Subscriptions {
		if a.state.Subscriptions[i].ID == id {
			if e != nil {
				a.state.Subscriptions[i].LastError = core.Redact(e.Error())
			} else {
				now := time.Now()
				a.state.Subscriptions[i].UpdatedAt = &now
				a.state.Subscriptions[i].LastError = ""
				a.state.Merge(servers, id)
				a.pending = a.conn != nil
			}
			break
		}
	}
	saveErr := a.save()
	if e != nil {
		return e
	}
	return saveErr
}
func (a *App) updateAssets() error {
	m, e := core.UpdateAssets(a.ctx, a.assetsRoot)
	if e != nil {
		return e
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.state.DatabaseVersion = m.Version
	a.pending = a.conn != nil
	return a.save()
}
func (a *App) measureAll(fastest bool) error {
	a.mu.Lock()
	servers := append([]core.Server(nil), a.state.Servers...)
	iface := ""
	if a.conn != nil {
		iface = a.conn.Uplink
	}
	a.mu.Unlock()
	if len(servers) == 0 {
		return fmt.Errorf("import a server first")
	}
	type result struct {
		id  string
		ms  float64
		err error
	}
	ch := make(chan result, len(servers))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for _, s := range servers {
		wg.Add(1)
		go func(s core.Server) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-a.ctx.Done():
				return
			}
			defer func() { <-sem }()
			ms, e := platform.Measure(a.ctx, s, iface)
			ch <- result{s.ID, ms, e}
		}(s)
	}
	wg.Wait()
	close(ch)
	a.mu.Lock()
	defer a.mu.Unlock()
	best := 1e12
	id := ""
	for r := range ch {
		for i := range a.state.Servers {
			v := &a.state.Servers[i]
			if v.ID == r.id {
				if r.err != nil {
					v.Latency = nil
					v.LastError = r.err.Error()
				} else {
					v.Latency = &r.ms
					v.LastError = ""
					if r.ms < best {
						best = r.ms
						id = v.ID
					}
				}
			}
		}
	}
	if fastest && id != "" {
		a.state.SelectedServerID = id
		a.pending = a.conn != nil
	}
	return a.save()
}
func (a *App) Command(action string, p json.RawMessage) (any, error) {
	if action == "snapshot" {
		return a.Snapshot(), nil
	}
	if action == "telemetry" {
		a.mu.Lock()
		defer a.mu.Unlock()
		stats := packet.Stats{}
		if a.conn != nil {
			stats = a.conn.Engine.Stats()
		}
		return core.Object{"version": a.version, "stats": stats, "lowPower": platform.LowPower()}, nil
	}
	var q struct {
		ID        string        `json:"id"`
		Text      string        `json:"text"`
		Name      string        `json:"name"`
		URL       string        `json:"url"`
		Hours     float64       `json:"hours"`
		Direction int           `json:"direction"`
		Settings  core.Settings `json:"settings"`
		Rule      core.Rule     `json:"rule"`
		Host      string        `json:"host"`
		Port      uint16        `json:"port"`
		Network   string        `json:"network"`
		Protocol  string        `json:"protocol"`
	}
	if len(p) > 8*1024*1024+4096 {
		return nil, fmt.Errorf("request too large")
	}
	if len(p) > 0 && json.Unmarshal(p, &q) != nil {
		return nil, fmt.Errorf("invalid request")
	}
	switch action {
	case "checkUpdate":
		return nil, a.job("Check for updates", func() error {
			offer, e := a.updater.Check(a.ctx, buildinfo.Version, runtime.GOARCH)
			if e != nil {
				return e
			}
			a.mu.Lock()
			a.updateOffer = &offer
			a.version++
			a.mu.Unlock()
			return nil
		})
	case "installUpdate":
		return nil, a.job("Install update", func() error {
			a.mu.Lock()
			offer := a.updateOffer
			a.mu.Unlock()
			if offer == nil || !offer.Available {
				return fmt.Errorf("check for a newer version first")
			}
			// Refresh the authenticated offer; never take executable URLs from the UI.
			latest, e := a.updater.Check(a.ctx, buildinfo.Version, runtime.GOARCH)
			if e != nil {
				return e
			}
			if !latest.Available {
				return fmt.Errorf("no newer version is available")
			}
			path, e := a.updater.Download(a.ctx, latest, filepath.Join(filepath.Dir(a.path), "Updates"))
			if e != nil {
				return e
			}
			if e = platform.LaunchInstaller(path); e != nil {
				return e
			}
			if a.Quit != nil {
				a.Quit()
			}
			return nil
		})
	case "toggle":
		return nil, a.job("Connection", func() error {
			a.mu.Lock()
			connected := a.conn != nil
			a.mu.Unlock()
			if connected {
				a.disconnect()
				return nil
			}
			return a.connect()
		})
	case "apply":
		return nil, a.job("Apply policy", a.connect)
	case "measure", "fastest":
		return nil, a.job("TCP measurement", func() error { return a.measureAll(action == "fastest") })
	case "import":
		return nil, a.job("Import", func() error {
			servers, e := core.Parse(q.Text)
			if e != nil {
				return e
			}
			a.mu.Lock()
			defer a.mu.Unlock()
			seen := map[string]bool{}
			for _, s := range a.state.Servers {
				seen[s.Fingerprint] = true
			}
			for _, s := range servers {
				if !seen[s.Fingerprint] {
					a.state.Servers = append(a.state.Servers, s)
					seen[s.Fingerprint] = true
				}
			}
			if a.state.SelectedServerID == "" && len(a.state.Servers) > 0 {
				a.state.SelectedServerID = a.state.Servers[0].ID
			}
			return a.save()
		})
	case "subscriptionAdd":
		return nil, a.job("Add subscription", func() error {
			if q.Name == "" || q.Hours < 0 || q.Hours > 8760 {
				return fmt.Errorf("enter a subscription name and valid refresh interval")
			}
			servers, e := core.FetchSubscription(a.ctx, q.URL)
			if e != nil {
				return e
			}
			now := time.Now()
			sub := core.Subscription{ID: core.ID(), Name: q.Name, URL: q.URL, RefreshHours: q.Hours, UpdatedAt: &now}
			a.mu.Lock()
			defer a.mu.Unlock()
			a.state.Subscriptions = append(a.state.Subscriptions, sub)
			a.state.Merge(servers, sub.ID)
			return a.save()
		})
	case "subscriptionRefresh":
		return nil, a.job("Refresh subscription", func() error { return a.refresh(q.ID) })
	case "refreshAll":
		return nil, a.job("Refresh subscriptions", func() error {
			a.mu.Lock()
			subs := append([]core.Subscription(nil), a.state.Subscriptions...)
			a.mu.Unlock()
			var last error
			for _, s := range subs {
				if e := a.refresh(s.ID); e != nil {
					last = e
				}
			}
			return last
		})
	case "databaseUpdate":
		return nil, a.job("Database update", a.updateAssets)
	case "probe", "probeDirect", "inspect", "resolve":
		return nil, a.job("Diagnostics", func() error {
			a.mu.Lock()
			t := a.conn
			id := a.activeID
			a.mu.Unlock()
			if action == "resolve" {
				if q.Host == "" {
					return fmt.Errorf("enter a DNS name")
				}
				ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
				defer cancel()
				ips, e := net.DefaultResolver.LookupHost(ctx, q.Host)
				if e != nil {
					return fmt.Errorf("DNS lookup failed")
				}
				a.mu.Lock()
				a.result = core.Object{"host": q.Host, "addresses": ips, "note": "Windows DNS lookup through the current system policy"}
				a.mu.Unlock()
				return nil
			}
			if t == nil {
				return fmt.Errorf("connect before using this diagnostic")
			}
			var b []byte
			var e error
			if action == "inspect" {
				b, e = t.Engine.Inspect(p)
			} else {
				tag := "proxy-" + id
				if action == "probeDirect" {
					tag = "direct"
				}
				b, e = t.Engine.Probe(tag)
			}
			if e != nil {
				return fmt.Errorf("diagnostic request failed")
			}
			var result any
			if json.Unmarshal(b, &result) != nil {
				return fmt.Errorf("invalid diagnostic response")
			}
			a.mu.Lock()
			defer a.mu.Unlock()
			if a.conn != t {
				return nil
			}
			a.result = result
			if v, ok := result.(map[string]any); ok {
				if ip, ok := v["ip"].(string); ok {
					if action == "probeDirect" {
						a.directIP = ip
					} else {
						a.publicIP = ip
						a.verified = true
						a.health = "Connected"
					}
				}
			}
			return nil
		})
	case "export":
		a.mu.Lock()
		raw, _ := json.MarshalIndent(core.Object{"platform": "Windows", "events": a.logs, "mode": a.state.Settings.Mode, "serverCount": len(a.state.Servers), "ruleCount": len(a.state.Rules), "databaseVersion": a.state.DatabaseVersion, "health": a.health}, "", "  ")
		a.mu.Unlock()
		if a.Export == nil {
			return nil, fmt.Errorf("export unavailable")
		}
		return nil, a.Export(core.Redact(string(raw)))
	case "quit":
		if a.Quit != nil {
			a.Quit()
		}
		return nil, nil
	case "minimize":
		if a.Minimize != nil {
			a.Minimize()
		}
		return nil, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.busy || a.shutting {
		return nil, fmt.Errorf("wait for the current operation")
	}
	changedPolicy := false
	switch action {
	case "settings":
		if e := core.ValidateSettings(q.Settings); e != nil {
			return nil, e
		}
		a.state.Settings = q.Settings
		changedPolicy = true
	case "select", "favorite", "rename", "delete":
		index := -1
		for i, s := range a.state.Servers {
			if s.ID == q.ID {
				index = i
				break
			}
		}
		if index < 0 {
			return nil, fmt.Errorf("server not found")
		}
		switch action {
		case "select":
			a.state.SelectedServerID = q.ID
			changedPolicy = true
		case "favorite":
			a.state.Servers[index].Favorite = !a.state.Servers[index].Favorite
		case "rename":
			a.state.Servers[index].CustomName = q.Name
		case "delete":
			for _, r := range a.state.Rules {
				if r.ServerID == q.ID {
					return nil, fmt.Errorf("this server is pinned by a routing rule; edit that rule first")
				}
			}
			a.state.Servers = append(a.state.Servers[:index], a.state.Servers[index+1:]...)
			if a.state.SelectedServerID == q.ID {
				a.state.SelectedServerID = ""
				if len(a.state.Servers) > 0 {
					a.state.SelectedServerID = a.state.Servers[0].ID
				}
			}
			changedPolicy = true
		}
	case "ruleSave":
		r := q.Rule
		if e := core.ValidateRule(r); e != nil {
			return nil, e
		}
		if r.ServerID != "" {
			found := false
			for _, s := range a.state.Servers {
				found = found || s.ID == r.ServerID
			}
			if !found {
				return nil, fmt.Errorf("pinned server is unavailable")
			}
		}
		found := false
		for i, v := range a.state.Rules {
			if r.ID != "" && v.ID == r.ID {
				a.state.Rules[i] = r
				found = true
				break
			}
		}
		if !found {
			r.ID = core.ID()
			a.state.Rules = append(a.state.Rules, r)
		}
		changedPolicy = true
	case "ruleDelete", "ruleToggle", "ruleMove":
		for i, r := range a.state.Rules {
			if r.ID != q.ID {
				continue
			}
			switch action {
			case "ruleDelete":
				a.state.Rules = append(a.state.Rules[:i], a.state.Rules[i+1:]...)
			case "ruleToggle":
				a.state.Rules[i].Enabled = !r.Enabled
			case "ruleMove":
				j := i + q.Direction
				if (q.Direction != 1 && q.Direction != -1) || j < 0 || j >= len(a.state.Rules) {
					return nil, fmt.Errorf("invalid rule position")
				}
				a.state.Rules[i], a.state.Rules[j] = a.state.Rules[j], a.state.Rules[i]
			}
			break
		}
		changedPolicy = true
	case "subscriptionDelete":
		for i, s := range a.state.Subscriptions {
			if s.ID == q.ID {
				a.state.Subscriptions = append(a.state.Subscriptions[:i], a.state.Subscriptions[i+1:]...)
				for j := range a.state.Servers {
					if a.state.Servers[j].SubscriptionID == q.ID {
						a.state.Servers[j].SubscriptionID = ""
					}
				}
				break
			}
		}
	case "subscriptionInterval":
		if q.Hours < 0 || q.Hours > 8760 {
			return nil, fmt.Errorf("invalid interval")
		}
		for i := range a.state.Subscriptions {
			if a.state.Subscriptions[i].ID == q.ID {
				a.state.Subscriptions[i].RefreshHours = q.Hours
			}
		}
	case "clearLogs":
		a.logs = []Event{}
	case "dismissError":
		a.lastError = ""
	default:
		return nil, fmt.Errorf("unknown command")
	}
	if changedPolicy {
		a.pending = a.conn != nil
	}
	return nil, a.save()
}
func DataDirectory() (string, error) {
	p, e := os.UserConfigDir()
	if e != nil {
		return "", e
	}
	return filepath.Join(p, "Aster"), nil
}
