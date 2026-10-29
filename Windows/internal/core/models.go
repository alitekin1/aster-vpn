package core

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"
)

type Object = map[string]any

func ID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

type Server struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	Protocol       string   `json:"protocolName"`
	Fingerprint    string   `json:"fingerprint"`
	SubscriptionID string   `json:"subscriptionID,omitempty"`
	Favorite       bool     `json:"favorite"`
	CustomName     string   `json:"customName,omitempty"`
	Latency        *float64 `json:"latency,omitempty"`
	LastError      string   `json:"lastError,omitempty"`
	Outbound       Object   `json:"-"`
}
type Subscription struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	URL          string     `json:"-"`
	RefreshHours float64    `json:"refreshHours"`
	UpdatedAt    *time.Time `json:"updatedAt,omitempty"`
	LastError    string     `json:"lastError,omitempty"`
}
type Rule struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Group            string `json:"group"`
	Enabled          bool   `json:"enabled"`
	Match            string `json:"match"`
	Value            string `json:"value"`
	Action           string `json:"action"`
	ServerID         string `json:"serverID,omitempty"`
	AdditionalFields Object `json:"additionalFields,omitempty"`
}
type DNS struct {
	DirectResolver     string `json:"directResolver"`
	ProxyResolver      string `json:"proxyResolver"`
	Cache              bool   `json:"cache"`
	UseSystemResolvers bool   `json:"useSystemResolvers"`
}
type Settings struct {
	Mode               string `json:"mode"`
	DefaultAction      string `json:"defaultAction"`
	DNS                DNS    `json:"dns"`
	AutoConnect        bool   `json:"autoConnect"`
	Reconnect          bool   `json:"reconnect"`
	Failover           bool   `json:"failover"`
	DatabaseAutoUpdate bool   `json:"databaseAutoUpdate"`
	Theme              string `json:"theme"`
}
type State struct {
	Servers          []Server       `json:"servers"`
	Subscriptions    []Subscription `json:"subscriptions"`
	Rules            []Rule         `json:"rules"`
	SelectedServerID string         `json:"selectedServerID"`
	Settings         Settings       `json:"settings"`
	DatabaseVersion  string         `json:"databaseVersion"`
}

func DefaultState() State {
	return State{Servers: []Server{}, Subscriptions: []Subscription{}, Rules: []Rule{}, Settings: Settings{Mode: "smartIran", DefaultAction: "proxy", Reconnect: true, DatabaseAutoUpdate: true, Theme: "system", DNS: DNS{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query", true, true}}}
}
func CloneObject(o Object) Object {
	b, _ := json.Marshal(o)
	var v Object
	_ = json.Unmarshal(b, &v)
	return v
}
func (s *State) Merge(in []Server, subscription string) {
	old := map[string]Server{}
	pinned := map[string]bool{}
	for _, r := range s.Rules {
		pinned[r.ServerID] = true
	}
	for _, v := range s.Servers {
		if v.SubscriptionID == subscription {
			old[v.Fingerprint] = v
		}
	}
	seen := map[string]bool{}
	ids := map[string]bool{}
	merged := []Server{}
	for _, v := range in {
		if seen[v.Fingerprint] {
			continue
		}
		seen[v.Fingerprint] = true
		v.SubscriptionID = subscription
		if o, ok := old[v.Fingerprint]; ok {
			v.ID = o.ID
			v.Favorite = o.Favorite
			v.CustomName = o.CustomName
			v.Latency = o.Latency
		}
		ids[v.ID] = true
		merged = append(merged, v)
	}
	kept := []Server{}
	for _, v := range s.Servers {
		if v.SubscriptionID != subscription || pinned[v.ID] && !ids[v.ID] {
			kept = append(kept, v)
		}
	}
	s.Servers = append(kept, merged...)
	found := false
	for _, v := range s.Servers {
		found = found || v.ID == s.SelectedServerID
	}
	if !found {
		s.SelectedServerID = ""
		if len(s.Servers) > 0 {
			s.SelectedServerID = s.Servers[0].ID
		}
	}
}
