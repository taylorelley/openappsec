// Copyright (C) 2026 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fleet

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// EndpointPolicy decides which metrics endpoints the manager may connect to.
//
// It is a value rather than a package-level switch so that a test can exercise
// a stricter policy without mutating shared state that a concurrent test is
// reading.
type EndpointPolicy struct {
	// AllowPrivate permits scraping RFC1918 and unique-local addresses.
	//
	// The normal deployment is exactly that: agents on a private compose or
	// cluster network. Set it false where the manager can reach infrastructure
	// the agents should not be able to make it call.
	AllowPrivate bool
}

// DefaultEndpointPolicy is the policy used unless the operator narrows it.
func DefaultEndpointPolicy() EndpointPolicy {
	return EndpointPolicy{AllowPrivate: true}
}

// Parse validates an agent's metrics endpoint and returns the URL to scrape.
//
// This is a server-side-request-forgery boundary, not a formatting helper. The
// value is not only set by an operator: RecordStatus also takes it from the
// status push, so an enrolled agent can choose what the manager connects to.
// Without validation an agent could point the manager at a cloud metadata
// service or another internal host, and the scraped values would then be
// readable through the agent's metrics view.
//
// Parse can only classify a literal address. A hostname is resolved by the
// transport, so the address a name actually resolves to is checked at dial
// time instead — see Transport.
func (p EndpointPolicy) Parse(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", fmt.Errorf("fleet: metrics endpoint is empty")
	}

	host, port := endpoint, strconv.Itoa(DefaultMetricsPort)

	// A full URL is accepted only for http and https, and its path is
	// discarded: the manager always scrapes /metrics.
	if strings.Contains(endpoint, "://") {
		parsed, err := url.Parse(endpoint)
		if err != nil {
			return "", fmt.Errorf("fleet: malformed metrics endpoint: %w", err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return "", fmt.Errorf("fleet: metrics endpoint scheme %q is not allowed", parsed.Scheme)
		}
		host = parsed.Hostname()
		if hostPort := parsed.Port(); hostPort != "" {
			port = hostPort
		}
		if err := p.checkTarget(host); err != nil {
			return "", err
		}
		return (&url.URL{
			Scheme: parsed.Scheme,
			Host:   net.JoinHostPort(host, port),
			Path:   "/metrics",
		}).String(), nil
	}

	// Otherwise a bare host, or host:port.
	if h, prt, err := net.SplitHostPort(endpoint); err == nil {
		host, port = h, prt
	}
	if host == "" {
		return "", fmt.Errorf("fleet: metrics endpoint has no host")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("fleet: metrics endpoint port %q is not valid", port)
	}
	if err := p.checkTarget(host); err != nil {
		return "", err
	}

	return (&url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(host, port),
		Path:   "/metrics",
	}).String(), nil
}

// Transport is the only transport the scraper may use.
//
// Parse cannot decide a hostname: `metrics.example.com` is a legal endpoint
// whose A record can point at 127.0.0.1 or at 169.254.169.254, and it can
// change between the check and the connection. Control runs after resolution
// with the address the socket is about to connect to, which is the one place
// the decision cannot be evaded — including for each hop of a redirect.
//
// Proxy is nil deliberately: an HTTP_PROXY in the environment would send every
// scrape to the proxy instead, so Control would only ever see the proxy's own
// address and the check would silently stop meaning anything.
func (p EndpointPolicy) Transport() *http.Transport {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   p.control,
	}
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		MaxIdleConns:          32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

// control refuses a socket whose resolved peer is an address the policy bars.
func (p EndpointPolicy) control(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("fleet: refusing to dial %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Control is called with a resolved address, so this should not
		// happen; refuse rather than let an unclassifiable peer through.
		return fmt.Errorf("fleet: refusing to dial %q: not an IP address", host)
	}
	return p.checkIP(ip)
}

// checkTarget classifies a literal address, and lets a hostname through for
// control to decide once it has been resolved.
func (p EndpointPolicy) checkTarget(host string) error {
	if host == "" {
		return fmt.Errorf("fleet: metrics endpoint has no host")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil // a hostname; classified at dial time instead
	}
	return p.checkIP(ip)
}

// checkIP refuses the address families that make SSRF worth attempting.
func (p EndpointPolicy) checkIP(ip net.IP) error {
	switch {
	case ip.IsLoopback():
		return fmt.Errorf("fleet: refusing to scrape the loopback address %q", ip.String())
	case ip.IsUnspecified():
		return fmt.Errorf("fleet: refusing to scrape the unspecified address %q", ip.String())
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		// 169.254.169.254 is the cloud metadata address; the whole range goes.
		return fmt.Errorf("fleet: refusing to scrape the link-local address %q", ip.String())
	case ip.IsInterfaceLocalMulticast(), ip.IsMulticast():
		return fmt.Errorf("fleet: refusing to scrape the multicast address %q", ip.String())
	case ip.IsPrivate() && !p.AllowPrivate:
		return fmt.Errorf("fleet: refusing to scrape the private address %q", ip.String())
	}
	return nil
}
