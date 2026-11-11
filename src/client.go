// client is a test client for the XDP load balancer.
//
// It sends traffic to the VIP and reports which backend answered each request.
//
// A "flow" is one TCP connection or one UDP socket. Every flow gets its own
// ephemeral source port, so it has its own 5-tuple and its own hash in the
// load balancer. Backends must put their name on the first line of the reply
// (for example "backend-2"): the HTTP 200 body for TCP, the datagram for UDP.
//
// Examples:
//
//	./client -vip 192.0.2.10:8080                  # 100 TCP flows, show the distribution
//	./client -flows 20 -per-flow 10                # every connection must stick to one backend
//	./client -mode udp -flows 100 -expect 3        # UDP; fail unless exactly 3 backends answer
//
// The UDP socket is connected (net.Dial), so the kernel drops any reply whose
// source address is not the VIP. That makes the UDP mode a direct server
// return check as well: if a backend replies from its own IP, the client sees a
// timeout instead of a name.
//
// Exit status is 0 on success and 1 on any request error, stickiness violation
// or -expect mismatch, so test scripts can use it directly.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	vip := flag.String("vip", "192.0.2.10:8080", "VIP as host:port")
	mode := flag.String("mode", "tcp", "tcp (HTTP GET) or udp (datagram echo)")
	flows := flag.Int("flows", 100, "number of flows; each is a new TCP connection or UDP socket (new source port)")
	perFlow := flag.Int("per-flow", 1, "requests per flow; above 1, each flow must stay on one backend")
	conc := flag.Int("c", 8, "flows running at the same time")
	timeout := flag.Duration("timeout", 2*time.Second, "timeout per request")
	expect := flag.Int("expect", 0, "if above 0, fail unless exactly this many distinct backends answered")
	flag.Parse()

	if *mode != "tcp" && *mode != "udp" {
		fatalf("unknown -mode %q (use tcp or udp)", *mode)
	}
	if *flows < 1 || *perFlow < 1 || *conc < 1 {
		fatalf("-flows, -per-flow and -c must all be at least 1")
	}

	runFlow := func() ([]string, int, error) {
		if *mode == "udp" {
			return udpFlow(*vip, *perFlow, *timeout)
		}
		return tcpFlow(*vip, *perFlow, *timeout)
	}

	var (
		mu         sync.Mutex
		counts     = map[string]int{}
		reqErrors  int
		violations int
		errSamples []string
		badSamples []string
	)

	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < *conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				names, nerr, err := runFlow()

				mu.Lock()
				for _, n := range names {
					counts[n]++
				}
				if nerr > 0 {
					reqErrors += nerr
					if err != nil && len(errSamples) < 3 && !contains(errSamples, err.Error()) {
						errSamples = append(errSamples, err.Error())
					}
				}
				if d := distinct(names); len(d) > 1 {
					violations++
					if len(badSamples) < 3 {
						badSamples = append(badSamples, fmt.Sprintf("flow %d answered by %s", i, strings.Join(d, ", ")))
					}
				}
				mu.Unlock()
			}
		}()
	}

	start := time.Now()
	for i := 0; i < *flows; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	elapsed := time.Since(start)

	total := *flows * *perFlow
	ok := total - reqErrors

	fmt.Printf("%s -> %s   flows=%d per-flow=%d concurrency=%d\n\n", *mode, *vip, *flows, *perFlow, *conc)

	names := make([]string, 0, len(counts))
	maxCount := 0
	for n, c := range counts {
		names = append(names, n)
		if c > maxCount {
			maxCount = c
		}
	}
	sort.Strings(names)
	for _, n := range names {
		c := counts[n]
		bar := strings.Repeat("#", (c*30+maxCount-1)/maxCount)
		fmt.Printf("  %-16s %6d  %5.1f%%  %s\n", n, c, 100*float64(c)/float64(ok), bar)
	}
	if len(names) == 0 {
		fmt.Println("  no successful replies")
	}

	fmt.Printf("\nrequests: %d ok, %d failed   elapsed: %s   rate: %.0f req/s\n",
		ok, reqErrors, elapsed.Round(time.Millisecond), float64(total)/elapsed.Seconds())

	var failures []string
	if reqErrors > 0 {
		failures = append(failures, fmt.Sprintf("%d requests failed (e.g. %s)", reqErrors, strings.Join(errSamples, "; ")))
	}
	if violations > 0 {
		failures = append(failures, fmt.Sprintf("%d flows were not sticky (%s)", violations, strings.Join(badSamples, "; ")))
	}
	if *expect > 0 && len(names) != *expect {
		failures = append(failures, fmt.Sprintf("expected %d distinct backends, saw %d", *expect, len(names)))
	}

	if len(failures) > 0 {
		for _, f := range failures {
			fmt.Println("FAIL:", f)
		}
		os.Exit(1)
	}
	if *perFlow > 1 {
		fmt.Printf("PASS: all %d flows stayed on a single backend\n", *flows)
	} else {
		fmt.Println("PASS")
	}
}

// tcpFlow opens one TCP connection and sends k HTTP GETs over it. It returns
// the backend name from each reply, the number of requests that failed, and
// the first error.
func tcpFlow(vip string, k int, timeout time.Duration) ([]string, int, error) {
	var dials int32
	dialer := net.Dialer{Timeout: timeout}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			atomic.AddInt32(&dials, 1)
			return dialer.DialContext(ctx, network, addr)
		},
		MaxConnsPerHost:   1,
		DisableKeepAlives: k == 1,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: timeout}
	url := "http://" + vip + "/"

	names := make([]string, 0, k)
	for i := 0; i < k; i++ {
		resp, err := client.Get(url)
		if err != nil {
			return names, k - len(names), err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		if err != nil {
			return names, k - len(names), err
		}
		if resp.StatusCode != http.StatusOK {
			return names, k - len(names), fmt.Errorf("HTTP status %d", resp.StatusCode)
		}
		names = append(names, firstLine(string(body)))
	}
	if k > 1 && atomic.LoadInt32(&dials) > 1 {
		return names, 1, fmt.Errorf("connection was reopened %d time(s): the backend closed a keep-alive connection, so stickiness cannot be checked", dials-1)
	}
	return names, 0, nil
}

// udpFlow opens one UDP socket and sends k datagrams from it, waiting for a
// reply after each one.
func udpFlow(vip string, k int, timeout time.Duration) ([]string, int, error) {
	conn, err := net.Dial("udp", vip)
	if err != nil {
		return nil, k, err
	}
	defer conn.Close()

	buf := make([]byte, 512)
	names := make([]string, 0, k)
	for i := 0; i < k; i++ {
		conn.SetDeadline(time.Now().Add(timeout))
		if _, err := conn.Write([]byte(fmt.Sprintf("ping %d\n", i))); err != nil {
			return names, k - len(names), err
		}
		n, err := conn.Read(buf)
		if err != nil {
			return names, k - len(names), err
		}
		names = append(names, firstLine(string(buf[:n])))
	}
	return names, 0, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(strings.SplitN(s, "\n", 2)[0])
	if s == "" {
		return "(empty reply)"
	}
	return s
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func distinct(names []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "client: "+format+"\n", args...)
	os.Exit(2)
}