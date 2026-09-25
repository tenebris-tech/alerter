/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package alerter

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// testCert is a self-signed certificate for 127.0.0.1, and a pool trusting it.
func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// fakeSMTP is a minimal SMTP server: EHLO, STARTTLS, AUTH PLAIN, MAIL, RCPT,
// DATA, QUIT. It records the envelope and message of each delivery.
type fakeSMTP struct {
	implicitTLS bool   // TLS from the first byte
	startTLS    bool   // advertise STARTTLS
	user, pass  string // advertise AUTH PLAIN and require these
	rejectRcpt  string // answer 550 to this recipient
	silent      bool   // accept connections and never answer
	dropQuit    bool   // close the connection instead of answering QUIT

	cert tls.Certificate
	ln   net.Listener

	mu        sync.Mutex
	helo      string
	from      string
	rcpts     []string
	data      string
	authed    bool
	tlsActive bool
}

func startSMTP(t *testing.T, f *fakeSMTP) (host string, port int) {
	t.Helper()
	var pool *x509.CertPool
	f.cert, pool = testCert(t)
	old := smtpRootCAs
	smtpRootCAs = pool
	t.Cleanup(func() { smtpRootCAs = old })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if f.implicitTLS {
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{f.cert}})
	}
	f.ln = ln
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.handle(c)
		}
	}()
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port
}

func (f *fakeSMTP) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	if f.silent {
		_, _ = c.Read(make([]byte, 1))
		return
	}
	f.mu.Lock()
	f.tlsActive = f.implicitTLS
	f.mu.Unlock()
	r := bufio.NewReader(c)
	say := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
	say("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		f.mu.Lock()
		tlsOn := f.tlsActive
		f.mu.Unlock()
		switch verb {
		case "EHLO", "HELO":
			f.mu.Lock()
			f.helo = line
			f.mu.Unlock()
			lines := []string{"fake"}
			if f.startTLS && !tlsOn {
				lines = append(lines, "STARTTLS")
			}
			if f.user != "" {
				lines = append(lines, "AUTH PLAIN")
			}
			for i, l := range lines {
				sep := "-"
				if i == len(lines)-1 {
					sep = " "
				}
				say("250" + sep + l)
			}
		case "STARTTLS":
			say("220 go ahead")
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{f.cert}})
			if tc.Handshake() != nil {
				return
			}
			c, r = tc, bufio.NewReader(tc)
			say = func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
			f.mu.Lock()
			f.tlsActive = true
			f.mu.Unlock()
		case "AUTH":
			parts := strings.Fields(line)
			raw, _ := base64.StdEncoding.DecodeString(parts[len(parts)-1])
			if string(raw) == "\x00"+f.user+"\x00"+f.pass {
				f.mu.Lock()
				f.authed = true
				f.mu.Unlock()
				say("235 ok")
			} else {
				say("535 bad credentials")
			}
		case "MAIL":
			if f.user != "" && !f.authed {
				say("530 authentication required")
				continue
			}
			f.mu.Lock()
			f.from = line
			f.mu.Unlock()
			say("250 ok")
		case "RCPT":
			if f.rejectRcpt != "" && strings.Contains(line, f.rejectRcpt) {
				say("550 no such user")
				continue
			}
			f.mu.Lock()
			f.rcpts = append(f.rcpts, line)
			f.mu.Unlock()
			say("250 ok")
		case "DATA":
			say("354 go on")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.data = b.String()
			f.mu.Unlock()
			say("250 queued")
		case "QUIT":
			if f.dropQuit {
				return
			}
			say("221 bye")
			return
		default:
			say("502 unknown")
		}
	}
}

func (f *fakeSMTP) got() (from string, rcpts []string, data string, authed, tlsOn bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.from, append([]string(nil), f.rcpts...), f.data, f.authed, f.tlsActive
}

func newSMTPSink(host string, port int, user, pass string) *smtpSink {
	from, _ := mail.ParseAddress("Alerts <alerts@example.com>")
	a, _ := mail.ParseAddress("ops@example.com")
	b, _ := mail.ParseAddress("Pager <pager@example.com>")
	return &smtpSink{host: host, port: port, user: user, pass: pass, from: from, to: []*mail.Address{a, b}}
}

func TestSMTPMessage(t *testing.T) {
	s := newSMTPSink("h", 25, "", "")
	msg := string(s.message(sample))
	head, text, ok := strings.Cut(msg, "\r\n\r\n")
	if !ok {
		t.Fatalf("no header/body separator:\n%s", msg)
	}
	for _, want := range []string{
		`From: "Alerts" <alerts@example.com>`,
		`To: <ops@example.com>, "Pager" <pager@example.com>`,
		"Subject: Provider authentication failed (ClawEh@empire)",
		"Date: Thu, 24 Sep 2026 10:00:00 -0400",
		"X-Priority: 1", "Importance: high",
		"MIME-Version: 1.0", "Content-Type: text/plain; charset=UTF-8",
	} {
		if !strings.Contains(head, want+"\r\n") {
			t.Errorf("header %q missing:\n%s", want, head)
		}
	}
	if !strings.Contains(head, "Message-ID: <") || !strings.Contains(head, "@example.com>\r\n") {
		t.Errorf("Message-ID missing:\n%s", head)
	}
	if !strings.HasSuffix(head, "\r\nContent-Transfer-Encoding: quoted-printable") {
		t.Errorf("not quoted-printable:\n%s", head)
	}
	want := "claude-cli returned 401\r\n\r\n" +
		"Source: ClawEh@empire\r\nPriority: Urgent\r\nDate: Thu, 24 Sep 2026 10:00:00 -0400\r\n" +
		"Event: claude-cli\r\nRepeats: 3 suppressed since the last one\r\n\r\n" +
		"run `claude login`\r\non the host\r\n"
	if got := decodeQP(t, text); got != want {
		t.Errorf("body =\n%q\nwant\n%q", got, want)
	}
	if strings.Contains(strings.ReplaceAll(msg, "\r\n", ""), "\n") {
		t.Error("bare LF in message")
	}

	normal := string(s.message(Alert{Title: "Tëst ünicode", Time: sample.Time}))
	if strings.Contains(normal, "X-Priority") {
		t.Error("normal alert marked as important")
	}
	if !strings.Contains(normal, "Subject: =?utf-8?q?") {
		t.Errorf("non-ASCII subject not encoded:\n%s", normal)
	}
}

func decodeQP(t *testing.T, s string) string {
	t.Helper()
	b, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(s)))
	if err != nil {
		t.Fatalf("quoted-printable: %v", err)
	}
	return string(b)
}

func TestSMTPMessageHostileContent(t *testing.T) {
	s := newSMTPSink("h", 25, "", "")
	a := Alert{
		Title:       strings.Repeat("é", 400) + "\r\nBcc: victim@example.com",
		Description: "bare\rcr and\r\ncrlf",
		Details:     strings.Repeat("x", 5000) + "\n\r.\r\nunicode ✓",
		Time:        sample.Time,
	}
	msg := string(s.message(a))
	for i, line := range strings.Split(msg, "\r\n") {
		if len(line) > 998 {
			t.Errorf("line %d is %d bytes", i, len(line))
		}
		if strings.ContainsRune(line, '\r') || strings.ContainsRune(line, '\n') {
			t.Errorf("line %d has a bare CR or LF: %q", i, line)
		}
		if strings.HasPrefix(line, "Bcc:") {
			t.Error("header injected through the title")
		}
	}
	for _, r := range msg {
		if r > 127 {
			t.Fatal("message is not 7-bit")
		}
	}
	head, text, _ := strings.Cut(msg, "\r\n\r\n")
	subj := head[strings.Index(head, "Subject: "):strings.Index(head, "\r\nDate: ")]
	subj = strings.ReplaceAll(strings.TrimPrefix(subj, "Subject: "), "\r\n ", " ") // unfold
	dec, err := new(mime.WordDecoder).DecodeHeader(subj)
	if err != nil || utf8.RuneCountInString(dec) != smtpSubjectMax {
		t.Errorf("subject decodes to %d runes (%v)", utf8.RuneCountInString(dec), err)
	}
	got := decodeQP(t, text)
	if !strings.Contains(got, "bare\r\ncr and\r\ncrlf") || !strings.Contains(got, "\r\n\r\n.\r\nunicode ✓") {
		t.Errorf("line ends not normalised: %q", got)
	}
}

func TestIsLoopback(t *testing.T) {
	for h, want := range map[string]bool{
		"localhost": true, "LOCALHOST": true, "127.0.0.1": true, "127.1.2.3": true, "::1": true,
		"10.0.0.1": false, "mail.example.com": false, "localhost.example.com": false,
	} {
		if isLoopback(h) != want {
			t.Errorf("isLoopback(%q) = %v", h, !want)
		}
	}
}

func TestSMTPPlain(t *testing.T) {
	f := &fakeSMTP{}
	host, port := startSMTP(t, f)
	s := newSMTPSink(host, port, "", "")
	a := sample
	a.Details = "line one\n.\n.leading dot"
	if err := s.send(context.Background(), a); err != nil {
		t.Fatalf("send: %v", err)
	}
	from, rcpts, data, _, _ := f.got()
	if from != "MAIL FROM:<alerts@example.com>" {
		t.Errorf("envelope from = %q", from)
	}
	if strings.Join(rcpts, "|") != "RCPT TO:<ops@example.com>|RCPT TO:<pager@example.com>" {
		t.Errorf("recipients = %v", rcpts)
	}
	// Dot-stuffed on the wire: a line that is "." arrives as "..".
	if !strings.Contains(data, "\r\n..\r\n..leading dot\r\n") {
		t.Errorf("data not dot-stuffed:\n%q", data)
	}
	if !strings.Contains(data, "Subject: "+subject(sample)+"\r\n") {
		t.Errorf("data = %q", data)
	}
	hostname, _ := os.Hostname()
	f.mu.Lock()
	helo := f.helo
	f.mu.Unlock()
	if helo != "EHLO "+hostname {
		t.Errorf("greeting = %q, want EHLO %s", helo, hostname)
	}
}

func TestSMTPQuitFailureAfterAccept(t *testing.T) {
	f := &fakeSMTP{dropQuit: true}
	host, port := startSMTP(t, f)
	if err := newSMTPSink(host, port, "", "").send(context.Background(), sample); err != nil {
		t.Errorf("message was accepted; a dropped QUIT must not fail it: %v", err)
	}
}

func TestSMTPStartTLSAndAuth(t *testing.T) {
	f := &fakeSMTP{startTLS: true, user: "u", pass: "secret"}
	host, port := startSMTP(t, f)
	if err := newSMTPSink(host, port, "u", "secret").send(context.Background(), sample); err != nil {
		t.Fatalf("send: %v", err)
	}
	_, rcpts, data, authed, tlsOn := f.got()
	if !tlsOn || !authed || len(rcpts) != 2 || data == "" {
		t.Errorf("tls %v auth %v rcpts %v data %d bytes", tlsOn, authed, rcpts, len(data))
	}
}

func TestSMTPImplicitTLS(t *testing.T) {
	f := &fakeSMTP{implicitTLS: true, user: "u", pass: "secret"}
	host, port := startSMTP(t, f)
	s := newSMTPSink(host, port, "u", "secret")
	s.tls = true
	if err := s.send(context.Background(), sample); err != nil {
		t.Fatalf("send: %v", err)
	}
	if _, _, data, authed, tlsOn := f.got(); !tlsOn || !authed || data == "" {
		t.Errorf("tls %v auth %v data %d bytes", tlsOn, authed, len(data))
	}
}

func TestSMTPErrors(t *testing.T) {
	t.Run("bad credentials", func(t *testing.T) {
		host, port := startSMTP(t, &fakeSMTP{startTLS: true, user: "u", pass: "secret"})
		err := newSMTPSink(host, port, "u", "wrong").send(context.Background(), sample)
		if err == nil || !strings.Contains(err.Error(), "auth") {
			t.Errorf("error = %v", err)
		}
	})
	t.Run("server requires auth", func(t *testing.T) {
		host, port := startSMTP(t, &fakeSMTP{startTLS: true, user: "u", pass: "secret"})
		err := newSMTPSink(host, port, "", "").send(context.Background(), sample)
		if err == nil || !strings.Contains(err.Error(), "mail from") {
			t.Errorf("error = %v", err)
		}
	})
	t.Run("recipient rejected", func(t *testing.T) {
		host, port := startSMTP(t, &fakeSMTP{rejectRcpt: "pager@"})
		err := newSMTPSink(host, port, "", "").send(context.Background(), sample)
		if err == nil || !strings.Contains(err.Error(), "rcpt pager@example.com") {
			t.Errorf("error = %v", err)
		}
	})
	t.Run("untrusted certificate", func(t *testing.T) {
		host, port := startSMTP(t, &fakeSMTP{startTLS: true})
		smtpRootCAs = x509.NewCertPool()
		err := newSMTPSink(host, port, "", "").send(context.Background(), sample)
		if err == nil || !strings.Contains(err.Error(), "starttls") {
			t.Errorf("error = %v", err)
		}
	})
	t.Run("connection refused", func(t *testing.T) {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		port := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
		err := newSMTPSink("127.0.0.1", port, "", "").send(context.Background(), sample)
		if err == nil || !strings.Contains(err.Error(), "127.0.0.1:"+strconv.Itoa(port)) {
			t.Errorf("error = %v", err)
		}
	})
	t.Run("silent server times out", func(t *testing.T) {
		host, port := startSMTP(t, &fakeSMTP{silent: true})
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		start := time.Now()
		if err := newSMTPSink(host, port, "", "").send(ctx, sample); err == nil {
			t.Error("expected a timeout")
		}
		if time.Since(start) > 2*time.Second {
			t.Error("send did not stop at the context deadline")
		}
	})
	t.Run("cancelled without deadline", func(t *testing.T) {
		host, port := startSMTP(t, &fakeSMTP{silent: true})
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(100*time.Millisecond, cancel)
		if err := newSMTPSink(host, port, "", "").send(ctx, sample); err == nil {
			t.Error("expected an error after cancel")
		}
	})
}

func TestSMTPPriorityHeaders(t *testing.T) {
	s := newSMTPSink("h", 25, "", "")
	for _, tc := range []struct {
		level  int
		marked bool
	}{{Normal, false}, {Urgent, true}, {Emergency, true}, {9, false}} {
		msg := string(s.message(Alert{Priority: tc.level, Title: "t", Time: sample.Time}))
		head, _, _ := strings.Cut(msg, "\r\n\r\n")
		marked := strings.Contains(head, "X-Priority: 1\r\n") && strings.Contains(head, "Importance: high\r\n")
		if marked != tc.marked || (!tc.marked && (strings.Contains(head, "X-Priority") || strings.Contains(head, "Importance"))) {
			t.Errorf("level %d: priority headers %v, want %v", tc.level, marked, tc.marked)
		}
	}
}

func TestMailBody(t *testing.T) {
	at := sample.Time
	cases := []struct {
		name string
		a    Alert
		want string
	}{
		{"minimal: title stands in for the message", Alert{Title: "Disk full", Time: at},
			"Disk full\n\nPriority: Normal\nDate: Thu, 24 Sep 2026 10:00:00 -0400\n"},
		{"emergency with source", Alert{Priority: Emergency, Title: "t", Description: "d", App: "A", Instance: "i", Time: at},
			"d\n\nSource: A@i\nPriority: Emergency\nDate: Thu, 24 Sep 2026 10:00:00 -0400\n"},
		{"out of range level", Alert{Priority: 9, Title: "t", Description: "d", Time: at},
			"d\n\nPriority: Normal\nDate: Thu, 24 Sep 2026 10:00:00 -0400\n"},
		{"event and details", Alert{Priority: Urgent, Title: "t", Description: "d", EventID: "e", Details: "x\ny\n\n", Time: at},
			"d\n\nPriority: Urgent\nDate: Thu, 24 Sep 2026 10:00:00 -0400\nEvent: e\n\nx\ny\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mailBody(tc.a); got != tc.want {
				t.Errorf("mailBody =\n%q\nwant\n%q", got, tc.want)
			}
		})
	}
}

// TestMailIsFullerThanPushover: mail carries the labelled particulars;
// Pushover keeps the short body.
func TestMailIsFullerThanPushover(t *testing.T) {
	msg := string(newSMTPSink("h", 25, "", "").message(sample))
	_, text, _ := strings.Cut(msg, "\r\n\r\n")
	mail := decodeQP(t, text)
	for _, want := range []string{"\r\nSource: ClawEh@empire\r\n", "\r\nPriority: Urgent\r\n", "\r\nDate: "} {
		if !strings.Contains(mail, want) {
			t.Errorf("mail lacks %q", want)
		}
	}
	push := pushoverForm(t, sample)
	if strings.Contains(push, "Source:") || strings.Contains(push, "Date:") || !strings.Contains(push, "\nUrgent alert\n") {
		t.Errorf("pushover text changed: %q", push)
	}
}
