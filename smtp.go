/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package alerter

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
)

// smtpRootCAs verifies the server certificate; nil means the system pool.
// Tests set it to trust their own server.
var smtpRootCAs *x509.CertPool

const defaultSMTPPort = 587

// smtpSubjectMax keeps the encoded Subject header well inside the 998-byte
// line limit of RFC 5322.
const smtpSubjectMax = 200

// smtpSink sends one message addressed to every recipient. Port 465 is
// implicit TLS; any other port must offer STARTTLS, except on a loopback
// host (a local relay), so neither the alert nor the credentials cross the
// network in clear.
type smtpSink struct {
	host       string
	port       int
	tls        bool // implicit TLS (port 465) rather than STARTTLS
	user, pass string
	from       *mail.Address
	to         []*mail.Address
}

func smtpFromEnv() (sink, error) {
	if !anySet(EnvSMTPHost, EnvSMTPPort, EnvSMTPUser, EnvSMTPPassword, EnvSMTPFrom, EnvSMTPTo) {
		return nil, nil
	}
	if err := require("smtp", EnvSMTPHost, EnvSMTPFrom, EnvSMTPTo); err != nil {
		return nil, err
	}
	s := &smtpSink{host: env(EnvSMTPHost), port: defaultSMTPPort, user: env(EnvSMTPUser), pass: env(EnvSMTPPassword)}
	if p := env(EnvSMTPPort); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("alerter: smtp: %s %q is not a port number", EnvSMTPPort, p)
		}
		s.port = n
	}
	s.tls = s.port == 465
	if (s.user == "") != (s.pass == "") {
		return nil, fmt.Errorf("alerter: smtp: set both %s and %s, or neither", EnvSMTPUser, EnvSMTPPassword)
	}
	from, err := mail.ParseAddress(env(EnvSMTPFrom))
	if err != nil {
		return nil, fmt.Errorf("alerter: smtp: %s: %w", EnvSMTPFrom, err)
	}
	s.from = from
	to := strings.Trim(env(EnvSMTPTo), ", ")
	if to == "" {
		return nil, fmt.Errorf("alerter: smtp: %s has no address", EnvSMTPTo)
	}
	s.to, err = mail.ParseAddressList(to)
	if err != nil {
		return nil, fmt.Errorf("alerter: smtp: %s: %w", EnvSMTPTo, err)
	}
	if len(s.to) == 0 {
		return nil, fmt.Errorf("alerter: smtp: %s has no address", EnvSMTPTo)
	}
	return s, nil
}

func (s *smtpSink) name() string { return "smtp" }

// message renders the RFC 5322 message with CRLF line endings.
func (s *smtpSink) message(a Alert) []byte {
	to := make([]string, len(s.to))
	for i, t := range s.to {
		to[i] = t.String()
	}
	var id [12]byte
	_, _ = rand.Read(id[:])
	domain := s.from.Address[strings.LastIndex(s.from.Address, "@")+1:]

	var b strings.Builder
	b.WriteString("From: " + s.from.String() + "\r\n")
	b.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	// The encoder splits long text into encoded words of at most 75 bytes,
	// separated by spaces; fold at those spaces to keep each line short.
	subj := mime.QEncoding.Encode("utf-8", truncate(subject(a), smtpSubjectMax))
	b.WriteString("Subject: " + strings.ReplaceAll(subj, "?= =?", "?=\r\n =?") + "\r\n")
	b.WriteString("Date: " + a.Time.Format(time.RFC1123Z) + "\r\n")
	b.WriteString("Message-ID: <" + hex.EncodeToString(id[:]) + "@" + domain + ">\r\n")
	if level(a.Priority) != Normal {
		b.WriteString("X-Priority: 1\r\nImportance: high\r\n")
	}
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
	// Quoted-printable keeps every line short and 7-bit whatever the details
	// hold. Line ends are normalised first so a stray CR cannot end a line
	// early on the wire.
	text := strings.ReplaceAll(strings.ReplaceAll(mailBody(a), "\r\n", "\n"), "\r", "\n")
	qp := quotedprintable.NewWriter(&b)
	_, _ = qp.Write([]byte(strings.ReplaceAll(text, "\n", "\r\n")))
	_ = qp.Close()
	return []byte(b.String())
}

// mailBody is the fuller text mail carries: the message, then one labelled
// line per particular, then the details.
//
//	claude-cli returned 401
//
//	Source: ClawEh@empire
//	Priority: Urgent
//	Date: Thu, 24 Sep 2026 10:00:00 -0400
//	Event: claude-cli
//	Repeats: 3 suppressed since the last one
//
//	run `claude login` on the host
func mailBody(a Alert) string {
	var b strings.Builder
	msg := a.Description
	if msg == "" {
		msg = a.Title
	}
	b.WriteString(msg + "\n\n")
	if src := source(a); src != "" {
		fmt.Fprintf(&b, "Source: %s\n", src)
	}
	fmt.Fprintf(&b, "Priority: %s\n", priorityName(a.Priority))
	fmt.Fprintf(&b, "Date: %s\n", a.Time.Format(time.RFC1123Z))
	if a.EventID != "" {
		fmt.Fprintf(&b, "Event: %s\n", a.EventID)
	}
	if a.Repeats > 0 {
		fmt.Fprintf(&b, "Repeats: %d suppressed since the last one\n", a.Repeats)
	}
	if a.Details != "" {
		b.WriteString("\n" + strings.TrimRight(a.Details, "\n") + "\n")
	}
	return b.String()
}

func (s *smtpSink) send(ctx context.Context, a Alert) error {
	if err := s.deliver(ctx, s.message(a)); err != nil {
		return fmt.Errorf("smtp %s:%d: %w", s.host, s.port, err)
	}
	return nil
}

func (s *smtpSink) deliver(ctx context.Context, msg []byte) error {
	addr := net.JoinHostPort(s.host, strconv.Itoa(s.port))
	tlsConf := &tls.Config{ServerName: s.host, RootCAs: smtpRootCAs, MinVersion: tls.VersionTLS12}

	var conn net.Conn
	var err error
	if s.tls {
		conn, err = (&tls.Dialer{Config: tlsConf}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	// The SMTP conversation has no context of its own: bound it by ctx.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	c, err := smtp.NewClient(conn, s.host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer func() { _ = c.Close() }()

	if name, err := os.Hostname(); err == nil && name != "" {
		if err := c.Hello(name); err != nil {
			return fmt.Errorf("ehlo: %w", err)
		}
	}
	if !s.tls {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsConf); err != nil {
				return fmt.Errorf("starttls: %w", err)
			}
		} else if !isLoopback(s.host) {
			return errors.New("server does not offer STARTTLS; refusing to send in clear")
		}
	}
	if s.user != "" {
		if err := c.Auth(smtp.PlainAuth("", s.user, s.pass, s.host)); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	if err := c.Mail(s.from.Address); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}
	for _, t := range s.to {
		if err := c.Rcpt(t.Address); err != nil {
			return fmt.Errorf("rcpt %s: %w", t.Address, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		_ = w.Close()
		return fmt.Errorf("data: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("data: %w", err)
	}
	// The server has accepted the message; a failed QUIT does not undo that.
	_ = c.Quit()
	return nil
}

// isLoopback reports whether host is localhost or a loopback address.
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
