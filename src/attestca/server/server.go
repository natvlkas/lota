// SPDX-License-Identifier: MIT
// LOTA Attestation CA - TLS enrollment server
//
// One TLS connection carries one enrollment: the server reads a
// BeginRequest, runs the credential-activation challenge, reads the
// CompleteRequest with the activated secret, and replies with the issued
// AIK certificate. Enrollment errors are mapped to wire status codes.

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/szymonwilczek/lota/attestca/ca"
	"github.com/szymonwilczek/lota/attestca/credential"
	"github.com/szymonwilczek/lota/attestca/enroll"
	"github.com/szymonwilczek/lota/attestca/wire"
)

const (
	defaultReadTimeout  = 15 * time.Second
	defaultWriteTimeout = 15 * time.Second
	defaultMaxConns     = 256
)

// Config configures the enrollment server.
type Config struct {
	// Service performs the actual enrollment.
	Service *enroll.Service

	// TLSConfig is the server TLS configuration (certificate required).
	TLSConfig *tls.Config

	// Logger receives structured events; nil discards.
	Logger *slog.Logger

	// ReadTimeout/WriteTimeout bound a single connection's I/O.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// MaxConns caps concurrent connections.
	MaxConns int
}

// Server accepts enrollment connections.
type Server struct {
	svc          *enroll.Service
	tlsConfig    *tls.Config
	log          *slog.Logger
	readTimeout  time.Duration
	writeTimeout time.Duration
	connSem      chan struct{}

	wg sync.WaitGroup
}

// New builds a Server from Config.
func New(cfg Config) (*Server, error) {
	if cfg.Service == nil {
		return nil, errors.New("nil enrollment service")
	}
	if cfg.TLSConfig == nil {
		return nil, errors.New("nil TLS config")
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	readTimeout := cfg.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = defaultReadTimeout
	}
	writeTimeout := cfg.WriteTimeout
	if writeTimeout <= 0 {
		writeTimeout = defaultWriteTimeout
	}
	maxConns := cfg.MaxConns
	if maxConns <= 0 {
		maxConns = defaultMaxConns
	}
	return &Server{
		svc:          cfg.Service,
		tlsConfig:    cfg.TLSConfig,
		log:          log,
		readTimeout:  readTimeout,
		writeTimeout: writeTimeout,
		connSem:      make(chan struct{}, maxConns),
	}, nil
}

// Serve accepts connections until the listener is closed.
// Listener is wrapped in TLS using the configured certificate.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	tlsLn := tls.NewListener(ln, s.tlsConfig)

	go func() {
		<-ctx.Done()
		_ = tlsLn.Close()
	}()

	for {
		conn, err := tlsLn.Accept()
		if err != nil {
			if ctx.Err() != nil {
				s.wg.Wait()
				return nil
			}
			return err
		}

		select {
		case s.connSem <- struct{}{}:
		default:
			// at capacity: shed load rather than queue unboundedly
			_ = conn.Close()
			continue
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.connSem }()
			s.handle(conn)
		}()
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()

	begin, err := s.readBegin(conn)
	if err != nil {
		s.log.Warn("enroll begin read failed", "remote", remote, "error", err)
		return
	}

	challenge, err := s.svc.Begin(begin.EKCertDER, begin.AIKPublic)
	if err != nil {
		status := beginStatus(err)
		s.log.Warn("enroll begin rejected", "remote", remote, "status", status, "error", err)
		if werr := s.writeChallenge(conn, &wire.ChallengeReply{Status: status}); werr != nil {
			s.log.Debug("failed to write begin rejection", "remote", remote, "error", werr)
		}
		return
	}

	if err := s.writeChallenge(conn, &wire.ChallengeReply{
		Status:          wire.StatusOK,
		SessionID:       challenge.SessionID,
		CredentialBlob:  challenge.CredentialBlob,
		EncryptedSecret: challenge.EncryptedSecret,
	}); err != nil {
		s.log.Warn("enroll challenge write failed", "remote", remote, "error", err)
		return
	}

	complete, err := s.readComplete(conn)
	if err != nil {
		s.log.Warn("enroll complete read failed", "remote", remote, "error", err)
		return
	}

	certDER, deviceID, err := s.svc.Complete(complete.SessionID, complete.Secret)
	if err != nil {
		status := completeStatus(err)
		s.log.Warn("enroll complete rejected", "remote", remote, "status", status, "error", err)
		if werr := s.writeResult(conn, &wire.ResultReply{Status: status}); werr != nil {
			s.log.Debug("failed to write complete rejection", "remote", remote, "error", werr)
		}
		return
	}

	s.log.Info("enroll issued AIK certificate", "remote", remote, "device_id", deviceID)
	if werr := s.writeResult(conn, &wire.ResultReply{
		Status:     wire.StatusOK,
		AIKCertDER: certDER,
		DeviceID:   deviceID,
	}); werr != nil {
		s.log.Debug("failed to write enrollment result", "remote", remote, "error", werr)
	}
}

func (s *Server) readBegin(conn net.Conn) (*wire.BeginRequest, error) {
	if err := conn.SetReadDeadline(time.Now().Add(s.readTimeout)); err != nil {
		return nil, err
	}
	body, err := wire.ReadFrame(conn)
	if err != nil {
		return nil, err
	}
	return wire.DecodeBegin(body)
}

func (s *Server) readComplete(conn net.Conn) (*wire.CompleteRequest, error) {
	if err := conn.SetReadDeadline(time.Now().Add(s.readTimeout)); err != nil {
		return nil, err
	}
	body, err := wire.ReadFrame(conn)
	if err != nil {
		return nil, err
	}
	return wire.DecodeComplete(body)
}

func (s *Server) writeChallenge(conn net.Conn, r *wire.ChallengeReply) error {
	body, err := wire.EncodeChallenge(r)
	if err != nil {
		return err
	}
	return s.writeFrame(conn, body)
}

func (s *Server) writeResult(conn net.Conn, r *wire.ResultReply) error {
	body, err := wire.EncodeResult(r)
	if err != nil {
		return err
	}
	return s.writeFrame(conn, body)
}

func (s *Server) writeFrame(conn net.Conn, body []byte) error {
	if err := conn.SetWriteDeadline(time.Now().Add(s.writeTimeout)); err != nil {
		return err
	}
	return wire.WriteFrame(conn, body)
}

func beginStatus(err error) uint16 {
	switch {
	case errors.Is(err, ca.ErrEKChain), errors.Is(err, ca.ErrEKExpired),
		errors.Is(err, ca.ErrEKNotYet), errors.Is(err, ca.ErrEKMissingOID),
		errors.Is(err, ca.ErrEKParse), errors.Is(err, ca.ErrEKKeyType),
		errors.Is(err, ca.ErrEKKeySize), errors.Is(err, enroll.ErrEKKeyType):
		return wire.StatusEKRejected
	case errors.Is(err, credential.ErrAIKDecode), errors.Is(err, credential.ErrAIKTemplate),
		errors.Is(err, credential.ErrAIKName), errors.Is(err, enroll.ErrAIKKeyType):
		return wire.StatusAIKRejected
	case errors.Is(err, enroll.ErrTooManyPending):
		return wire.StatusRateLimited
	default:
		return wire.StatusInternalError
	}
}

func completeStatus(err error) uint16 {
	switch {
	case errors.Is(err, enroll.ErrUnknownSession), errors.Is(err, enroll.ErrSessionExpired):
		return wire.StatusUnknownSession
	case errors.Is(err, enroll.ErrActivationMismatch):
		return wire.StatusActivationFail
	default:
		return wire.StatusInternalError
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
