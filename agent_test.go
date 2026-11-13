package ssh

import (
	"errors"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func newAgentTestClient(t *testing.T, srv *Server) (*gossh.Client, func()) {
	t.Helper()
	l := newLocalListener()
	go func() {
		if err := srv.Serve(l); err != nil && err != ErrServerClosed {
			t.Errorf("server error: %v", err)
		}
	}()
	client, err := gossh.Dial("tcp", l.Addr().String(), &gossh.ClientConfig{
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return client, func() {
		client.Close()
		srv.Close()
	}
}

func TestAgentForwardingDeniedByDefault(t *testing.T) {
	t.Parallel()

	srv := &Server{Handler: func(s Session) {}}
	client, cleanup := newAgentTestClient(t, srv)
	defer cleanup()

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	if err := agent.RequestAgentForwarding(session); err == nil {
		t.Fatal("agent forwarding request should be denied without a callback")
	}

	if _, _, err := client.OpenChannel(agentChannelType, nil); err == nil {
		t.Fatal("agent channel should be rejected without an authorized session")
	}
}

func TestAgentForwardingCallbackAllowsRequest(t *testing.T) {
	t.Parallel()

	srv := &Server{
		Handler: func(s Session) {
			if !AgentRequested(s) {
				t.Error("AgentRequested should be true after an authorized request")
			}
		},
		AgentForwardingCallback: func(ctx Context) bool {
			return true
		},
	}
	client, cleanup := newAgentTestClient(t, srv)
	defer cleanup()

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	if err := agent.RequestAgentForwarding(session); err != nil {
		t.Fatalf("agent forwarding request should be allowed: %v", err)
	}
	if err := session.Run(""); err != nil {
		t.Fatal(err)
	}
}

func TestAgentForwardingCallbackCanDeny(t *testing.T) {
	t.Parallel()

	srv := &Server{
		Handler:                 func(s Session) {},
		AgentForwardingCallback: func(ctx Context) bool { return false },
	}
	client, cleanup := newAgentTestClient(t, srv)
	defer cleanup()

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	if err := agent.RequestAgentForwarding(session); err == nil {
		t.Fatal("agent forwarding request should be denied when the callback returns false")
	}
}

func TestAgentChannelOnlyOpensForAuthorizedSession(t *testing.T) {
	t.Parallel()

	srv := &Server{
		Handler: func(s Session) {
			if AgentRequested(s) {
				l, err := NewAgentListener()
				if err != nil {
					t.Error(err)
					return
				}
				defer l.Close()
				go ForwardAgentConnections(l, s)
			}
		},
		AgentForwardingCallback: func(ctx Context) bool {
			return true
		},
	}
	client, cleanup := newAgentTestClient(t, srv)
	defer cleanup()

	if _, _, err := client.OpenChannel(agentChannelType, nil); err == nil {
		t.Fatal("agent channel should be rejected before agent forwarding was requested")
	} else {
		var reason *gossh.OpenChannelError
		if !errors.As(err, &reason) {
			t.Fatalf("expected *gossh.OpenChannelError, got %T: %v", err, err)
		}
		if reason.Reason != gossh.Prohibited {
			t.Fatalf("expected Prohibited rejection, got %v", reason.Reason)
		}
		if !strings.Contains(reason.Message, "agent forwarding is disabled") {
			t.Fatalf("expected agent forwarding message, got %q", reason.Message)
		}
	}

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := agent.RequestAgentForwarding(session); err != nil {
		t.Fatalf("agent forwarding request should be allowed: %v", err)
	}

	opened := make(chan error, 1)
	go func() {
		_, _, err := client.OpenChannel(agentChannelType, nil)
		opened <- err
	}()

	if err := session.Run(""); err != nil {
		t.Fatal(err)
	}
	if err := <-opened; err != nil {
		t.Fatalf("agent channel should open for the authorized session: %v", err)
	}
}

func TestAgentChannelHandlerIsRegisteredByDefault(t *testing.T) {
	t.Parallel()

	srv := &Server{}
	srv.ensureHandlers()
	if _, ok := srv.ChannelHandlers[agentChannelType]; !ok {
		t.Fatal("auth-agent channel handler should be registered by default")
	}
	if srv.ChannelHandlers["session"] == nil {
		t.Fatal("session channel handler must remain registered")
	}
}
