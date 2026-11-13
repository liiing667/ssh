package ssh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

func TestAddHostKey(t *testing.T) {
	s := Server{}
	signer, err := generateSigner()
	if err != nil {
		t.Fatal(err)
	}
	s.AddHostKey(signer)
	if len(s.HostSigners) != 1 {
		t.Fatal("Key was not properly added")
	}
	signer, err = generateSigner()
	if err != nil {
		t.Fatal(err)
	}
	s.AddHostKey(signer)
	if len(s.HostSigners) != 1 {
		t.Fatal("Key was not properly replaced")
	}
}

func TestServerShutdown(t *testing.T) {
	l := newLocalListener()
	testBytes := []byte("Hello world\n")
	s := &Server{
		Handler: func(s Session) {
			s.Write(testBytes)
			time.Sleep(50 * time.Millisecond)
		},
	}
	go func() {
		err := s.Serve(l)
		if err != nil && err != ErrServerClosed {
			t.Fatal(err)
		}
	}()
	sessDone := make(chan struct{})
	sess, _, cleanup := newClientSession(t, l.Addr().String(), nil)
	go func() {
		defer cleanup()
		defer close(sessDone)
		var stdout bytes.Buffer
		sess.Stdout = &stdout
		if err := sess.Run(""); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(stdout.Bytes(), testBytes) {
			t.Fatalf("expected = %s; got %s", testBytes, stdout.Bytes())
		}
	}()

	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		err := s.Shutdown(context.Background())
		if err != nil {
			t.Fatal(err)
		}
	}()

	timeout := time.After(2 * time.Second)
	select {
	case <-timeout:
		t.Fatal("timeout")
		return
	case <-srvDone:
		// TODO: add timeout for sessDone
		<-sessDone
		return
	}
}

func TestServerClose(t *testing.T) {
	l := newLocalListener()
	s := &Server{
		Handler: func(s Session) {
			time.Sleep(5 * time.Second)
		},
	}
	go func() {
		err := s.Serve(l)
		if err != nil && err != ErrServerClosed {
			t.Fatal(err)
		}
	}()

	clientDoneChan := make(chan struct{})
	closeDoneChan := make(chan struct{})

	sess, _, cleanup := newClientSession(t, l.Addr().String(), nil)
	go func() {
		defer cleanup()
		defer close(clientDoneChan)
		<-closeDoneChan
		if err := sess.Run(""); err != nil && err != io.EOF {
			t.Fatal(err)
		}
	}()

	go func() {
		err := s.Close()
		if err != nil {
			t.Fatal(err)
		}
		close(closeDoneChan)
	}()

	timeout := time.After(100 * time.Millisecond)
	select {
	case <-timeout:
		t.Error("timeout")
		return
	case <-s.getDoneChan():
		<-clientDoneChan
		return
	}
}

func TestServerHandshakeTimeout(t *testing.T) {
	l := newLocalListener()

	s := &Server{
		HandshakeTimeout: time.Millisecond,
	}
	go func() {
		if err := s.Serve(l); err != nil {
			t.Error(err)
		}
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ch := make(chan struct{})
	go func() {
		defer close(ch)
		io.Copy(io.Discard, conn)
	}()

	select {
	case <-ch:
		return
	case <-time.After(time.Second):
		t.Fatal("client connection was not force-closed")
		return
	}
}

func TestServerConfigCallbackNoClientAuth(t *testing.T) {
	t.Parallel()

	newAuthConfigServer := func(config *gossh.ServerConfig) (*Server, net.Listener) {
		l := newLocalListener()
		s := &Server{
			Handler: func(s Session) {},
			ServerConfigCallback: func(ctx Context) *gossh.ServerConfig {
				return config
			},
		}
		go func() {
			s.Serve(l)
		}()
		return s, l
	}

	dial := func(addr string, auth []gossh.AuthMethod) error {
		client, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{
			User:            "testuser",
			Auth:            auth,
			HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		})
		if err != nil {
			return err
		}
		client.Close()
		return nil
	}

	t.Run("PasswordCallbackRejectsNoneAuth", func(t *testing.T) {
		t.Parallel()
		s, l := newAuthConfigServer(&gossh.ServerConfig{
			PasswordCallback: func(conn gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
				if string(password) == "testpass" {
					return nil, nil
				}
				return nil, fmt.Errorf("permission denied")
			},
		})
		defer s.Close()

		if err := dial(l.Addr().String(), nil); err == nil {
			t.Fatal("expected none auth to be rejected")
		} else if !strings.Contains(err.Error(), "unable to authenticate") {
			t.Fatal(err)
		}
		if err := dial(l.Addr().String(), []gossh.AuthMethod{gossh.Password("badpass")}); err == nil {
			t.Fatal("expected bad password to be rejected")
		}
		if err := dial(l.Addr().String(), []gossh.AuthMethod{gossh.Password("testpass")}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("PublicKeyCallbackRejectsNoneAuth", func(t *testing.T) {
		t.Parallel()
		signer, err := generateSigner()
		if err != nil {
			t.Fatal(err)
		}
		s, l := newAuthConfigServer(&gossh.ServerConfig{
			PublicKeyCallback: func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
				if KeysEqual(key, signer.PublicKey()) {
					return nil, nil
				}
				return nil, fmt.Errorf("permission denied")
			},
		})
		defer s.Close()

		if err := dial(l.Addr().String(), nil); err == nil {
			t.Fatal("expected none auth to be rejected")
		} else if !strings.Contains(err.Error(), "unable to authenticate") {
			t.Fatal(err)
		}
		if err := dial(l.Addr().String(), []gossh.AuthMethod{gossh.PublicKeys(signer)}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("ZeroValueServerAllowsNoneAuth", func(t *testing.T) {
		t.Parallel()
		l := newLocalListener()
		s := &Server{
			Handler: func(s Session) {},
		}
		go func() {
			s.Serve(l)
		}()
		defer s.Close()

		if err := dial(l.Addr().String(), nil); err != nil {
			t.Fatal(err)
		}
	})
}
