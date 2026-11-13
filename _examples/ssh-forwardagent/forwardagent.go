package main

import (
	"fmt"
	"log"
	"os/exec"

	"github.com/gliderlabs/ssh"
)

func main() {
	forwardingHandler := func(s ssh.Session) {
		cmd := exec.Command("ssh-add", "-l")
		if ssh.AgentRequested(s) {
			l, err := ssh.NewAgentListener()
			if err != nil {
				log.Fatal(err)
			}
			defer l.Close()
			go ssh.ForwardAgentConnections(l, s)
			cmd.Env = append(s.Environ(), fmt.Sprintf("%s=%s", "SSH_AUTH_SOCK", l.Addr().String()))
		} else {
			cmd.Env = s.Environ()
		}
		cmd.Stdout = s
		cmd.Stderr = s.Stderr()
		if err := cmd.Run(); err != nil {
			log.Println(err)
			return
		}
	}

	log.Println("starting ssh server on port 2222...")
	srv := &ssh.Server{
		Addr:    ":2222",
		Handler: forwardingHandler,
		// Agent forwarding is denied unless the callback explicitly opts in
		// the connection.
		AgentForwardingCallback: func(ctx ssh.Context) bool {
			return true
		},
	}
	log.Fatal(srv.ListenAndServe())
}
