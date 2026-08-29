package admin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"bastionctl/internal/config"
	"bastionctl/internal/report"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestRunThroughEmbeddedSSHTransport(t *testing.T) {
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, userPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userSigner, err := ssh.NewSignerFromKey(userPrivate)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverConfig := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if string(key.Marshal()) != string(userSigner.PublicKey().Marshal()) {
			return nil, ssh.ErrNoAuth
		}
		return nil, nil
	}}
	serverConfig.AddHostKey(hostSigner)
	serverDone := make(chan error, 1)
	go serveEmbeddedTransportTest(listener, serverConfig, serverDone)

	directory := t.TempDir()
	block, err := ssh.MarshalPrivateKey(userPrivate, "embedded-test")
	if err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(directory, "id_ed25519")
	if err := os.WriteFile(identity, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	knownHosts := filepath.Join(directory, "known_hosts")
	line := knownhosts.Line([]string{knownhosts.Normalize(listener.Addr().String())}, hostSigner.PublicKey()) + "\n"
	if err := os.WriteFile(knownHosts, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	r := Run(context.Background(), config.Defaults().Admin, "test", Options{
		Action: "audit", Target: "ops@127.0.0.1", Port: port, Identity: identity,
		KnownHostsFile: knownHosts, Embedded: true,
	})
	if r.HasFailures() || len(r.Results) != 1 || r.Results[0].Status != report.Pass {
		t.Fatalf("embedded report failed: %+v", r)
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("test SSH server did not finish")
	}
}

func serveEmbeddedTransportTest(listener net.Listener, config *ssh.ServerConfig, done chan<- error) {
	connection, err := listener.Accept()
	if err != nil {
		done <- err
		return
	}
	defer connection.Close()
	_, channels, requests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		done <- err
		return
	}
	go ssh.DiscardRequests(requests)
	for request := range channels {
		if request.ChannelType() != "session" {
			request.Reject(ssh.UnknownChannelType, "session required")
			continue
		}
		channel, incoming, err := request.Accept()
		if err != nil {
			done <- err
			return
		}
		for message := range incoming {
			if message.Type != "exec" || len(message.Payload) < 4 {
				message.Reply(false, nil)
				continue
			}
			length := int(binary.BigEndian.Uint32(message.Payload[:4]))
			if length < 1 || length != len(message.Payload)-4 {
				message.Reply(false, nil)
				continue
			}
			message.Reply(true, nil)
			_, _ = channel.Write([]byte(`{"schema":"bastionctl.report.v1","tool_version":"test","mode":"server","action":"audit","started_at":"2026-01-01T00:00:00Z","finished_at":"2026-01-01T00:00:01Z","summary":{"pass":1,"fail":0,"warn":0,"info":0,"planned":0,"changed":0,"skipped":0},"results":[{"control":"embedded-ssh","status":"pass","message":"ok"}]}` + "\n"))
			_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			channel.Close()
			break
		}
		break
	}
	done <- nil
}
