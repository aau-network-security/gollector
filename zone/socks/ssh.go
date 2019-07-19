package socks

import (
	"fmt"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"strconv"
	"strings"
)

//func PrivateKeyFile(path string) (ssh.AuthMethod, error) {
//	buffer, err := ioutil.ReadFile(path)
//	if err != nil {
//		return nil, err
//	}
//	key, err := ssh.ParsePrivateKey(buffer)
//	if err != nil {
//		return nil, err
//	}
//	return ssh.PublicKeys(key), nil
//}
//
//func sshClient(conf SSH, auth ssh.AuthMethod) (*ssh.Client, error) {
//	if auth == nil {
//		var err error
//		auth, err = privateKeyAuth(conf.Key)
//		if err != nil {
//			return nil, err
//		}
//	}
//	sshConf := ssh.ClientConfig{
//		User: conf.User,
//		Auth: []ssh.AuthMethod{
//			auth,
//		},
//		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
//			return nil
//		},
//	}
//	host := fmt.Sprintf("%s:22", conf.Host)
//	return ssh.Dial("tcp", host, &sshConf)
//}

type Endpoint struct {
	Host string
	Port int
	User string
}

func NewEndpoint(s string) *Endpoint {
	endpoint := &Endpoint{
		Host: s,
	}
	if parts := strings.Split(endpoint.Host, "@"); len(parts) > 1 {
		endpoint.User = parts[0]
		endpoint.Host = parts[1]
	}
	if parts := strings.Split(endpoint.Host, ":"); len(parts) > 1 {
		endpoint.Host = parts[0]
		endpoint.Port, _ = strconv.Atoi(parts[1])
	}
	return endpoint
}

func (endpoint *Endpoint) String() string {
	return fmt.Sprintf("%s:%d", endpoint.Host, endpoint.Port)
}

type SSHTunnel struct {
	Local  *Endpoint
	Server *Endpoint
	Remote *Endpoint
	Config *ssh.ClientConfig
}

func (tunnel *SSHTunnel) Start() error {
	listener, err := net.Listen("tcp", tunnel.Local.String())
	if err != nil {
		return err
	}
	defer listener.Close()
	tunnel.Local.Port = listener.Addr().(*net.TCPAddr).Port
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		log.Debug().Msgf("accepted connection")
		go func() {
			if err := tunnel.forward(conn); err != nil {
				log.Debug().Msgf("error while forwarding traffic over ssh tunnel: %s", err)
			}
		}()
	}
}

func (tunnel *SSHTunnel) forward(localConn net.Conn) error {
	serverConn, err := ssh.Dial("tcp", tunnel.Server.String(), tunnel.Config)
	if err != nil {
		return err
	}
	log.Debug().Msgf("connected to %s (1 of 2)", tunnel.Server.String())
	remoteConn, err := serverConn.Dial("tcp", tunnel.Remote.String())
	if err != nil {
		return err
	}
	log.Debug().Msgf("connected to %s (2 of 2)", tunnel.Remote.String())
	copyConn := func(writer, reader net.Conn) {
		_, err := io.Copy(writer, reader)
		if err != nil {
			log.Debug().Msgf("io.Copy error: %s", err)
		}
	}
	go copyConn(localConn, remoteConn)
	go copyConn(remoteConn, localConn)
	return nil
}

func NewSSHTunnel(tunnel string, auth ssh.AuthMethod, destination string) *SSHTunnel {
	// A random port will be chosen for us.
	localEndpoint := NewEndpoint("127.0.0.1:4182")
	server := NewEndpoint(tunnel)
	if server.Port == 0 {
		server.Port = 22
	}
	sshTunnel := &SSHTunnel{
		Config: &ssh.ClientConfig{
			User: server.User,
			Auth: []ssh.AuthMethod{auth},
			HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
				// Always accept key.
				return nil
			},
		},
		Local:  localEndpoint,
		Server: server,
		Remote: NewEndpoint(destination),
	}
	return sshTunnel
}
