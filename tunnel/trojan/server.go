package trojan

import (
	"context"
	"fmt"
	"github.com/Potterli20/trojan-go-fork/api"
	"github.com/Potterli20/trojan-go-fork/common"
	"github.com/Potterli20/trojan-go-fork/config"
	"github.com/Potterli20/trojan-go-fork/log"
	"github.com/Potterli20/trojan-go-fork/recorder"
	"github.com/Potterli20/trojan-go-fork/redirector"
	"github.com/Potterli20/trojan-go-fork/statistic"
	"github.com/Potterli20/trojan-go-fork/statistic/memory"
	"github.com/Potterli20/trojan-go-fork/statistic/mysql"
	"github.com/Potterli20/trojan-go-fork/tunnel"
	"github.com/Potterli20/trojan-go-fork/tunnel/mux"
	"github.com/Potterli20/trojan-go-fork/tunnel/websocket"
	"io"
	"net"
	"strings"
	"sync/atomic"
)

var Auth statistic.Authenticator

// InboundConn is a trojan inbound connection
type InboundConn struct {
	// WARNING: do not change the order of these fields.
	// 64-bit fields that use `sync/atomic` package functions
	// must be 64-bit aligned on 32-bit systems.
	// Reference: https://github.com/golang/go/issues/599
	// Solution: https://github.com/golang/go/issues/11891#issuecomment-433623786
	sent uint64
	recv uint64

	net.Conn
	auth     statistic.Authenticator
	user     statistic.User
	hash     string
	metadata *tunnel.Metadata
	ip       string
	ipX      string
	password string
}

func (c *InboundConn) Metadata() *tunnel.Metadata {
	return c.metadata
}

func (c *InboundConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	atomic.AddUint64(&c.sent, uint64(n))
	c.user.AddSentTraffic(n)
	return n, err
}

func (c *InboundConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	atomic.AddUint64(&c.recv, uint64(n))
	c.user.AddRecvTraffic(n)
	return n, err
}

func (c *InboundConn) Close() error {
	log.Debug("Closing connection for user", c.hash, "KeyShare", c.password, "RealIP", c.ipX, "from", c.Conn.RemoteAddr(), "tunneling to", c.metadata.Address,
		"sent:", common.HumanFriendlyTraffic(atomic.LoadUint64(&c.sent)), "recv:", common.HumanFriendlyTraffic(atomic.LoadUint64(&c.recv)))
	return c.Conn.Close()
}

func GetRealIP(c *InboundConn) string {
	switch conn := c.Conn.(type) {
	case *websocket.InboundConn:
		for name, value := range conn.OutboundConn.Request().Header {
			if name == "X-Forwarded-For" {
				ips := strings.Split(value[0], ",")
				return ips[0]
			}
			if name == "CF-Connecting-IP" {
				return value[0]
			}
		}
	case *common.RewindConn:
		if wsConn, ok := conn.Conn.(*websocket.InboundConn); ok {
			for name, value := range wsConn.OutboundConn.Request().Header {
				if name == "X-Forwarded-For" {
					ips := strings.Split(value[0], ",")
					return ips[0]
				}
				if name == "CF-Connecting-IP" {
					return value[0]
				}
			}
		}
	default:
		log.Debug("Failed to convert to WebSocket or RewindConn")
	}
	return c.ip
}

func (c *InboundConn) Auth() error {
	userHash := [56]byte{}
	n, err := c.Conn.Read(userHash[:])
	if err != nil || n != 56 {
		return common.NewError("failed to read hash").Base(err)
	}

	valid, user := c.auth.AuthUser(string(userHash[:]))
	if !valid {
		return common.NewError("invalid hash:" + string(userHash[:]))
	}
	c.hash = string(userHash[:])
	c.user = user

	ip, _, err := net.SplitHostPort(c.Conn.RemoteAddr().String())
	if err != nil {
		return common.NewError("failed to parse host:" + c.Conn.RemoteAddr().String()).Base(err)
	}
	c.ip = ip
	RealIP := GetRealIP(c)
	c.ipX = RealIP
	ok := user.AddIP(RealIP)
	if !ok {
		return common.NewError("ip limit reached, UserPassword: " + user.GetKeyShare() + " UserHash: " + c.hash + " RealIP: " + RealIP)
	}

	crlf := [2]byte{}
	_, err = io.ReadFull(c.Conn, crlf[:])
	if err != nil {
		return err
	}

	c.metadata = &tunnel.Metadata{}
	if err := c.metadata.ReadFrom(c.Conn); err != nil {
		return err
	}

	_, err = io.ReadFull(c.Conn, crlf[:])
	if err != nil {
		return err
	}
	return nil
}

func (c *InboundConn) Record() {
	log.Debug("user", c.hash, "from", c.Conn.RemoteAddr(), "tunneling to", c.metadata.Address)
	recorder.Add(c.hash, c.Conn.RemoteAddr(), c.metadata.Address, "TCP", nil)
}

func (c *InboundConn) Hash() string {
	return c.hash
}

// Server is a trojan tunnel server
type Server struct {
	auth       statistic.Authenticator
	redir      *redirector.Redirector
	redirAddr  *tunnel.Address
	underlay   tunnel.Server
	connChan   chan tunnel.Conn
	muxChan    chan tunnel.Conn
	packetChan chan tunnel.PacketConn
	ctx        context.Context
	cancel     context.CancelFunc
}

func (s *Server) Close() error {
	s.cancel()
	return s.underlay.Close()
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.underlay.AcceptConn(&Tunnel{})
		if err != nil { // Closing
			log.Error(common.NewError("trojan failed to accept conn").Base(err))
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			continue
		}
		go func(conn tunnel.Conn) {
			rewindConn := common.NewRewindConn(conn)
			rewindConn.SetBufferSize(128)
			defer rewindConn.StopBuffering()

			inboundConn := &InboundConn{
				Conn: rewindConn,
				auth: s.auth,
			}

			if err := inboundConn.Auth(); err != nil {
				rewindConn.Rewind()
				rewindConn.StopBuffering()
				log.Warn(common.NewError("connection with invalid trojan header from " + rewindConn.RemoteAddr().String()).Base(err))
				s.redir.Redirect(&redirector.Redirection{
					RedirectTo:  s.redirAddr,
					InboundConn: rewindConn,
				})
				return
			}

			rewindConn.StopBuffering()
			switch inboundConn.metadata.Command {
			case Connect:
				if inboundConn.metadata.DomainName == "MUX_CONN" {
					s.muxChan <- inboundConn
					log.Debug("mux(r) connection")
				} else {
					s.connChan <- inboundConn
					log.Debug("normal trojan connection")
					inboundConn.Record()
				}

			case Associate:
				s.packetChan <- &PacketConn{
					Conn: inboundConn,
				}
				log.Debug("trojan udp connection")
			case Mux:
				s.muxChan <- inboundConn
				log.Debug("mux connection")
			default:
				log.Error(common.NewError(fmt.Sprintf("unknown trojan command %d", inboundConn.metadata.Command)))
			}
		}(conn)
	}
}

func (s *Server) AcceptConn(nextTunnel tunnel.Tunnel) (tunnel.Conn, error) {
	switch nextTunnel.(type) {
	case *mux.Tunnel:
		select {
		case t := <-s.muxChan:
			return t, nil
		case <-s.ctx.Done():
			return nil, common.NewError("trojan client closed")
		}
	default:
		select {
		case t := <-s.connChan:
			return t, nil
		case <-s.ctx.Done():
			return nil, common.NewError("trojan client closed")
		}
	}
}

func (s *Server) AcceptPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	select {
	case t := <-s.packetChan:
		return t, nil
	case <-s.ctx.Done():
		return nil, common.NewError("trojan client closed")
	}
}

func NewServer(ctx context.Context, underlay tunnel.Server) (*Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	ctx, cancel := context.WithCancel(ctx)

	if Auth == nil {
		var err error
		if cfg.MySQL.Enabled {
			log.Debug("mysql enabled")
			Auth, err = statistic.NewAuthenticator(ctx, mysql.Name)
		} else {
			log.Debug("auth by config file")
			Auth, err = statistic.NewAuthenticator(ctx, memory.Name)
		}
		if err != nil {
			cancel()
			return nil, common.NewError("trojan failed to create authenticator")
		}
	}

	if cfg.API.Enabled {
		go api.RunService(ctx, Name+"_SERVER", Auth)
	}

	recorder.Capacity = cfg.RecordCapacity

	redirAddr := tunnel.NewAddressFromHostPort("tcp", cfg.RemoteHost, cfg.RemotePort)
	s := &Server{
		underlay:   underlay,
		auth:       Auth,
		redirAddr:  redirAddr,
		connChan:   make(chan tunnel.Conn, 64),       // 增加连接池大小
		muxChan:    make(chan tunnel.Conn, 64),       // 增加连接池大小
		packetChan: make(chan tunnel.PacketConn, 64), // 增加连接池大小
		ctx:        ctx,
		cancel:     cancel,
		redir:      redirector.NewRedirector(ctx),
	}

	if !cfg.DisableHTTPCheck {
		redirConn, err := net.Dial("tcp", redirAddr.String())
		if err != nil {
			cancel()
			return nil, common.NewError("invalid redirect address. check your http server: " + redirAddr.String()).Base(err)
		}
		redirConn.Close()
	}

	go s.acceptLoop()
	log.Debug("trojan server created")
	return s, nil
}
