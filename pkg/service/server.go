package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/livekit/livekit-server/pkg/config"
	"github.com/livekit/livekit-server/pkg/routing"
	"github.com/livekit/livekit-server/version"
	"github.com/livekit/protocol/auth"
	"github.com/livekit/protocol/livekit"
	"github.com/livekit/protocol/logger"
	"github.com/pion/turn/v2"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
	"github.com/urfave/negroni"
	"go.uber.org/atomic"
	"golang.org/x/sync/errgroup"
	"net"
	"net/http"
	_ "net/http/pprof"
	"runtime/pprof"
	"sync"
	"time"
)

type LivekitServer struct {
	Config        *config.Config
	egressService *EgressService
	rtcService    *RTCService
	httpServer    *http.Server
	promServer    *http.Server
	router        routing.Router
	roomManager   *RoomManager
	turnServer    *turn.Server
	currentNode   routing.LocalNode
	running       atomic.Bool
	doneChan      chan struct{}
	closedChan    chan struct{}
}

func NewLivekitServer(conf *config.Config,
	roomService livekit.RoomService,
	egressService *EgressService,
	rtcService *RTCService,
	keyProvider auth.KeyProvider,
	router routing.Router,
	roomManager *RoomManager,
	turnServer *turn.Server,
	currentNode routing.LocalNode,
) (s *LivekitServer, err error) {
	s = &LivekitServer{
		Config:        conf,
		egressService: egressService,
		rtcService:    rtcService,
		router:        router,
		roomManager:   roomManager,
		// turn server starts automatically
		turnServer:  turnServer,
		currentNode: currentNode,
		closedChan:  make(chan struct{}),
	}

	middlewares := []negroni.Handler{
		// always first
		negroni.NewRecovery(),
		// CORS is allowed, we rely on token authentication to prevent improper use
		cors.New(cors.Options{
			AllowOriginFunc: func(origin string) bool {
				return true
			},
			AllowedHeaders: []string{"*"},
		}),
	}
	if keyProvider != nil {
		middlewares = append(middlewares, NewAPIKeyAuthMiddleware(keyProvider))
	}

	roomServer := livekit.NewRoomServiceServer(roomService)
	egressServer := livekit.NewEgressServer(egressService)

	mux := http.NewServeMux()
	if conf.Development {
		// pprof handlers are registered onto DefaultServeMux
		mux = http.DefaultServeMux
		mux.HandleFunc("/debug/goroutine", s.debugGoroutines)
		mux.HandleFunc("/debug/rooms", s.debugInfo)
	}
	mux.Handle(roomServer.PathPrefix(), roomServer)
	mux.Handle(egressServer.PathPrefix(), egressServer)
	mux.Handle("/rtc", rtcService)
	mux.HandleFunc("/rtc/validate", rtcService.Validate)
	mux.HandleFunc("/", s.healthCheck)

	s.httpServer = &http.Server{
		Handler: configureMiddlewares(mux, middlewares...),
	}

	if conf.PrometheusPort > 0 {
		s.promServer = &http.Server{
			Handler: promhttp.Handler(),
		}
	}

	// clean up old rooms on startup
	if err = roomManager.CleanupRooms(); err != nil {
		return
	}
	if err = router.RemoveDeadNodes(); err != nil {
		return
	}

	return
}

func (s *LivekitServer) Node() *livekit.Node {
	return s.currentNode
}

func (s *LivekitServer) HTTPPort() int {
	return int(s.Config.Port)
}

func (s *LivekitServer) IsRunning() bool {
	return s.running.Load()
}

func (s *LivekitServer) Start() error {
	if s.running.Load() {
		return errors.New("already running")
	}
	s.doneChan = make(chan struct{})
	if err := s.router.RegisterNode(); err != nil {
		return err
	}
	defer func() {
		if err := s.router.UnregisterNode(); err != nil {
			logger.Errorw("could not unregister node", err)
		}
	}()
	if err := s.router.Start(); err != nil {
		return err
	}

	if err := s.egressService.Start(); err != nil {
		return err
	}
	addresses := s.Config.BindAddresses
	if addresses == nil {
		addresses = []string{""}
	}

	// ensure we could listen
	listeners := make([]net.Listener, 0)
	promListeners := make([]net.Listener, 0)
	for _, addr := range addresses {
		ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", addr, s.Config.Port))
		if err != nil {
			return err
		}
		listeners = append(listeners, ln)

		if s.promServer != nil {
			ln, err = net.Listen("tcp", fmt.Sprintf("%s:%d", addr, s.Config.PrometheusPort))
			if err != nil {
				return err
			}
			promListeners = append(promListeners, ln)
		}
	}
	values := []interface{}{
		"portHttp", s.Config.Port,
		"nodeID", s.currentNode.Id,
		"nodeIP", s.currentNode.Ip,
		"version", version.Version,
	}
	if s.Config.BindAddresses != nil {
		values = append(values, "bindAddresses", s.Config.BindAddresses)
	}
	if s.Config.RTC.TCPPort != 0 {
		values = append(values, "rtc.portTCP", s.Config.RTC.TCPPort)
	}
	if !s.Config.RTC.ForceTCP && s.Config.RTC.UDPPort != 0 {
		values = append(values, "rtc.portUDP", s.Config.RTC.UDPPort)
	} else {
		values = append(values,
			"rtc.portICERange", []uint32{s.Config.RTC.ICEPortRangeStart, s.Config.RTC.ICEPortRangeEnd},
		)
	}
	if s.Config.PrometheusPort != 0 {
		values = append(values, "portPrometheus", s.Config.PrometheusPort)
	}
	if s.Config.Region != "" {
		values = append(values, "region", s.Config.Region)
	}

	for _, promLn := range promListeners {
		go s.promServer.Serve(promLn)
	}
	httpGroup := &errgroup.Group{}
	for _, ln := range listeners {
		httpGroup.Go(func() error {
			return s.httpServer.Serve(ln)
		})
	}
	go func() {
		if err := httpGroup.Wait(); err != http.ErrServerClosed {
			logger.Errorw("could not start server", err)
			s.Stop(true)
		}
	}()
	go s.backgroundWorker()
	// give time for Serve goroutine to start
	time.Sleep(100 * time.Millisecond)
	s.running.Store(true)
	<-s.doneChan
	println("")
	println("=================================")
	logger.Infow("starting LiveKit server", values...)
	go func() {
		// wait for shutdown
		var wg sync.WaitGroup
		wg.Add(1)
		//wg.Wait()
		// wait for shutdown
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()
		_ = s.httpServer.Shutdown(ctx)
		if s.turnServer != nil {
			_ = s.turnServer.Close()
		}
		s.roomManager.Stop()
		s.egressService.Stop()
		close(s.closedChan)
		wg.Done() // 操作完成，减少一个计数
	}()
	logger.Infow("starting LiveKit server running on background", values...)
	return nil
}

func (s *LivekitServer) Stop(force bool) {
	// wait for all participants to exit
	//logger.Infow("livekit is exit, bye bye -1 !!")
	s.router.Drain()
	if s.turnServer != nil {
		go func() {
			err := s.turnServer.Close()
			if err != nil {
				fmt.Printf("关闭TURN服务失败%s\n", err)
			} else {
				fmt.Printf("关闭TURN服务\n")
			}
		}()
	}
	//logger.Infow("livekit is exit, bye bye -1.5 !!")
	partTicker := time.NewTicker(5 * time.Second)
	//logger.Infow("livekit is exit, bye bye -1.55 !!")
	waitingForParticipants := !force && s.roomManager.HasParticipants()
	//logger.Infow("livekit is exit, bye bye -1.555 !!")
	for waitingForParticipants {
		<-partTicker.C
		logger.Infow("waiting for participants to exit")
		waitingForParticipants = s.roomManager.HasParticipants()
	}
	//logger.Infow("livekit is exit, bye bye -1.56 !!")
	partTicker.Stop()

	//logger.Infow("livekit is exit, bye bye -1.565 !!")
	if !s.running.Swap(false) {
		return
	}
	//logger.Infow("livekit is exit, bye bye 0 !!")
	s.router.Stop()
	close(s.doneChan)
	//logger.Infow("livekit is exit, bye bye 1 !!")
	// wait for fully closed
	<-s.closedChan
	//logger.Infow("livekit is exit, bye bye 2 !!")
}

func (s *LivekitServer) RoomManager() *RoomManager {
	return s.roomManager
}

func (s *LivekitServer) debugGoroutines(w http.ResponseWriter, _ *http.Request) {
	_ = pprof.Lookup("goroutine").WriteTo(w, 2)
}

func (s *LivekitServer) debugInfo(w http.ResponseWriter, _ *http.Request) {
	s.roomManager.lock.RLock()
	info := make([]map[string]interface{}, 0, len(s.roomManager.rooms))
	for _, room := range s.roomManager.rooms {
		info = append(info, room.DebugInfo())
	}
	s.roomManager.lock.RUnlock()

	b, err := json.Marshal(info)
	if err != nil {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(err.Error()))
	} else {
		_, _ = w.Write(b)
	}
}

func (s *LivekitServer) healthCheck(w http.ResponseWriter, _ *http.Request) {
	var updatedAt time.Time
	if s.Node().Stats != nil {
		updatedAt = time.Unix(s.Node().Stats.UpdatedAt, 0)
	}
	if time.Since(updatedAt) > 4*time.Second {
		w.WriteHeader(http.StatusNotAcceptable)
		_, _ = w.Write([]byte(fmt.Sprintf("Not Ready\nNode Updated At %s", updatedAt)))
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

// worker to perform periodic tasks per node
func (s *LivekitServer) backgroundWorker() {
	roomTicker := time.NewTicker(30 * time.Second)
	defer roomTicker.Stop()
	for {
		select {
		case <-s.doneChan:
			return
		case <-roomTicker.C:
			s.roomManager.CloseIdleRooms()
		}
	}
}

func configureMiddlewares(handler http.Handler, middlewares ...negroni.Handler) *negroni.Negroni {
	n := negroni.New()
	for _, m := range middlewares {
		n.Use(m)
	}
	n.UseHandler(handler)
	return n
}
