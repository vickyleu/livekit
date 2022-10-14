package main

// #include <stdlib.h>
import "C"
import (
	"encoding/json"
	_ "encoding/json"
	_ "flag"
	"fmt"
	"github.com/livekit/protocol/auth"
	"github.com/livekit/protocol/utils"
	"github.com/urfave/cli/v2"
	"math/rand"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"syscall"
	"time"
	"unsafe"

	serverlogger "github.com/livekit/livekit-server/pkg/logger"
	"github.com/livekit/protocol/logger"

	"github.com/livekit/livekit-server/pkg/config"
	"github.com/livekit/livekit-server/pkg/routing"
	"github.com/livekit/livekit-server/pkg/service"
	"github.com/livekit/livekit-server/version"
)

var gServerPointer *unsafe.Pointer // 全局变量

// 通过命令行参数启动服务
//
//export startByTerminal
func startByTerminal() int {
	app := &cli.App{
		Name:                 "livekit-server",
		Usage:                "High performance WebRTC server",
		UsageText:            "livekit-server  [global options] command [command options] [arguments...]",
		Description:          "run without subcommands to start the server",
		EnableBashCompletion: false,
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "k", Usage: "api key", Value: "", Required: true},
			&cli.StringFlag{Name: "s", Usage: "api secret", Value: "", Required: true},
			&cli.IntFlag{Name: "p", Usage: "livekit server port", Value: 7891},
			&cli.IntFlag{Name: "P", Usage: "livekit rtc tcp port", Value: 7881},
			&cli.IntFlag{Name: "sp", Usage: "rtc port range start port", Value: 50000},
			&cli.IntFlag{Name: "ep", Usage: "rtc port range end port", Value: 60000},
			&cli.BoolFlag{Name: "ex", Usage: "rtc use external ip", Value: true},
			&cli.BoolFlag{Name: "u", Usage: "room enable remote unmute", Value: true},
			&cli.StringFlag{Name: "l", Usage: "logging level", Value: "info"},
			&cli.StringFlag{Name: "L", Usage: "logging level for pion", Value: "error"},
		},
		Action: func(context *cli.Context) error {
			var k = context.String("k")
			var s = context.String("s")
			var p = context.Int("p")
			var P = context.Int("P")
			var sp = context.Int("sp")
			var ep = context.Int("ep")
			var ex = context.Bool("ex")
			var u = context.Bool("u")
			var l = context.String("l")
			var L = context.String("L")
			if k == "" || s == "" {
				fmt.Println("请输入api key 和 api secret")
				return nil
			}
			_config := config.Config{
				Port:           uint32(p),
				BindAddresses:  []string{"127.0.0.1", "[::1]"},
				PrometheusPort: 0,
				RTC: config.RTCConfig{
					UDPPort:           0,
					TCPPort:           uint32(P),
					ICEPortRangeStart: uint32(sp),
					ICEPortRangeEnd:   uint32(ep),
					NodeIP:            "0.0.0.0",
					STUNServers:       nil,
					TURNServers:       nil,
					UseExternalIP:     ex,
					UseICELite:        false,
					Interfaces:        config.InterfacesConfig{},
					PacketBufferSize:  0,
					PLIThrottle:       config.PLIThrottleConfig{},
					CongestionControl: config.CongestionControlConfig{},
					ForceTCP:          false,
				},
				Redis: config.RedisConfig{},
				Audio: config.AudioConfig{},
				Video: config.VideoConfig{},
				Room: config.RoomConfig{
					AutoCreate:         true,
					EnabledCodecs:      config.CodecDef(),
					MaxParticipants:    0,
					EmptyTimeout:       300,
					EnableRemoteUnmute: u,
					MaxMetadataSize:    0,
				},
				TURN:         config.TURNConfig{},
				Ingress:      config.IngressConfig{},
				WebHook:      config.WebHookConfig{},
				NodeSelector: config.NodeSelectorConfig{},
				KeyFile:      "",
				Keys:         map[string]string{"key1": k, "key2": s},
				Region:       "",
				//LogLevel:     l,
				Logging: config.LoggingConfig{
					Config: logger.Config{
						JSON:   true,
						Level:  l,
						Sample: false,
					},
					PionLevel: L,
				},
				Limit:       config.LimitConfig{},
				Development: false,
			}
			jsonText, err := json.MarshalIndent(_config, "", "")
			if err != nil {
				fmt.Printf("json error : %s", err)
				return err
			}
			if jsonText == nil {
				fmt.Printf("_config==>>%s \n", jsonText)
			}

			serverlogger.InitFromConfig(_config.Logging)
			return startServer(context, &_config)
		},
		//Commands: []*cli.Command{
		//	{
		//		Name:   "generate-keys",
		//		Usage:  "generates an API key and secret pair",
		//		Action: generateKeys,
		//	},
		//	{
		//		// this subcommand is deprecated, token generation is provided by CLI
		//		Name:   "create-join-token",
		//		Hidden: true,
		//
		//		Usage:     "create a room join token for development use",
		//		UsageText: "livekit-server create-join-token [command options] [arguments...]",
		//		Action:    createToken,
		//		Flags: []cli.Flag{
		//			&cli.StringFlag{
		//				Name:     "room",
		//				Usage:    "name of room to join",
		//				Required: true,
		//			},
		//			&cli.StringFlag{
		//				Name:     "identity",
		//				Usage:    "identity of participant that holds the token",
		//				Required: true,
		//			},
		//			&cli.BoolFlag{
		//				Name:     "recorder",
		//				Usage:    "creates a hidden participant that can only subscribe",
		//				Required: false,
		//			},
		//		},
		//	},
		//	{
		//		Name:   "list-nodes",
		//		Usage:  "list all nodes",
		//		Action: listNodes,
		//	},
		//},
		Version: version.Version,
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Println(err)
		return 0
	}
	return 1
}

// 通过json数据启动服务,返回一个服务的指针
//
//export startByArgument
func startByArgument(jsonText string) unsafe.Pointer {
	var _config config.Config
	data := []byte(jsonText)
	err := json.Unmarshal(data, &_config)
	if err != nil {
		return nil
	}
	format, err := json.MarshalIndent(_config, "", "")
	if err != nil {
		fmt.Printf("json error : %s", err)
		return nil
	}
	if format == nil {
		fmt.Printf("_config==>>%s \n %s", jsonText, format)
	}

	serverlogger.InitFromConfig(_config.Logging)
	var service_ *service.LivekitServer //返回一个void指针
	service_, err = startServerOnlyConfig(&_config)
	if err != nil {
		fmt.Printf("startServer error : %s", err)
		return nil
	}
	if service_ == nil {
		fmt.Printf("我tm直接素质三连")
		return nil
	}
	serverMemAlloc := convertServerToCPointer(service_)
	gServerPointer = &serverMemAlloc
	return serverMemAlloc
}

//export stopServerByPointer
func stopServerByPointer(pointer unsafe.Pointer) {
	println("stopServerByPointer start")
	var server *service.LivekitServer
	println("")
	println("stopServerByPointer calling from dart!!")
	server = convertCPointerToGoPointer(pointer)
	go server.Stop(true)
	gServerPointer = nil
	//freeing pointer
	defer C.free(pointer)
	runtime.GC()
	println("stopServerByPointer called from dart!!")
}

// 生成key和secret
//
//export generateKeys
func generateKeys() error {
	apiKey := utils.NewGuid(utils.APIKeyPrefix)
	secret := utils.RandomSecret()
	fmt.Println("API Key: ", apiKey)
	fmt.Println("API Secret: ", secret)
	return nil
}

// 传一个void*指针进来,转换为service.LivekitServer,从里面拿到key和secret
//
//export createToken
func createToken(pointer unsafe.Pointer, room string, identity string) string {
	grant := &auth.VideoGrant{
		RoomJoin: true,
		Room:     room,
	}
	grant.Hidden = true
	grant.Recorder = true
	grant.SetCanPublish(false)
	grant.SetCanPublishData(false)
	//apiKey string, apiSecret string,

	var server *service.LivekitServer
	server = convertCPointerToGoPointer(pointer)
	conf := server.Config
	apiKey := conf.Keys["key1"]
	apiSecret := conf.Keys["key2"]
	at := auth.NewAccessToken(apiKey, apiSecret).
		AddGrant(grant).
		SetIdentity(identity).
		SetValidFor(30 * 24 * time.Hour)

	token, err := at.ToJWT()
	if err != nil {
		logger.Infow("create token failure by ", "toJwt", err)
		format, err := json.MarshalIndent(Response{
			Code: 0,
			Msg:  fmt.Sprintf("创建token失败了: %s", err),
			Data: nil,
		}, "", "")
		if err != nil {
			return "{\"code\":0,\"msg\":\"治不了,等死吧\",\"data\":null}"
		}
		return fmt.Sprintf(string(format))
	}
	fmt.Println("Token:", token)
	format, err := json.MarshalIndent(Response{
		Code: 1,
		Msg:  fmt.Sprintf("创建token成功"),
		Data: &(token),
	}, "", "")
	if err != nil {
		return fmt.Sprintf("{\"code\":0,\"msg\":\"治不了,等死吧:%s\",\"data\":null}", err)
	}
	return fmt.Sprintf(string(format))
}

func init() {
	rand.Seed(time.Now().Unix())
}

func main() {
	//startByTerminal() //main函数通过命令行启动服务
	pointer := startByArgument("{\n    \"Port\":7891,\n    \"BindAddresses\":[\n        \"127.0.0.1\",\n        \"[::1]\"\n    ],\n    \"PrometheusPort\":0,\n    \"RTC\":{\n        \"UDPPort\":0,\n        \"TCPPort\":7881,\n        \"ICEPortRangeStart\":50000,\n        \"ICEPortRangeEnd\":60000,\n        \"NodeIP\":\"0.0.0.0\",\n        \"STUNServers\":null,\n        \"TURNServers\":null,\n        \"UseExternalIP\":true,\n        \"UseICELite\":false,\n        \"Interfaces\":{\n            \"Includes\":null,\n            \"Excludes\":null\n        },\n        \"PacketBufferSize\":0,\n        \"PLIThrottle\":{\n            \"LowQuality\":0,\n            \"MidQuality\":0,\n            \"HighQuality\":0\n        },\n        \"CongestionControl\":{\n            \"Enabled\":false,\n            \"AllowPause\":false,\n            \"UseSendSideBWE\":false,\n            \"ProbeMode\":\"\",\n            \"MinChannelCapacity\":0\n        },\n        \"ForceTCP\":false\n    },\n    \"Redis\":{\n        \"Address\":\"\",\n        \"Username\":\"\",\n        \"Password\":\"\",\n        \"DB\":0,\n        \"UseTLS\":false,\n        \"MasterName\":\"\",\n        \"SentinelUsername\":\"\",\n        \"SentinelPassword\":\"\",\n        \"SentinelAddresses\":null\n    },\n    \"Audio\":{\n        \"ActiveLevel\":0,\n        \"MinPercentile\":0,\n        \"UpdateInterval\":0,\n        \"SmoothIntervals\":0\n    },\n    \"Video\":{\n        \"DynacastPauseDelay\":0\n    },\n    \"Room\":{\n        \"AutoCreate\":true,\n        \"EnabledCodecs\":[\n            {\n                \"Mime\":\"audio/opus\",\n                \"FmtpLine\":\"\"\n            },\n            {\n                \"Mime\":\"video/VP8\",\n                \"FmtpLine\":\"\"\n            },\n            {\n                \"Mime\":\"video/H264\",\n                \"FmtpLine\":\"\"\n            }\n        ],\n        \"MaxParticipants\":0,\n        \"EmptyTimeout\":300,\n        \"EnableRemoteUnmute\":true,\n        \"MaxMetadataSize\":0\n    },\n    \"TURN\":{\n        \"Enabled\":false,\n        \"Domain\":\"\",\n        \"CertFile\":\"\",\n        \"KeyFile\":\"\",\n        \"TLSPort\":0,\n        \"UDPPort\":0,\n        \"RelayPortRangeStart\":0,\n        \"RelayPortRangeEnd\":0,\n        \"ExternalTLS\":false\n    },\n    \"Ingress\":{\n        \"RTMPBaseURL\":\"\"\n    },\n    \"WebHook\":{\n        \"URLs\":null,\n        \"APIKey\":\"\"\n    },\n    \"NodeSelector\":{\n        \"Kind\":\"\",\n        \"SortBy\":\"\",\n        \"CPULoadLimit\":0,\n        \"SysloadLimit\":0,\n        \"Regions\":null\n    },\n    \"KeyFile\":\"\",\n    \"Keys\":{\n        \"key1\":\"APIdCLQLh5E8P2u\",\n        \"key2\":\"kArfeuTGLDc3WLQ7JsGu6bQTAr0CHblnURijqHgHGR5\"\n    },\n    \"Region\":\"\",\n    \"LogLevel\":\"\",\n    \"Logging\":{\n        \"JSON\":true,\n        \"Level\":\"info\",\n        \"Sample\":false,\n        \"PionLevel\":\"error\"\n    },\n    \"Limit\":{\n        \"NumTracks\":0,\n        \"BytesPerSec\":0\n    },\n    \"Development\":false\n}\n\n")
	stopServerByPointer(pointer)
}

func startServer(c *cli.Context, conf *config.Config) error {
	rand.Seed(time.Now().UnixNano())

	memProfile := c.String("memprofile")

	if memProfile != "" {
		if f, err := os.Create(memProfile); err != nil {
			return err
		} else {
			defer func() {
				// run memory profile at termination
				runtime.GC()
				_ = pprof.WriteHeapProfile(f)
				_ = f.Close()
			}()
		}
	}

	currentNode, err := routing.NewLocalNode(conf)
	if err != nil {
		return err
	}

	server, err := service.InitializeServer(conf, currentNode)
	if err != nil {
		return err
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	go func() {
		sig := <-sigChan
		logger.Infow("exit requested, shutting down", "signal", sig)
		server.Stop(false)
	}()

	return server.Start()
}

func startServerOnlyConfig(conf *config.Config) (*service.LivekitServer, error) {
	rand.Seed(time.Now().UnixNano())
	println("")
	currentNode, err := routing.NewLocalNode(conf)
	if err != nil {
		return nil, err
	}
	logger.Infow("startServer InitializeServer", "error:", err)
	server, err := service.InitializeServer(conf, currentNode)
	if err != nil {
		logger.Infow("startServer InitializeServer failure", "error:", err)
		return nil, err
	}
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		sig := <-sigChan
		logger.Infow("exit requested, shutting down", "signal", sig)
		server.Stop(false)
	}()
	go server.Start()

	println("startServer get void pointer success")
	println("")
	return server, nil //返回一个void*指针
}

func convertServerToCPointer(server *service.LivekitServer) unsafe.Pointer {
	//allocate memory on C heap. we send the server address in this pointer
	//allocated memory is freed in Eb_TcpSecureStreamCloseListener()
	serverMemAlloc := C.malloc(C.size_t(unsafe.Sizeof(server)))
	//serverMemAlloc := C.malloc(C.size_t(unsafe.Sizeof(uintptr(0))))
	//create array to write the address in the array
	a := (*[1]*service.LivekitServer)(serverMemAlloc)
	//save the address in index 0 of the array
	a[0] = &(*(*service.LivekitServer)(unsafe.Pointer(&server)))
	fmt.Printf("convertServerToCPointer>>>Address of server=%p\n", &server)
	fmt.Printf("convertServerToCPointer>>>Address of config=%p\n", &(server.Config))
	fmt.Printf("convertServerToCPointer>>>Address of alloc=%p\n", &serverMemAlloc)
	fmt.Printf("convertServerToCPointer>>> port=%d\n", server.Config.Port)
	fmt.Printf("convertServerToCPointer>>> IsRunning=%t\n", server.IsRunning())
	fmt.Printf("convertServerToCPointer>>> String=%s\n", server.Node().String())
	return serverMemAlloc
}

// 转换void* 指针
func convertCPointerToGoPointer(serverMemAlloc unsafe.Pointer) *service.LivekitServer {
	println("${(pointer)[0]}")
	if serverMemAlloc == nil {
		return nil
	}

	parseStructPointer := false

	var server *service.LivekitServer
	if parseStructPointer {
		p := &(*((*[1]*service.LivekitServer)(serverMemAlloc)[0]))
		p2 := unsafe.Pointer(p.Config)
		server = (*service.LivekitServer)(p2)
	} else {
		a := (**[1]*service.LivekitServer)(serverMemAlloc)
		server = (*a)[0]
	}
	fmt.Printf("convertCPointerToGoPointer>>>Address of server=%p\n", &server)
	fmt.Printf("convertCPointerToGoPointer>>>Address of config=%p\n", &(server.Config))
	fmt.Printf("convertCPointerToGoPointer>>>Address of alloc=%p\n", &serverMemAlloc)
	fmt.Printf("convertCPointerToGoPointer>>> port=%d\n", server.Config.Port)
	fmt.Printf("convertCPointerToGoPointer>>> IsRunning=%t\n", server.IsRunning())
	fmt.Printf("convertCPointerToGoPointer>>> String=%s\n", server.Node().String())
	println("convertCPointerToGoPointer")
	return server
}

type Response struct {
	Code int     `json:"code"`
	Msg  string  `json:"msg"`
	Data *string `json:"data"`
}
