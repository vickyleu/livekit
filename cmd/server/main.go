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
	"sync"
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
var gTurnPointer *unsafe.Pointer   // 全局变量

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
		return nil
	}
	if gServerPointer != nil {
		server := convertCPointerToGoPointer(*gServerPointer)
		if server != nil {
			format2, err := json.MarshalIndent(server.Config, "", "")
			if err == nil && format2 != nil {
				jsonText2 := string(format2[:])
				jsonText1 := string(format[:])
				if jsonText2 == jsonText1 {
					fmt.Printf("配置没改,直接返回旧指针")
					return *gServerPointer
				}
			}
			fmt.Printf("关闭之前的服务,回收指针")
			group := sync.WaitGroup{}
			group.Add(1)
			go func() {
				server.Stop(true)
				group.Done()
			}()
			group.Wait()
			C.free(*gServerPointer)
			gServerPointer = nil
		} else {
			fmt.Printf("未找到服务,回收指针")
			C.free(*gServerPointer)
			gServerPointer = nil
		}
	}
	serverlogger.InitFromConfig(_config.Logging)
	var service_ *service.LivekitServer //返回一个void指针
	service_, err = startServerOnlyConfig(&_config)
	if err != nil {
		fmt.Printf("startServer error : %s\n", err)
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

	/*{
		"port": 7891,
		"bindAddresses": ["127.0.0.1", "[::1]"],
	"prometheusPort": 0,
	"rtc": {
	"udpPort": 0,
	"tcpPort": 7881,
	"icePortRangeStart": 50000,
	"icePortRangeEnd": 60000,
	"nodeIP": "0.0.0.0",
	"stunServers": null,
	"turnServers": null,
	"useExternalIP": true,
	"useICELite": false,
	"interfaces": {
	"includes": null,
	"excludes": null
	},
	"packetBufferSize": 0,
	"pliThrottle": {
	"lowQuality": 0,
	"midQuality": 0,
	"highQuality": 0
	},
	"congestionControl": {
	"enabled": false,
	"allowPause": false,
	"useSendSideBWE": false,
	"probeMode": "",
	"minChannelCapacity": 0
	},
	"forceTCP": false
	},
	"redis": {
	"address": "",
	"username": "",
	"password": "",
	"db": 0,
	"useTLS": false,
	"masterName": "",
	"sentinelUsername": "",
	"sentinelPassword": "",
	"sentinelAddresses": null
	},
	"audio": {
	"activeLevel": 0,
	"minPercentile": 0,
	"updateInterval": 0,
	"smoothIntervals": 0
	},
	"video": {
	"dynacastPauseDelay": 0
	},
	"room": {
	"autoCreate": true,
	"enabledCodecs": [{
	"mime": "audio/opus",
	"fmtpLine": ""
	}, {
	"mime": "video/VP8",
	"fmtpLine": ""
	}, {
	"mime": "video/H264",
	"fmtpLine": ""
	}],
	"maxParticipants": 0,
	"emptyTimeout": 300,
	"enableRemoteUnmute": true,
	"maxMetadataSize": 0
	},
	"turn": {
	"enabled": true,
	"secretName": "livekit-turn",
	"domain": "127.0.0.1",
	"cert_file": null,
	"key_file": null,
	"udp_port": 7894,
	"tls_port": 0,
	"relay_range_start": 30000,
	"relay_range_end": 40000,
	"external_tls": true
	},
	"ingress": {
	"rtmpBaseUrl": ""
	},
	"webHook": {
	"urls": null,
	"apiKey": ""
	},
	"nodeSelector": {
	"kind": "",
	"sortBy": "",
	"cpuLoadLimit": 0,
	"sysloadLimit": 0,
	"regions": null
	},
	"keyFile": "",
	"keys": {
	"key1": "APIdCLQLh5E8P2u",
	"key2": "kArfeuTGLDc3WLQ7JsGu6bQTAr0CHblnURijqHgHGR5"
	},
	"region": "",
	"logLevel": "",
	"logging": {
	"JSON": true,
	"Level": "info",
	"Sample": false,
	"pionLevel": "error"
	},
	"limit": {
	"numTracks": 0,
	"bytesPerSec": 0
	},
	"development": false
	}*/
	//startByTerminal() //main函数通过命令行启动服务
	configJson := "{\"port\": 7891,\"bindAddresses\": [\"127.0.0.1\", \"[::1]\"],\"prometheusPort\": 0,\"rtc\": {\"udpPort\": 0,\"tcpPort\": 7881,\"icePortRangeStart\": 50000,\"icePortRangeEnd\": 60000,\"nodeIP\": \"0.0.0.0\",\"stunServers\": null,\"turnServers\": null,\"useExternalIP\": true,\"useICELite\": false,\"interfaces\": {\"includes\": null,\"excludes\": null},\"packetBufferSize\": 0,\"pliThrottle\": {\"lowQuality\": 0,\"midQuality\": 0,\"highQuality\": 0},\"congestionControl\": {\"enabled\": false,\"allowPause\": false,\"useSendSideBWE\": false,\"probeMode\": \"\",\"minChannelCapacity\": 0},\"forceTCP\": false},\"redis\": {\"address\": \"\",\"username\": \"\",\"password\": \"\",\"db\": 0,\"useTLS\": false,\"masterName\": \"\",\"sentinelUsername\": \"\",\"sentinelPassword\": \"\",\"sentinelAddresses\": null},\"audio\": {\"activeLevel\": 0,\"minPercentile\": 0,\"updateInterval\": 0,\"smoothIntervals\": 0},\"video\": {\"dynacastPauseDelay\": 0},\"room\": {\"autoCreate\": true,\"enabledCodecs\": [{\"mime\": \"audio/opus\",\"fmtpLine\": \"\"}, {\"mime\": \"video/VP8\",\"fmtpLine\": \"\"}, {\"mime\": \"video/H264\",\"fmtpLine\": \"\"}],\"maxParticipants\": 0,\"emptyTimeout\": 300,\"enableRemoteUnmute\": true,\"maxMetadataSize\": 0},\"turn\": {\"enabled\": true,\"secretName\": \"livekit-turn\",\"domain\": \"127.0.0.1\",\"cert_file\": null,\"key_file\": null,\"udp_port\": 7894,\"tls_port\": 0,\"relay_range_start\": 30000,\"relay_range_end\": 40000,\"external_tls\": true},\"ingress\": {\"rtmpBaseUrl\": \"\"},\"webHook\": {\"urls\": null,\"apiKey\": \"\"},\"nodeSelector\": {\"kind\": \"\",\"sortBy\": \"\",\"cpuLoadLimit\": 0,\"sysloadLimit\": 0,\"regions\": null},\"keyFile\": \"\",\"keys\": {\"key1\": \"APIdCLQLh5E8P2u\",\"key2\": \"kArfeuTGLDc3WLQ7JsGu6bQTAr0CHblnURijqHgHGR5\"},\"region\": \"\",\"logLevel\": \"\",\"logging\": {\"JSON\": true,\"Level\": \"info\",\"Sample\": false,\"pionLevel\": \"error\"},\"limit\": {\"numTracks\": 0,\"bytesPerSec\": 0},\"development\": false}"
	pointer := startByArgument(configJson)
	time.Sleep(time.Duration(2) * time.Second)
	if pointer != nil {
		stopServerByPointer(pointer)
	}

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
	//fmt.Printf("convertServerToCPointer>>> String=%s\n", server.Node().String())
	return serverMemAlloc
}

// 转换void* 指针
func convertCPointerToGoPointer(serverMemAlloc unsafe.Pointer) *service.LivekitServer {
	if serverMemAlloc == nil {
		return nil
	}
	var server *service.LivekitServer
	a := (**[1]*service.LivekitServer)(serverMemAlloc)
	server = (*a)[0]
	//fmt.Printf("convertCPointerToGoPointer>>> String=%s\n", server.Node().String())
	return server
}

type Response struct {
	Code int     `json:"code"`
	Msg  string  `json:"msg"`
	Data *string `json:"data"`
}
