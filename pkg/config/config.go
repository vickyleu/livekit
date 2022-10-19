package config

import (
	"fmt"
	"os"
	"time"

	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"

	"github.com/livekit/protocol/logger"
)

var DefaultStunServers = []string{
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
}

type CongestionControlProbeMode string

const (
	CongestionControlProbeModePadding CongestionControlProbeMode = "padding"
	CongestionControlProbeModeMedia   CongestionControlProbeMode = "media"

	StatsUpdateInterval = time.Second * 10
)

type Config struct {
	Port           uint32             `yaml:"port" json:"port"`
	BindAddresses  []string           `yaml:"bind_addresses" json:"bindAddresses"`
	PrometheusPort uint32             `yaml:"prometheus_port,omitempty" json:"prometheusPort"`
	RTC            RTCConfig          `yaml:"rtc,omitempty" json:"rtc"`
	Redis          RedisConfig        `yaml:"redis,omitempty" json:"redis"`
	Audio          AudioConfig        `yaml:"audio,omitempty" json:"audio"`
	Video          VideoConfig        `yaml:"video,omitempty" json:"video"`
	Room           RoomConfig         `yaml:"room,omitempty" json:"room"`
	TURN           TURNConfig         `yaml:"turn,omitempty" json:"turn"`
	Ingress        IngressConfig      `yaml:ingress,omitempty" json:"ingress"`
	WebHook        WebHookConfig      `yaml:"webhook,omitempty" json:"webHook"`
	NodeSelector   NodeSelectorConfig `yaml:"node_selector,omitempty" json:"nodeSelector"`
	KeyFile        string             `yaml:"key_file,omitempty" json:"keyFile"`
	Keys           map[string]string  `yaml:"keys,omitempty" json:"keys"`
	Region         string             `yaml:"region,omitempty" json:"region"`
	// LogLevel is deprecated
	LogLevel    string        `yaml:"log_level,omitempty" json:"logLevel"`
	Logging     LoggingConfig `yaml:"logging,omitempty" json:"logging"`
	Limit       LimitConfig   `yaml:"limit,omitempty" json:"limit"`
	Development bool          `yaml:"development,omitempty" json:"development"`
}

type RTCConfig struct {
	UDPPort           uint32           `yaml:"udp_port,omitempty" json:"udpPort"`
	TCPPort           uint32           `yaml:"tcp_port,omitempty" json:"tcpPort"`
	ICEPortRangeStart uint32           `yaml:"port_range_start,omitempty" json:"icePortRangeStart"`
	ICEPortRangeEnd   uint32           `yaml:"port_range_end,omitempty" json:"icePortRangeEnd"`
	NodeIP            string           `yaml:"node_ip,omitempty" json:"nodeIP"`
	STUNServers       []string         `yaml:"stun_servers,omitempty" json:"stunServers"`
	TURNServers       []TURNServer     `yaml:"turn_servers,omitempty" json:"turnServers"`
	UseExternalIP     bool             `yaml:"use_external_ip" json:"useExternalIP"`
	UseICELite        bool             `yaml:"use_ice_lite,omitempty" json:"useICELite"`
	Interfaces        InterfacesConfig `yaml:"interfaces" json:"interfaces"`

	// Number of packets to buffer for NACK
	PacketBufferSize int `yaml:"packet_buffer_size,omitempty" json:"packetBufferSize"`

	// Throttle periods for pli/fir rtcp packets
	PLIThrottle PLIThrottleConfig `yaml:"pli_throttle,omitempty" json:"pliThrottle"`

	CongestionControl CongestionControlConfig `yaml:"congestion_control,omitempty" json:"congestionControl"`

	// for testing, disable UDP
	ForceTCP bool `yaml:"force_tcp,omitempty" json:"forceTCP"`
}

type TURNServer struct {
	Host       string `yaml:"host" json:"host"`
	Port       int    `yaml:"port" json:"port"`
	Protocol   string `yaml:"protocol" json:"protocol"`
	Username   string `yaml:"username,omitempty" json:"username"`
	Credential string `yaml:"credential,omitempty" json:"credential"`
}

type PLIThrottleConfig struct {
	LowQuality  time.Duration `yaml:"low_quality,omitempty" json:"lowQuality"`
	MidQuality  time.Duration `yaml:"mid_quality,omitempty" json:"midQuality"`
	HighQuality time.Duration `yaml:"high_quality,omitempty" json:"highQuality"`
}

type CongestionControlConfig struct {
	Enabled            bool                       `yaml:"enabled" json:"enabled"`
	AllowPause         bool                       `yaml:"allow_pause" json:"allowPause"`
	UseSendSideBWE     bool                       `yaml:"send_side_bandwidth_estimation,omitempty" json:"useSendSideBWE"`
	ProbeMode          CongestionControlProbeMode `yaml:"padding_mode,omitempty" json:"probeMode"`
	MinChannelCapacity int64                      `yaml:"min_channel_capacity,omitempty" json:"minChannelCapacity"`
}

type InterfacesConfig struct {
	Includes []string `yaml:"includes" json:"includes"`
	Excludes []string `yaml:"excludes" json:"excludes"`
}

type AudioConfig struct {
	// minimum level to be considered active, 0-127, where 0 is loudest
	ActiveLevel uint8 `yaml:"active_level" json:"activeLevel"`
	// percentile to measure, a participant is considered active if it has exceeded the ActiveLevel more than
	// MinPercentile% of the time
	MinPercentile uint8 `yaml:"min_percentile" json:"minPercentile"`
	// interval to update clients, in ms
	UpdateInterval uint32 `yaml:"update_interval" json:"updateInterval"`
	// smoothing for audioLevel values sent to the client.
	// audioLevel will be an average of `smooth_intervals`, 0 to disable
	SmoothIntervals uint32 `yaml:"smooth_intervals" json:"smoothIntervals"`
}

type VideoConfig struct {
	DynacastPauseDelay time.Duration `yaml:"dynacast_pause_delay,omitempty" json:"dynacastPauseDelay"`
}

type RedisConfig struct {
	Address           string   `yaml:"address" json:"address"`
	Username          string   `yaml:"username" json:"username"`
	Password          string   `yaml:"password" json:"password"`
	DB                int      `yaml:"db" json:"db"`
	UseTLS            bool     `yaml:"use_tls" json:"useTLS"`
	MasterName        string   `yaml:"sentinel_master_name" json:"masterName"`
	SentinelUsername  string   `yaml:"sentinel_username" json:"sentinelUsername"`
	SentinelPassword  string   `yaml:"sentinel_password" json:"sentinelPassword"`
	SentinelAddresses []string `yaml:"sentinel_addresses" json:"sentinelAddresses"`
}

type RoomConfig struct {
	// enable rooms to be automatically created
	AutoCreate         bool        `yaml:"auto_create" json:"autoCreate"`
	EnabledCodecs      []CodecSpec `yaml:"enabled_codecs" json:"enabledCodecs"`
	MaxParticipants    uint32      `yaml:"max_participants" json:"maxParticipants"`
	EmptyTimeout       uint32      `yaml:"empty_timeout" json:"emptyTimeout"`
	EnableRemoteUnmute bool        `yaml:"enable_remote_unmute" json:"enableRemoteUnmute"`
	MaxMetadataSize    uint32      `yaml:"max_metadata_size" json:"maxMetadataSize"`
}

type CodecSpec struct {
	Mime     string `yaml:"mime" json:"mime"`
	FmtpLine string `yaml:"fmtp_line" json:"fmtpLine"`
}

type LoggingConfig struct {
	logger.Config `yaml:",inline" `
	PionLevel     string `yaml:"pion_level,omitempty" json:"pionLevel"`
}

type TURNConfig struct {
	Enabled             bool   `yaml:"enabled" json:"enabled"`
	Domain              string `yaml:"domain" json:"domain"`
	CertFile            string `yaml:"cert_file" json:"cert_file"`
	KeyFile             string `yaml:"key_file" json:"key_file"`
	TLSPort             int    `yaml:"tls_port" json:"tls_port"`
	UDPPort             int    `yaml:"udp_port" json:"udp_port"`
	RelayPortRangeStart uint16 `yaml:"relay_range_start,omitempty" json:"relay_range_start"`
	RelayPortRangeEnd   uint16 `yaml:"relay_range_end,omitempty" json:"relay_range_end"`
	ExternalTLS         bool   `yaml:"external_tls" json:"external_tls"`
}

type WebHookConfig struct {
	URLs []string `yaml:"urls" json:"urls"`
	// key to use for webhook
	APIKey string `yaml:"api_key" json:"apiKey"`
}

type NodeSelectorConfig struct {
	Kind         string         `yaml:"kind" json:"kind"`
	SortBy       string         `yaml:"sort_by" json:"sortBy"`
	CPULoadLimit float32        `yaml:"cpu_load_limit" json:"cpuLoadLimit"`
	SysloadLimit float32        `yaml:"sysload_limit" json:"sysloadLimit"`
	Regions      []RegionConfig `yaml:"regions" json:"regions"`
}

// RegionConfig lists available regions and their latitude/longitude, so the selector would prefer
// regions that are closer
type RegionConfig struct {
	Name string  `yaml:"name" json:"name"`
	Lat  float64 `yaml:"lat" json:"lat"`
	Lon  float64 `yaml:"lon" json:"lon"`
}

type LimitConfig struct {
	NumTracks   int32   `yaml:"num_tracks" json:"numTracks"`
	BytesPerSec float32 `yaml:"bytes_per_sec" json:"bytesPerSec"`
}

type IngressConfig struct {
	RTMPBaseURL string `yaml:"rtmp_base_url" json:"rtmpBaseUrl"`
}

func NewConfig(confString string, c *cli.Context) (*Config, error) {
	// start with defaults
	conf := &Config{
		Port: 7880,
		RTC: RTCConfig{
			UseExternalIP:     false,
			TCPPort:           7881,
			UDPPort:           0,
			ICEPortRangeStart: 0,
			ICEPortRangeEnd:   0,
			STUNServers:       []string{},
			PacketBufferSize:  500,
			PLIThrottle: PLIThrottleConfig{
				LowQuality:  500 * time.Millisecond,
				MidQuality:  time.Second,
				HighQuality: time.Second,
			},
			CongestionControl: CongestionControlConfig{
				Enabled:    true,
				AllowPause: false,
				ProbeMode:  CongestionControlProbeModePadding,
			},
		},
		Audio: AudioConfig{
			ActiveLevel:     35, // -35dBov
			MinPercentile:   40,
			UpdateInterval:  400,
			SmoothIntervals: 2,
		},
		Video: VideoConfig{
			DynacastPauseDelay: 5 * time.Second,
		},
		Redis: RedisConfig{},
		Room: RoomConfig{
			AutoCreate:    true,
			EnabledCodecs: CodecDef(),
			EmptyTimeout:  5 * 60,
		},
		Logging: LoggingConfig{
			PionLevel: "error",
		},
		TURN: TURNConfig{
			Enabled: false,
		},
		NodeSelector: NodeSelectorConfig{
			Kind:         "any",
			SortBy:       "random",
			SysloadLimit: 0.9,
			CPULoadLimit: 0.9,
		},
		Keys: map[string]string{},
	}
	if confString != "" {
		if err := yaml.Unmarshal([]byte(confString), conf); err != nil {
			return nil, fmt.Errorf("could not parse config: %v", err)
		}
	}

	if c != nil {
		if err := conf.updateFromCLI(c); err != nil {
			return nil, err
		}
	}

	// expand env vars in filenames
	file, err := homedir.Expand(os.ExpandEnv(conf.KeyFile))
	if err != nil {
		return nil, err
	}
	conf.KeyFile = file

	// set defaults for ports if none are set
	if conf.RTC.UDPPort == 0 && conf.RTC.ICEPortRangeStart == 0 {
		// to make it easier to run in dev mode/docker, default to single port
		if conf.Development {
			conf.RTC.UDPPort = 7882
		} else {
			conf.RTC.ICEPortRangeStart = 50000
			conf.RTC.ICEPortRangeEnd = 60000
		}
	}

	// set defaults for Turn relay if none are set
	if conf.TURN.RelayPortRangeStart == 0 || conf.TURN.RelayPortRangeEnd == 0 {
		// to make it easier to run in dev mode/docker, default to two ports
		if conf.Development {
			conf.TURN.RelayPortRangeStart = 30000
			conf.TURN.RelayPortRangeEnd = 30002
		} else {
			conf.TURN.RelayPortRangeStart = 30000
			conf.TURN.RelayPortRangeEnd = 40000
		}
	}

	if conf.RTC.NodeIP == "" {
		conf.RTC.NodeIP, err = conf.determineIP()
		if err != nil {
			return nil, err
		}
	}

	if conf.LogLevel != "" {
		conf.Logging.Level = conf.LogLevel
	}
	if conf.Logging.Level == "" && conf.Development {
		conf.Logging.Level = "debug"
	}

	return conf, nil
}

func (conf *Config) HasRedis() bool {
	return conf.Redis.Address != "" || conf.Redis.SentinelAddresses != nil
}

func (conf *Config) UseSentinel() bool {
	return conf.Redis.SentinelAddresses != nil
}

func (conf *Config) updateFromCLI(c *cli.Context) error {
	if c.IsSet("dev") {
		conf.Development = c.Bool("dev")
	}
	if c.IsSet("key-file") {
		conf.KeyFile = c.String("key-file")
	}
	if c.IsSet("keys") {
		if err := conf.unmarshalKeys(c.String("keys")); err != nil {
			return errors.New("Could not parse keys, it needs to be exactly, \"key: secret\", including the space")
		}
	}
	if c.IsSet("region") {
		conf.Region = c.String("region")
	}
	if c.IsSet("redis-host") {
		conf.Redis.Address = c.String("redis-host")
	}
	if c.IsSet("redis-password") {
		conf.Redis.Password = c.String("redis-password")
	}
	if c.IsSet("turn-cert") {
		conf.TURN.CertFile = c.String("turn-cert")
	}
	if c.IsSet("turn-key") {
		conf.TURN.KeyFile = c.String("turn-key")
	}
	if c.IsSet("node-ip") {
		conf.RTC.NodeIP = c.String("node-ip")
	}
	if c.IsSet("udp-port") {
		conf.RTC.UDPPort = uint32(c.Int("udp-port"))
	}
	if c.IsSet("bind") {
		conf.BindAddresses = c.StringSlice("bind")
	}
	return nil
}

func (conf *Config) unmarshalKeys(keys string) error {
	temp := make(map[string]interface{})
	if err := yaml.Unmarshal([]byte(keys), temp); err != nil {
		return err
	}

	conf.Keys = make(map[string]string, len(temp))

	for key, val := range temp {
		if secret, ok := val.(string); ok {
			conf.Keys[key] = secret
		}
	}
	return nil
}
