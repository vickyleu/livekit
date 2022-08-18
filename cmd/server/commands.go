package main

import (
	"github.com/livekit/livekit-server/pkg/config"
	serverlogger "github.com/livekit/livekit-server/pkg/logger"
	"github.com/livekit/protocol/logger"
	"github.com/urfave/cli/v2"
	"os"
)

func getConfig(c *cli.Context) (*config.Config, error) {
	confString, err := getConfigString("./config.xml", c.String("config-body"))
	//confString, err := getConfigString( c.String("config"), c.String("config-body"))
	if err != nil {
		return nil, err
	}
	conf, err := config.NewConfig(confString, c)
	if err != nil {
		return nil, err
	}
	serverlogger.InitFromConfig(conf.Logging)

	if c.String("config") == "" && c.String("config-body") == "" && conf.Development {
		// use single port UDP when no config is provided
		conf.RTC.UDPPort = 7882
		conf.RTC.ICEPortRangeStart = 0
		conf.RTC.ICEPortRangeEnd = 0
		logger.Infow("starting in development mode")

		if len(conf.Keys) == 0 {
			logger.Infow("no keys provided, using placeholder keys",
				"API Key", "devkey",
				"API Secret", "secret",
			)
			conf.Keys = map[string]string{
				"devkey": "secret",
			}
			// when dev mode and using shared keys, we'll bind to localhost by default
			if conf.BindAddresses == nil {
				conf.BindAddresses = []string{
					"127.0.0.1",
					"[::1]",
				}
			}
		}
	}
	return conf, nil
}

func getConfigString(configFile string, inConfigBody string) (string, error) {
	if inConfigBody != "" || configFile == "" {
		return inConfigBody, nil
	}

	outConfigBody, err := os.ReadFile(configFile)
	if err != nil {
		return "", err
	}

	return string(outConfigBody), nil
}
