//go:build !js

package config

import (
	"github.com/pion/webrtc/v3"
)

func CodecDef() []CodecSpec {
	return []CodecSpec{
		{Mime: webrtc.MimeTypeOpus},
		{Mime: webrtc.MimeTypeVP8},
		{Mime: webrtc.MimeTypeH264},
		// {Mime: webrtc.MimeTypeAV1},
		// {Mime: webrtc.MimeTypeVP9},
	}
}
