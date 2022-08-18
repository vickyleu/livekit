# LiveKit: High-performance WebRTC

LiveKit is an open source project that provides scalable, multi-user conferencing based on WebRTC. It's designed to
provide everything you need to build real-time video/audio/data capabilities in your applications.

LiveKit's server is written in Go, using the awesome [Pion WebRTC](https://github.com/pion/webrtc) implementation.

[![GitHub stars](https://img.shields.io/github/stars/livekit/livekit?style=social&label=Star&maxAge=2592000)](https://github.com/livekit/livekit/stargazers/)
[![Slack community](https://img.shields.io/endpoint?url=https%3A%2F%2Flivekit.io%2Fbadges%2Fslack)](https://livekit.io/join-slack)
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/livekit/livekit/Test)](https://github.com/livekit/livekit/actions/workflows/buildtest.yaml)
[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/livekit/livekit)](https://github.com/livekit/livekit/releases/latest)
[![License](https://img.shields.io/github/license/livekit/livekit)](https://github.com/livekit/livekit/blob/master/LICENSE)

## 剩余未完成功能 
框架实际上包含所有功能,但需要写一个C语言的导出函数,app通过头文件访问go打包二进制的函数
 - <strong>createToken</strong>: 创建token,不记得有没有写完 😓 (房间管理可以参考这种写法)
 - <strong>创建房间,管理房间</strong>: 还没做
 - ~~<strong>startByArgument</strong>: 通过传递json字符串启动一个rtc服务~~(已实现) 
  <br>
  <br>
  <br>
  但是 <u><font color=red>如果能在启动服务时
   返回一个var server *service.LivekitServer 的  <strong>void\*</strong>  指针更好,避免反复传apiKey和apiSecret,还有
   目前的服务调起后绑定的端口杀死不会解绑,不知道怎么回事,要修改成服务关闭前主动解绑端口号</font></u>

## 打包二进制
```
  goreleaser release --skip-publish --snapshot --rm-dist'
```
 - <font color=blue>目前注释掉了其他平台的打包,可以通过修改.goreleaser.yaml builds 里面对应的
   平台进行独立打包,除Webassembly以外,已全部实现各平台的交叉编译,windows编译在
   linux和mac上需要安装zig cc打包arm架构,mingw32打包x86架构,在windows上可以安装visual studio,
   其他的我也没试过.iOS必须使用mac打包,macOS的也可以实现交叉编译</font>

## Features

- Scalable, distributed WebRTC SFU (Selective Forwarding Unit)
- Modern, full-featured client SDKs
- Built for production, supports JWT authentication
- Robust networking and connectivity, UDP/TCP/TURN
- Easy to deploy: single binary, Docker or Kubernetes
- Advanced features including:
    - [speaker detection](https://docs.livekit.io/guides/room/receive/#speaker-detection)
    - [simulcast](https://docs.livekit.io/guides/room/publish/#video-simulcast)
    - [end-to-end optimizations](https://blog.livekit.io/livekit-one-dot-zero/)
    - [selective subscription](https://docs.livekit.io/guides/room/receive/#selective-subscription)
    - [moderation APIs](https://docs.livekit.io/guides/server-api/)
    - [webhooks](https://docs.livekit.io/guides/webhooks/)

## Documentation & Guides

https://docs.livekit.io

## Try it live

Head to [our playground](https://livekit.io/playground) and give it a spin. Build a Zoom-like conferencing app in under
100 lines of code!

## SDKs & Tools

### Client SDKs

Client SDKs enable your frontend to include interactive, multi-user experiences.

<table>
  <tr>
    <th>Language</th>
    <th>Repo</th>
    <th>
        <a href="https://docs.livekit.io/guides/room/events/#declarative-ui" target="_blank" rel="noopener noreferrer">Declarative UI</a>
    </th>
    <th>Links</th>
  </tr>
  <!-- BEGIN Template
  <tr>
    <td>Language</td>
    <td>
      <a href="" target="_blank" rel="noopener noreferrer"></a>
    </td>
    <td></td>
    <td></td>
  </tr>
  END -->
  <!-- JavaScript -->
  <tr>
    <td>JavaScript (TypeScript)</td>
    <td>
      <a href="https://github.com/livekit/client-sdk-js" target="_blank" rel="noopener noreferrer">client-sdk-js</a>
    </td>
    <td>
      <a href="https://github.com/livekit/livekit-react" target="_blank" rel="noopener noreferrer">React</a>
    </td>
    <td>
      <a href="https://docs.livekit.io/client-sdk-js/" target="_blank" rel="noopener noreferrer">docs</a>
      |
      <a href="https://github.com/livekit/client-sdk-js/tree/main/example" target="_blank" rel="noopener noreferrer">JS example</a>
      |
      <a href="https://github.com/livekit/client-sdk-js/tree/main/example" target="_blank" rel="noopener noreferrer">React example</a>
    </td>
  </tr>
  <!-- Swift -->
  <tr>
    <td>Swift (iOS / MacOS)</td>
    <td>
      <a href="https://github.com/livekit/client-sdk-swift" target="_blank" rel="noopener noreferrer">client-sdk-swift</a>
    </td>
    <td>Swift UI</td>
    <td>
      <a href="https://docs.livekit.io/client-sdk-swift/" target="_blank" rel="noopener noreferrer">docs</a>
      |
      <a href="https://github.com/livekit/client-example-swift" target="_blank" rel="noopener noreferrer">example</a>
    </td>
  </tr>
  <!-- Kotlin -->
  <tr>
    <td>Kotlin (Android)</td>
    <td>
      <a href="https://github.com/livekit/client-sdk-android" target="_blank" rel="noopener noreferrer">client-sdk-android</a>
    </td>
    <td>Compose</td>
    <td>
      <a href="https://docs.livekit.io/client-sdk-android/index.html" target="_blank" rel="noopener noreferrer">docs</a>
      |
      <a href="https://github.com/livekit/client-sdk-android/tree/main/sample-app/src/main/java/io/livekit/android/sample" target="_blank" rel="noopener noreferrer">example</a>
      |
      <a href="https://github.com/livekit/client-sdk-android/tree/main/sample-app-compose/src/main/java/io/livekit/android/composesample" target="_blank" rel="noopener noreferrer">Compose example</a>
    </td>
  </tr>
  <tr>
    <td>Flutter</td>
    <td>
      <a href="https://github.com/livekit/client-sdk-flutter" target="_blank" rel="noopener noreferrer">client-sdk-flutter</a>
    </td>
    <td>native</td>
    <td>
      <a href="https://docs.livekit.io/client-sdk-flutter/" target="_blank" rel="noopener noreferrer">docs</a>
      |
      <a href="https://github.com/livekit/client-sdk-flutter/tree/main/example" target="_blank" rel="noopener noreferrer">example</a>
    </td>
  </tr>
  <!-- Unity -->
  <tr>
    <td>Unity WebGL</td>
    <td>
      <a href="https://github.com/livekit/client-sdk-unity-web" target="_blank" rel="noopener noreferrer">client-sdk-unity-web</a>
    </td>
    <td></td>
    <td>
      <a href="https://livekit.github.io/client-sdk-unity-web/" target="_blank" rel="noopener noreferrer">docs</a>
    </td>
  </tr>
  <!-- React Native -->
  <tr>
    <td>React Native (beta)</td>
    <td>
      <a href="https://github.com/livekit/client-sdk-react-native" target="_blank" rel="noopener noreferrer">client-sdk-react-native</a>
    </td>
    <td>native</td>
    <td></td>
  </tr>
</table>

### Server SDKs

Server SDKs enable your backend to generate [access tokens](https://docs.livekit.io/guides/access-tokens/),
call [server APIs](https://docs.livekit.io/guides/server-api/), and
receive [webhooks](https://docs.livekit.io/guides/webhooks/). In addition, the Go SDK includes client capabilities,
enabling you to build automations that behave like end-users.

| Language                | Repo                                                                                                | Docs                                                        |
|:------------------------|:----------------------------------------------------------------------------------------------------|:------------------------------------------------------------|
| Go                      | [server-sdk-go](https://github.com/livekit/server-sdk-go)                                           | [docs](https://pkg.go.dev/github.com/livekit/server-sdk-go) |
| JavaScript (TypeScript) | [server-sdk-js](https://github.com/livekit/server-sdk-js)                                           | [docs](https://docs.livekit.io/server-sdk-js/)              |
| Ruby                    | [server-sdk-ruby](https://github.com/livekit/server-sdk-ruby)                                       |                                                             |
| Python (community)      | [tradablebits/livekit-server-sdk-python](https://github.com/tradablebits/livekit-server-sdk-python) |                                                             |
| PHP (community)         | [agence104/livekit-server-sdk-php](https://github.com/agence104/livekit-server-sdk-php)             |                                                             |

### Ecosystem & Tools

- [Egress](https://github.com/livekit/egress) - export and record your rooms
- [CLI](https://github.com/livekit/livekit-cli) - command line interface & load tester
- [Docker image](https://hub.docker.com/r/livekit/livekit-server)
- [Helm charts](https://github.com/livekit/livekit-helm)

## Install

We recommend installing [livekit-cli](https://github.com/livekit/livekit-cli) along with the server. It lets you access
server APIs, create tokens, and generate test traffic.

### MacOS

```shell
brew install livekit
```

### Linux

```shell
curl -sSL https://get.livekit.io | bash
```

### Windows

Download the [latest release here](https://github.com/livekit/livekit/releases/latest)

## Getting Started

### Starting LiveKit

Start LiveKit in development mode by running `livekit-server --dev`. It'll use a placeholder API key/secret pair.

```
API Key: devkey
API Secret: secret
```

To customize your setup for production, refer to our [deployment docs](https://docs.livekit.io/deploy/)

### Creating access token

A user connecting to a LiveKit room requires an [access token](https://docs.livekit.io/guides/access-tokens/). Access
tokens (JWT) encode the user's identity and the room permissions they've been granted. You can generate a token with our
CLI:

```shell
livekit-cli create-token \
    --api-key devkey --api-secret secret \
    --join --room my-first-room --identity user1 \
    --valid-for 24h
```

### Test with example app

Head over to our [example app](https://example.livekit.io) and enter a generated token to connect to your LiveKit
server. This app is built with our [React SDK](https://github.com/livekit/livekit-react).

Once connected, your video and audio are now being published to your new LiveKit instance!

### Simulating a test publisher

```shell
livekit-cli join-room \
    --url ws://localhost:7880 \
    --api-key devkey --api-secret secret \
    --room my-first-room --identity bot-user1 \
    --publish-demo
```

This command publishes a looped demo video to a room. Due to how the video clip was encoded (keyframes every 3s),
there's a slight delay before the browser has sufficient data to begin rendering frames. This is an artifact of the
simulation.

## Deploying to a server

Read our [deployment docs](https://docs.livekit.io/deploy/) for more information.

## Building from source

Pre-requisites:

- Go 1.16+ is installed
- GOPATH/bin is in your PATH

Then run

```shell
git clone https://github.com/livekit/livekit
cd livekit
./bootstrap.sh
mage
```

## Contributing

We welcome your contributions toward improving LiveKit! Please join us
[on Slack](http://livekit.io/join-slack) to discuss your ideas and/or PRs.

## License

LiveKit server is licensed under Apache License v2.0.
