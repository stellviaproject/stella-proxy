package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/stellviaproject/stella-proxy/transport"
)

func main() {
	PORT := os.Getenv("PORT")
	useCfg := flag.Bool("config", false, "use a file configuration")
	getExample := flag.Bool("example", false, "write a configuration example file")
	flag.Parse()
	var port int
	if p, err := strconv.Atoi(PORT); err != nil {
		port = 8080
	} else {
		port = p
	}
	proxy := goproxy.NewProxyHttpServer()
	cfg := NewConfig()
	if *useCfg {
		var err error
		cfg, err = LoadConfig("./config.json")
		if err != nil {
			log.Fatalln(err)
		}
		if cfg.Port > 0 {
			port = cfg.Port
		}
	}
	if *getExample {
		os.WriteFile("./example.json", []byte(Example), os.ModeDevice|os.ModePerm)
		return
	}
	dialer := &net.Dialer{
		Timeout:   time.Duration(float64(cfg.Timeout) * float64(time.Second)),
		KeepAlive: time.Duration(float64(cfg.KeepAlive) * float64(time.Second)),
	}
	proxy.Tr = GetTransport(dialer.DialContext, cfg.MaxRetry, cfg.Chain)
	log.Printf("proxy is running at: 0.0.0.0:%d\n", port)
	log.Println(http.ListenAndServe(fmt.Sprintf(":%d", port), proxy))
}

func GetTransport(dialContext transport.DialContext, maxRetry int, chain []ProxyConfig) *http.Transport {
	var Tr *http.Transport
	if len(chain) > 0 {
		dialChain := WrapChain(
			dialContext,
			maxRetry,
			chain,
		)
		Tr = &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				return dialChain(context.Background(), network, addr)
			},
			DialContext: dialChain,
		}
	} else {
		Tr = &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				return dialContext(context.Background(), network, addr)
			},
			DialContext: dialContext,
		}
	}
	return Tr
}

func WrapChain(dialContext transport.DialContext, maxRetry int, chain []ProxyConfig) transport.DialContext {
	for _, proxy := range chain {
		dialContext = transport.WrapDialContext(dialContext, maxRetry, proxy.IsHTTPS, proxy.IsNTLM, proxy.InsecureSkip, proxy.ProxyAddr, proxy.ProxyUser, proxy.ProxyPassword, proxy.ProxyDomain)
	}
	return dialContext
}

type ClientConfig struct {
	Port      int           `json:"port"`
	Timeout   float64       `json:"timeout"`
	KeepAlive float64       `json:"keep-alive"`
	MaxRetry  int           `json:"max-retry"`
	Chain     []ProxyConfig `json:"chain"`
}

type ProxyConfig struct {
	ProxyAddr     string `json:"addr"`
	IsHTTPS       bool   `json:"is-https"`
	InsecureSkip  bool   `json:"insecure-skip"`
	IsNTLM        bool   `json:"is-ntlm"`
	ProxyUser     string `json:"user"`
	ProxyPassword string `json:"password"`
	ProxyDomain   string `json:"domain"`
}

func SaveConfig(fileName string, config ClientConfig) error {
	data, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		return err
	}
	return os.WriteFile(fileName, data, os.ModePerm|os.ModeDevice)
}

func LoadConfig(fileName string) (config ClientConfig, err error) {
	var data []byte
	data, err = os.ReadFile(fileName)
	if err != nil {
		return
	}
	err = json.Unmarshal(data, &config)
	return
}

func NewConfig() ClientConfig {
	return ClientConfig{
		Timeout:   30.0,
		KeepAlive: 30.0,
		MaxRetry:  3,
		Port:      -1,
	}
}

const Example = `{
    "port": 9090,
    "timeout": 30,
    "keep-alive": 30,
	"max-retry": 3,
    "chain": [
        {
            "addr": "127.0.0.1:8080",
            "is-https": false,
            "is-ntlm": false,
            "insecure-skip": false,
            "user": "",
            "password": "",
            "domain": ""
        }, {
            "addr": "192.168.43.1:8080",
            "is-https": false,
            "is-ntlm": false,
            "insecure-skip": false,
            "user": "",
            "password": "",
            "domain": ""
        }
    ]
}`
