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
	usePrint := flag.Bool("ifaces", false, "print all interfaces")
	useGet := flag.Bool("get", false, "redirect all GET to a CONNECT HTTP method with internal wrapper")
	flag.Parse()
	var port int
	if p, err := strconv.Atoi(PORT); err != nil {
		port = 8080
	} else {
		port = p
	}
	if *usePrint {
		PrintIPs()
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
	if *useGet {
		log.Println("use get is active")
		log.Printf("proxy is running at: 0.0.0.0:%d\n", port)
		log.Println(http.ListenAndServe(fmt.Sprintf(":%d", port), &GetWrapper{
			proxy: proxy,
		}))
	} else {
		log.Printf("proxy is running at: 0.0.0.0:%d\n", port)
		log.Println(http.ListenAndServe(fmt.Sprintf(":%d", port), proxy))
	}
}

type GetWrapper struct {
	proxy *goproxy.ProxyHttpServer
}

func (wr *GetWrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" && (r.URL.Path == "" || r.URL.Path == "/") {
		r.Method = "CONNECT"
	}
	wr.proxy.ServeHTTP(w, r)
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
		dialContext = transport.WrapDialContext(dialContext, maxRetry, proxy.IsGet, proxy.IsHTTPS, proxy.IsNTLM, proxy.InsecureSkip, proxy.ProxyAddr, proxy.ProxyUser, proxy.ProxyPassword, proxy.ProxyDomain)
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
	IsGet         bool   `json:"is-get"`
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
			"is-get": false,
            "insecure-skip": false,
            "user": "",
            "password": "",
            "domain": ""
        }, {
            "addr": "192.168.43.1:8080",
            "is-https": false,
            "is-ntlm": false,
			"is-get": false,
            "insecure-skip": false,
            "user": "",
            "password": "",
            "domain": ""
        }
    ]
}`

func PrintIPs() {
	// Obtener todas las interfaces de red
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("Error al obtener las interfaces de red:", err)
		return
	}

	// Iterar sobre las interfaces de red
	for _, i := range interfaces {
		// Obtener todas las direcciones IP asociadas a la interfaz
		addrs, err := i.Addrs()
		if err != nil {
			fmt.Println("Error al obtener las direcciones IP de la interfaz:", err)
			continue
		}

		// Iterar sobre las direcciones IP
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// Verificar si la dirección IP es IPv4 o IPv6
			if ip.To4() != nil {
				fmt.Println("IPv4:", ip.String())
			} else if ip.To16() != nil {
				fmt.Println("IPv6:", ip.String())
			}
		}
	}
}
