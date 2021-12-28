package main

import (
	"bufio"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"gopkg.in/yaml.v2"
	"log"
	"net"
	"os"
)

const maxBufferSize = 2048

type Config struct {
	Server struct {
		ExternalDNS string `yaml:"external_dns"`
		ListenAddr  string `yaml:"listen_addr"`
		ListenPort  int    `yaml:"listen_port"`
	}
}

func externalDNSCheck(req []byte, extDNS string) []byte {
	p := make([]byte, maxBufferSize)
	conn, err := net.Dial("udp", extDNS)
	if err != nil {
		log.Println(err)
		return nil
	}
	_, err = conn.Write(req)
	if err != nil {
		log.Println(err)
		return nil
	}

	n, err := bufio.NewReader(conn).Read(p)
	if err != nil {
		log.Println(err)
		return nil
	}
	conn.Close()
	return p[:n]
}

func internalDNS(extDNS string, localPort int, localAddr string) {
	buf := make([]byte, maxBufferSize)
	addr := net.UDPAddr{Port: localPort, IP: net.ParseIP(localAddr)}
	lis, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Panic(err)
		return
	}
	for {
		n, rAddr, err := lis.ReadFrom(buf)
		if err != nil {
			log.Println(err)
			continue
		}

		req := buf[:n]
		var dnsReq dnsmessage.Parser
		h, err := dnsReq.Start(req)
		if err != nil {
			log.Println(err)
			return
		}
		q, err := dnsReq.Question()
		if err != nil {
			log.Println(err)
			return
		}
		log.Println("Recv data ", h, q)
		extResp := externalDNSCheck(req, fmt.Sprintf("%s:53", extDNS))
		if extResp != nil {
			_, err := lis.WriteTo(extResp, rAddr)
			if err != nil {
				log.Println(err)
			}
		}
	}
}

func main() {
	f, err := os.Open("config.yaml")
	if err != nil {
		log.Panic(err)
		return
	}
	defer f.Close()
	var cfg Config
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&cfg)
	if err != nil {
		log.Panic(err)
		return
	}

	internalDNS(cfg.Server.ExternalDNS, cfg.Server.ListenPort, cfg.Server.ListenAddr)
}
