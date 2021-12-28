package main

import (
	"context"
	"fmt"
	"github.com/go-redis/redis/v8"
	"golang.org/x/net/dns/dnsmessage"
	"gopkg.in/yaml.v2"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const maxBufferSize = 512

var currentConfig Config
var privateDomains map[string][4]byte
var redisCli *redis.Client
var ctx = context.Background()
var unresolvedAddr = [4]byte{0, 0, 0, 0}

type Config struct {
	Server struct {
		ExternalDNS string   `yaml:"external_dns"`
		ListenAddr  string   `yaml:"listen_addr"`
		ListenPort  int      `yaml:"listen_port"`
		AllowedIps  []string `yaml:"allowed_ips"`
	}
	Cache struct {
		RedisHost  string        `yaml:"redis_host"`
		Password   string        `yaml:"password"`
		DataBase   int           `yaml:"database"`
		MaxRetries int           `yaml:"max_retries"`
		TimeoutSec time.Duration `yaml:"timeout_sec"`
	}
	NSZones map[string]map[string]string `yaml:"private_domains"`
}

func newAResource(query dnsmessage.Name, a [4]byte) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  query,
			Class: dnsmessage.ClassINET,
			TTL:   600,
		},
		Body: &dnsmessage.AResource{
			A: a,
		},
	}
}

func isAllowedIp(ipAddr *net.UDPAddr) bool {
	for _, cidr := range currentConfig.Server.AllowedIps {
		_, allowedNet, _ := net.ParseCIDR(cidr)
		if allowedNet == nil {
			if cidr == ipAddr.IP.String() {
				return true
			}
		} else if allowedNet.Contains(ipAddr.IP) {
			return true
		}
	}
	return false
}

func isPrivateHost(name string) bool {
	if _, ok := privateDomains[name]; ok {
		return true
	}
	return false
}

func ipToBytes(ipAddr string) [4]byte {
	var byteIpAddr [4]byte
	for i, o := range strings.Split(ipAddr, ".") {
		resOct, err := strconv.Atoi(o)
		if err != nil {
			resOct = 0
		}
		byteIpAddr[i] = byte(resOct)
	}
	return byteIpAddr
}

func bytesToIp(bytes [4]byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", int(bytes[0]), int(bytes[1]), int(bytes[2]), int(bytes[3]))
}

// check query in external dns-server
func externalDNSCheck(req []byte) [4]byte {
	// prepare connection to external dns
	buf := make([]byte, maxBufferSize)
	dst := net.UDPAddr{IP: net.ParseIP(currentConfig.Server.ExternalDNS), Port: 53}
	conn, err := net.DialUDP("udp", nil, &dst)
	defer conn.Close()
	// proxy-pass question
	conn.Write(req)

	// parse answer
	conn.ReadFromUDP(buf)
	var dnsMsg dnsmessage.Parser
	_, err = dnsMsg.Start(buf)
	if err != nil {
		log.Println("can't decode response from external dns")
	}
	// move cursor to answers
	dnsMsg.SkipAllQuestions()
	// find answer with A type and return
	for {
		h, err := dnsMsg.AnswerHeader()
		if err != nil {
			break
		}
		if h.Type != dnsmessage.TypeA || h.Class != dnsmessage.ClassINET {
			continue
		}
		switch h.Type {
		case dnsmessage.TypeA:
			r, err := dnsMsg.AResource()
			if err != nil {
				continue
			}
			return r.A
		default:
			continue
		}
	}
	return unresolvedAddr
}

func ServeDNS(addr *net.UDPAddr, conn *net.UDPConn, msg dnsmessage.Message, rawMsg []byte) {
	var resolvedAddr [4]byte
	// prepare data
	if len(msg.Questions) < 1 {
		return
	}

	question := msg.Questions[0]
	if question.Type != dnsmessage.TypeA {
		log.Printf("unsupported dns request type %s", question.Type.String())
		return
	}
	var resource dnsmessage.Resource
	var (
		queryNameStr = question.Name.String()
		queryName, _ = dnsmessage.NewName(queryNameStr)
	)

	// check in cache
	if redisCli != nil {
		cacheRes, err := redisCli.Get(ctx, queryNameStr).Result()
		if err == nil && cacheRes != "" {
			resource = newAResource(queryName, ipToBytes(cacheRes))
			sendResult(addr, conn, msg, resource)
			return
		}
	}

	// if host not in private list send data from external dns
	if !isPrivateHost(queryNameStr) {
		extResp := externalDNSCheck(rawMsg)
		if extResp != unresolvedAddr {
			resolvedAddr = extResp
		}
	} else {
		resolvedAddr = privateDomains[queryNameStr]
	}
	// send data from internal list
	resource = newAResource(queryName, resolvedAddr)
	sendResult(addr, conn, msg, resource)
	// store data to cache
	if redisCli != nil {
		redisCli.Set(ctx, queryNameStr, bytesToIp(resolvedAddr), 12*time.Hour)
	}
	return
}

func sendResult(addr *net.UDPAddr, conn *net.UDPConn, msg dnsmessage.Message, resource dnsmessage.Resource) {
	// send answer
	msg.Response = true
	msg.Answers = append(msg.Answers, resource)
	packed, err := msg.Pack()
	if err != nil {
		log.Println(err)
		return
	}
	if _, err = conn.WriteToUDP(packed, addr); err != nil {
		log.Println(err)
	}
	return
}

func main() {
	f, err := os.Open("config.yaml")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&currentConfig)
	if err != nil {
		panic(err)
	}
	log.Printf("Server config: \n Listen addr: %s:%d\n External DNS: %s \n",
		currentConfig.Server.ListenAddr, currentConfig.Server.ListenPort, currentConfig.Server.ExternalDNS)

	if currentConfig.Cache.RedisHost != "" {
		log.Println("Connect to cache server...")
		redisCli = redis.NewClient(&redis.Options{
			Addr:        currentConfig.Cache.RedisHost,
			Password:    currentConfig.Cache.Password,
			DB:          currentConfig.Cache.DataBase,
			MaxRetries:  currentConfig.Cache.MaxRetries,
			DialTimeout: currentConfig.Cache.TimeoutSec * time.Second,
			ReadTimeout: currentConfig.Cache.TimeoutSec * time.Second,
		})
	}
	newPrivDomains := make(map[string][4]byte)

	for zName, zHosts := range currentConfig.NSZones {
		for hName, hAddr := range zHosts {
			newPrivDomains[fmt.Sprintf("%s.%s.", hName, zName)] = ipToBytes(hAddr)
		}
	}
	privateDomains = newPrivDomains
	privDomainsInfo := "Private domains: \n"
	for k, _ := range newPrivDomains {
		privDomainsInfo += fmt.Sprintf(" %s\n", k)
	}
	log.Print(privDomainsInfo)
	log.Println("Starting DNS server...")
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: currentConfig.Server.ListenPort, IP: net.ParseIP(currentConfig.Server.ListenAddr)})
	if err != nil {
		panic(err)
	}
	log.Println("DNS was started")
	for {
		buf := make([]byte, maxBufferSize)
		n, addr, _ := conn.ReadFromUDP(buf)
		if !isAllowedIp(addr) {
			conn.WriteToUDP(buf, addr)
			continue
		}

		var dnsMsg dnsmessage.Message
		if err = dnsMsg.Unpack(buf); err != nil {
			log.Println(err)
			continue
		}
		go ServeDNS(addr, conn, dnsMsg, buf[:n])
	}
}
