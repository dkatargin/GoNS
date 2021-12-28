package main

import (
	"bufio"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"gopkg.in/yaml.v2"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

const maxBufferSize = 512

var privateDomains map[string][4]byte

type Config struct {
	Server struct {
		ExternalDNS string   `yaml:"external_dns"`
		ListenAddr  string   `yaml:"listen_addr"`
		ListenPort  int      `yaml:"listen_port"`
		AllowedIps  []string `yaml:"allowed_ips"`
	}
	NSZones map[string]map[string]string `yaml:"private_domains"`
}

var CurrentConfig Config

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
	for _, cidr := range CurrentConfig.Server.AllowedIps {
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

// check query in external dns-server
func externalDNSCheck(req []byte) []byte {
	buf := make([]byte, maxBufferSize)

	conn, err := net.Dial("udp", fmt.Sprintf("%s:53", CurrentConfig.Server.ExternalDNS))
	defer conn.Close()

	if err != nil {
		log.Println(err)
		return nil
	}
	_, err = conn.Write(req)
	if err != nil {
		log.Println(err)
		return nil
	}

	n, err := bufio.NewReader(conn).Read(buf)
	if err != nil {
		log.Println(err)
		return nil
	}

	return buf[:n]
}

func ServeDNS(addr *net.UDPAddr, conn *net.UDPConn, msg dnsmessage.Message, rawMsg []byte) {
	// prepare data
	if len(msg.Questions) < 1 {
		return
	}
	question := msg.Questions[0]
	var (
		queryTypeStr = question.Type.String()
		queryNameStr = question.Name.String()
		queryType    = question.Type
		queryName, _ = dnsmessage.NewName(queryNameStr)
	)
	// check if host in private list
	if !isPrivateHost(queryNameStr) {
		extResp := externalDNSCheck(rawMsg)
		if extResp != nil {
			_, err := conn.WriteTo(extResp, addr)
			if err != nil {
				log.Println(err)
			}
		}
		return
	}
	// check request type
	var resource dnsmessage.Resource
	switch queryType {
	case dnsmessage.TypeA:
		resource = newAResource(queryName, privateDomains[queryNameStr])
	default:
		log.Printf("unsupported dns request type %s", queryTypeStr)
		return
	}
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
	err = decoder.Decode(&CurrentConfig)
	if err != nil {
		panic(err)
	}
	log.Printf("Server config: \n Listen addr: %s:%d\n External DNS: %s \n",
		CurrentConfig.Server.ListenAddr, CurrentConfig.Server.ListenPort, CurrentConfig.Server.ExternalDNS)
	newPrivDomains := make(map[string][4]byte)
	var byteIpAddr [4]byte
	for zName, zHosts := range CurrentConfig.NSZones {
		for hName, hAddr := range zHosts {
			for i, o := range strings.Split(hAddr, ".") {
				resOct, err := strconv.Atoi(o)
				if err != nil {
					resOct = 0
				}
				byteIpAddr[i] = byte(resOct)
			}
			newPrivDomains[fmt.Sprintf("%s.%s.", hName, zName)] = byteIpAddr
		}
	}
	privateDomains = newPrivDomains
	privDomainsInfo := "Private domains: \n"
	for k, _ := range newPrivDomains {
		privDomainsInfo += fmt.Sprintf(" %s\n", k)
	}
	log.Print(privDomainsInfo)
	log.Println("Starting DNS server...")
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: CurrentConfig.Server.ListenPort, IP: net.ParseIP(CurrentConfig.Server.ListenAddr)})
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
