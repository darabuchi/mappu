package main

import (
	"fmt"
	"github.com/darabuchi/enputi/utils"
	"github.com/eddieivan01/nic"
	"github.com/elliotchance/pie/pie"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	baseDir := filepath.Join(utils.GetConfigDir(), "rule")
	if !utils.FileExists(baseDir) {
		err := os.MkdirAll(baseDir, 0777)
		if err != nil {
			log.Errorf("err:%v", err)
			return
		}
	}

	out := map[string]pie.Strings{}
	existMap := map[string]bool{}

	clashMap := map[NetType]pie.Strings{}

	add := func(s string, ruleType RuleType, netType NetType) {
		if existMap[s] {
			return
		}

		defer func() {
			existMap[s] = true
		}()

		out[fmt.Sprintf("%s_%s", netType, ruleType)] = append(out[fmt.Sprintf("%s_%s", netType, ruleType)], s)

		subconverter := func() string {
			switch ruleType {
			case RuleTypeDomain:
				if strings.Contains(s, ".") {
					return "DOMAIN-SUFFIX," + s
				} else {
					return "DOMAIN," + s
				}

			case RuleTypeCIDR:
				ip, _, err := net.ParseCIDR(s)
				if err != nil {
					log.Errorf("err:%v", err)
					return ""
				}

				if ip.To4() != nil {
					return "IP-CIDR," + s + ",no-resolve"
				}
				return "IP-CIDR6," + s + ",no-resolve"
			case RuleTypeProcessName:
				return "PROCESS-NAME," + s
			default:
				return ""
			}
		}

		clashMap[netType] = append(clashMap[netType], subconverter())
	}

	for _, val := range ruleConfigList {
		switch val.Type {
		case RuleConfigTypeList:
			pie.Strings(strings.Split(getOrUpdateRule(val.FileUrl), "\n")).
				Each(func(domain string) {
					add(domain, val.RuleType, val.NetType)
				})
		case RuleConfigTypeRuleProvider:
			var data struct {
				Payload []string `json:"payload" yaml:"payload" bson:"payload" xml:"payload"`
			}

			err := yaml.Unmarshal([]byte(getOrUpdateRule(val.FileUrl)), &data)
			if err != nil {
				log.Errorf("err:%v", err)
				continue
			}

			pie.Strings(data.Payload).Each(func(payload string) {
				payload = strings.TrimPrefix(payload, "+.")

				add(payload, val.RuleType, val.NetType)
			})

		case RuleConfigTypeRuleProviderCIDR:
			var data struct {
				Payload []string `json:"payload" yaml:"payload" bson:"payload" xml:"payload"`
			}

			err := yaml.Unmarshal([]byte(getOrUpdateRule(val.FileUrl)), &data)
			if err != nil {
				log.Errorf("err:%v", err)
				continue
			}

			pie.Strings(data.Payload).Each(func(payload string) {
				add(payload, val.RuleType, val.NetType)
			})
		}
	}

	for fileName, data := range out {
		err := utils.FileWrite(fileName+".txt", data.FilterNot(func(s string) bool {
			return s == ""
		}).Sort().Join("\n"))
		if err != nil {
			log.Errorf("err:%v", err)
			continue
		}
	}

	for fileName, data := range clashMap {
		err := utils.FileWrite("clash/"+string(fileName)+".txt", data.FilterNot(func(s string) bool {
			return s == ""
		}).Sort().Join("\n"))
		if err != nil {
			log.Errorf("err:%v", err)
			continue
		}
	}
}

type RuleConfigType int

const (
	RuleConfigTypeList RuleConfigType = iota
	RuleConfigTypeRuleProvider
	RuleConfigTypeRuleProviderCIDR
)

type NetType string

const (
	NetTypeDirect  NetType = "Direct"
	NetTypeProxy   NetType = "Proxy"
	NetTypeAdBlock NetType = "AdBlock"
	NetTypePrivacy NetType = "Privacy"
)

type RuleConfig struct {
	Type     RuleConfigType
	FileUrl  string
	NetType  NetType
	RuleType RuleType
}

type RuleType string

const (
	RuleTypeDomain      RuleType = "Domain"
	RuleTypeCIDR        RuleType = "IpCidr"
	RuleTypeProcessName RuleType = "ProcessName"
)

var ruleConfigList = []RuleConfig{
	{
		Type:     RuleConfigTypeList,
		FileUrl:  "https://raw.githubusercontent.com/darabuchi/mappu/master/serufu/Direct_DomainSuffix.txt",
		RuleType: RuleTypeDomain,
		NetType:  NetTypeDirect,
	},
	{
		Type:     RuleConfigTypeList,
		FileUrl:  "https://raw.githubusercontent.com/darabuchi/mappu/master/serufu/Proxy_DomainSuffix.txt",
		RuleType: RuleTypeDomain,
		NetType:  NetTypeProxy,
	},
	{
		Type:     RuleConfigTypeList,
		FileUrl:  "https://raw.githubusercontent.com/cobaltdisco/Google-Chinese-Results-Blocklist/master/GHHbD_perma_ban_list.txt",
		RuleType: RuleTypeDomain,
		NetType:  NetTypeAdBlock,
	},
	{
		Type:     RuleConfigTypeList,
		FileUrl:  "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/reject-list.txt",
		RuleType: RuleTypeDomain,
		NetType:  NetTypeAdBlock,
	},
	{
		Type:     RuleConfigTypeRuleProviderCIDR,
		FileUrl:  "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/telegramcidr.txt",
		RuleType: RuleTypeCIDR,
		NetType:  NetTypeProxy,
	},
	{
		Type:     RuleConfigTypeRuleProvider,
		FileUrl:  "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/google.txt",
		RuleType: RuleTypeDomain,
		NetType:  NetTypeProxy,
	},
	{
		Type:     RuleConfigTypeList,
		FileUrl:  "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/proxy-list.txt",
		RuleType: RuleTypeDomain,
		NetType:  NetTypeProxy,
	},
	{
		Type:     RuleConfigTypeRuleProvider,
		FileUrl:  "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/greatfire.txt",
		RuleType: RuleTypeDomain,
		NetType:  NetTypeProxy,
	},
	{
		Type:     RuleConfigTypeList,
		FileUrl:  "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/greatfire.txt",
		RuleType: RuleTypeDomain,
		NetType:  NetTypeProxy,
	},
	{
		Type:     RuleConfigTypeList,
		FileUrl:  "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt",
		RuleType: RuleTypeDomain,
		NetType:  NetTypeProxy,
	},
	{
		Type:     RuleConfigTypeList,
		FileUrl:  "https://raw.githubusercontent.com/Loyalsoldier/cn-blocked-domain/release/domains.txt",
		RuleType: RuleTypeDomain,
		NetType:  NetTypeProxy,
	},
	{
		Type:     RuleConfigTypeList,
		FileUrl:  "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt",
		RuleType: RuleTypeDomain,
		NetType:  NetTypeDirect,
	},
	{
		Type:     RuleConfigTypeList,
		FileUrl:  "https://raw.githubusercontent.com/Hackl0us/GeoIP2-CN/release/CN-ip-cidr.txt",
		RuleType: RuleTypeCIDR,
		NetType:  NetTypeDirect,
	},
	{
		Type:     RuleConfigTypeList,
		FileUrl:  "https://raw.githubusercontent.com/metowolf/iplist/master/data/special/china.txt",
		RuleType: RuleTypeCIDR,
		NetType:  NetTypeDirect,
	},
	{
		Type:     RuleConfigTypeRuleProviderCIDR,
		FileUrl:  "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/lancidr.txt",
		RuleType: RuleTypeCIDR,
		NetType:  NetTypeDirect,
	},
	{
		Type:     RuleConfigTypeList,
		FileUrl:  "https://raw.githubusercontent.com/darabuchi/mappu/master/serufu/Direct_ProcessName.txt",
		RuleType: RuleTypeProcessName,
		NetType:  NetTypeDirect,
	},
	{
		Type:     RuleConfigTypeList,
		FileUrl:  "https://raw.githubusercontent.com/darabuchi/mappu/master/serufu/Proxy_ProcessName.txt",
		RuleType: RuleTypeProcessName,
		NetType:  NetTypeProxy,
	},
}

//https://raw.githubusercontent.com/Loyalsoldier/cn-blocked-domain/release/ip.txt
// 封锁的ip清单

func getOrUpdateRule(fileUrl string) string {
	resp, err := nic.Get(fileUrl, nic.H{
		AllowRedirect: true,
		Timeout:       60,
		Chunked:       true,
		SkipVerifyTLS: true,
	})
	if err != nil {
		log.Errorf("err:%v", err)
		return ""
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return resp.Text
	default:
		return ""
	}
}
