package main

import (
	"fmt"
	"github.com/darabuchi/enputi/utils"
	"github.com/eddieivan01/nic"
	"github.com/elliotchance/pie/pie"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
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

	add := func(s string, ruleType RuleType, netType NetType) {
		if existMap[s] {
			return
		}

		defer func() {
			existMap[s] = true
		}()

		out[fmt.Sprintf("%s_%s", netType, ruleType)] = append(out[fmt.Sprintf("%s_%s", netType, ruleType)], s)
	}

	for _, val := range ruleConfigList {
		switch val.Type {
		case RuleConfigTypeDomainTxt:
			pie.Strings(strings.Split(getOrUpdateRule(val.FileUrl), "\n")).Each(func(domain string) {
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
		err := utils.FileWrite(fileName+".txt", data.Sort().Join("\n"))
		if err != nil {
			log.Errorf("err:%v", err)
			continue
		}
	}
}

type RuleConfigType int

const (
	RuleConfigTypeDomainTxt RuleConfigType = iota
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
	RuleTypeDomainSuffix RuleType = "DomainSuffix"
	RuleTypeCIDR         RuleType = "IpCidr"
)

var ruleConfigList = []RuleConfig{
	{
		Type:     RuleConfigTypeDomainTxt,
		FileUrl:  "https://raw.githubusercontent.com/darabuchi/mappu/master/serufu/Direct_DomainSuffix.txt",
		RuleType: RuleTypeDomainSuffix,
		NetType:  NetTypeDirect,
	},
	{
		Type:     RuleConfigTypeDomainTxt,
		FileUrl:  "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/reject-list.txt",
		RuleType: RuleTypeDomainSuffix,
		NetType:  NetTypeAdBlock,
	},
	{
		Type:     RuleConfigTypeRuleProviderCIDR,
		FileUrl:  "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/telegramcidr.txt",
		RuleType: RuleTypeCIDR,
		NetType:  NetTypeProxy,
	},
	{
		Type:     RuleConfigTypeRuleProvider,
		FileUrl:  "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/google.txt",
		RuleType: RuleTypeDomainSuffix,
		NetType:  NetTypeProxy,
	},
	{
		Type:     RuleConfigTypeDomainTxt,
		FileUrl:  "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/proxy-list.txt",
		RuleType: RuleTypeDomainSuffix,
		NetType:  NetTypeProxy,
	},
	{
		Type:     RuleConfigTypeRuleProvider,
		FileUrl:  "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/greatfire.txt",
		RuleType: RuleTypeDomainSuffix,
		NetType:  NetTypeProxy,
	},
	{
		Type:     RuleConfigTypeDomainTxt,
		FileUrl:  "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/greatfire.txt",
		RuleType: RuleTypeDomainSuffix,
		NetType:  NetTypeProxy,
	},
	{
		Type:     RuleConfigTypeDomainTxt,
		FileUrl:  "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/gfw.txt",
		RuleType: RuleTypeDomainSuffix,
		NetType:  NetTypeProxy,
	},
	{
		Type:     RuleConfigTypeDomainTxt,
		FileUrl:  "https://cdn.jsdelivr.net/gh/Loyalsoldier/cn-blocked-domain@release/domains.txt",
		RuleType: RuleTypeDomainSuffix,
		NetType:  NetTypeProxy,
	},
	{
		Type:     RuleConfigTypeDomainTxt,
		FileUrl:  "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/direct-list.txt",
		RuleType: RuleTypeDomainSuffix,
		NetType:  NetTypeDirect,
	},
	{
		Type:     RuleConfigTypeDomainTxt,
		FileUrl:  "https://cdn.jsdelivr.net/gh/Hackl0us/GeoIP2-CN@release/CN-ip-cidr.txt",
		RuleType: RuleTypeCIDR,
		NetType:  NetTypeDirect,
	},
	{
		Type:     RuleConfigTypeDomainTxt,
		FileUrl:  "https://raw.githubusercontent.com/metowolf/iplist/master/data/special/china.txt",
		RuleType: RuleTypeCIDR,
		NetType:  NetTypeDirect,
	},
	{
		Type:     RuleConfigTypeDomainTxt,
		FileUrl:  "https://cdn.jsdelivr.net/gh/17mon/china_ip_list@master/china_ip_list.txt",
		RuleType: RuleTypeCIDR,
		NetType:  NetTypeDirect,
	},
	{
		Type:     RuleConfigTypeRuleProviderCIDR,
		FileUrl:  "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt",
		RuleType: RuleTypeCIDR,
		NetType:  NetTypeDirect,
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
