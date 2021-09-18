package main

import (
	"fmt"
	"github.com/darabuchi/enputi/utils"
	"github.com/elliotchance/pie/pie"
	"github.com/roylee0704/gron/xtime"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
	"time"
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
			pie.Strings(strings.Split(getOrUpdateRule(val.FileName, val.FileUrl, false), "\n")).Each(func(domain string) {
				add(domain, val.RuleType, val.NetType)
			})
		case RuleConfigTypeRuleProvider:
			var data struct {
				Payload []string `json:"payload" yaml:"payload" bson:"payload" xml:"payload"`
			}

			err := yaml.Unmarshal([]byte(getOrUpdateRule(val.FileName, val.FileUrl, false)), &data)
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

			err := yaml.Unmarshal([]byte(getOrUpdateRule(val.FileName, val.FileUrl, false)), &data)
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
	FileName string
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
		FileUrl:  "https://cdn.jsdelivr.net/gh/darabuchi/mappu@master/serufu/Direct_DomainSuffix.txt",
		FileName: "mappu-direct-domain-suffix.txt",
		RuleType: RuleTypeDomainSuffix,
		NetType:  NetTypeDirect,
	},
	{
		Type:     RuleConfigTypeDomainTxt,
		FileUrl:  "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/reject-list.txt",
		FileName: "reject-list.txt",
		RuleType: RuleTypeDomainSuffix,
		NetType:  NetTypeAdBlock,
	},
	{
		Type:     RuleConfigTypeRuleProviderCIDR,
		FileUrl:  "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/telegramcidr.txt",
		FileName: "telegramcidr.yaml",
		RuleType: RuleTypeCIDR,
		NetType:  NetTypeProxy,
	},
	{
		Type:     RuleConfigTypeRuleProvider,
		FileUrl:  "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/google.txt",
		FileName: "google.txt",
		RuleType: RuleTypeDomainSuffix,
		NetType:  NetTypeProxy,
	},
	{
		Type:     RuleConfigTypeDomainTxt,
		FileUrl:  "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/proxy-list.txt",
		FileName: "proxy-list.txt",
		RuleType: RuleTypeDomainSuffix,
		NetType:  NetTypeProxy,
	},
	{
		Type:     RuleConfigTypeRuleProvider,
		FileUrl:  "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/greatfire.txt",
		FileName: "greatfir-clash-rulese.txt",
		RuleType: RuleTypeDomainSuffix,
		NetType:  NetTypeProxy,
	},
	{
		Type:     RuleConfigTypeDomainTxt,
		FileUrl:  "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/greatfire.txt",
		FileName: "greatfire-v2ray-rules-dat.txt",
		RuleType: RuleTypeDomainSuffix,
		NetType:  NetTypeProxy,
	},
	{
		Type:     RuleConfigTypeDomainTxt,
		FileUrl:  "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/gfw.txt",
		FileName: "gfw.txt",
		RuleType: RuleTypeDomainSuffix,
		NetType:  NetTypeProxy,
	},
	{
		Type:     RuleConfigTypeDomainTxt,
		FileUrl:  "https://cdn.jsdelivr.net/gh/Loyalsoldier/cn-blocked-domain@release/domains.txt",
		FileName: "domains.txt",
		RuleType: RuleTypeDomainSuffix,
		NetType:  NetTypeProxy,
	},
	{
		Type:     RuleConfigTypeDomainTxt,
		FileUrl:  "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/direct-list.txt",
		FileName: "direct-list.txt",
		RuleType: RuleTypeDomainSuffix,
		NetType:  NetTypeDirect,
	},
	{
		Type:     RuleConfigTypeDomainTxt,
		FileUrl:  "https://cdn.jsdelivr.net/gh/Hackl0us/GeoIP2-CN@release/CN-ip-cidr.txt",
		FileName: "CN-ip-cidr.txt",
		RuleType: RuleTypeCIDR,
		NetType:  NetTypeDirect,
	},
	{
		Type:     RuleConfigTypeDomainTxt,
		FileUrl:  "https://cdn.jsdelivr.net/gh/17mon/china_ip_list@master/china_ip_list.txt",
		FileName: "china_ip_list.txt",
		RuleType: RuleTypeCIDR,
		NetType:  NetTypeDirect,
	},
	{
		Type:     RuleConfigTypeRuleProviderCIDR,
		FileUrl:  "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt",
		FileName: "lancidr.txt",
		RuleType: RuleTypeCIDR,
		NetType:  NetTypeDirect,
	},
}

//https://raw.githubusercontent.com/Loyalsoldier/cn-blocked-domain/release/ip.txt
// 封锁的ip清单

func getOrUpdateRule(fileName string, url string, skipDownload bool) string {
	filePath := filepath.Join(utils.GetConfigDir(), "rule", fileName)
	if !skipDownload && !utils.FileExists(filePath) || time.Since(utils.GetFileModTime(filePath)) > xtime.Day {
		err := utils.DownloadWithProgressbar(url, filePath)
		if err != nil {
			log.Errorf("err:%v", err)
		}
	}

	buf, err := utils.FileRead(filePath)
	if err != nil {
		log.Errorf("err:%v", err)
		return ""
	}

	return buf
}
