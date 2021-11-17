package main

import (
	"fmt"
	"github.com/darabuchi/utils"
	"github.com/eddieivan01/nic"
	"github.com/elliotchance/pie/pie"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type RuleConfigInfo struct {
	RuleType RuleType
	NetType  NetType

	Data pie.Strings
}

func main() {
	baseDir := filepath.Join(utils.GetConfigDir(), "rule")
	if !utils.FileExists(baseDir) {
		err := os.MkdirAll(baseDir, 0777)
		if err != nil {
			log.Errorf("err:%v", err)
			return
		}
	}

	existMap := map[string]bool{}

	ruleMap := map[string]*RuleConfigInfo{}

	add := func(s string, ruleType RuleType, netType NetType) {
		if existMap[s] {
			return
		}

		defer func() {
			existMap[s] = true
		}()

		ruleKey := fmt.Sprintf("%s_%s", netType, ruleType)

		if _, ok := ruleMap[ruleKey]; !ok {
			ruleMap[ruleKey] = &RuleConfigInfo{
				RuleType: ruleType,
				NetType:  netType,
				Data:     []string{},
			}
		}

		ruleMap[ruleKey].Data = append(ruleMap[ruleKey].Data, s)
	}

	// 整理原始数据到内部的数据格式
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

	// 做数据合并和数据压缩
	for _, ruleInfo := range ruleMap {
		if ruleInfo.RuleType == RuleTypeCIDR {
			data, err := utils.MergeCIDRs(ruleInfo.Data)
			if err != nil {
				log.Errorf("err:%v", err)
			} else {
				ruleInfo.Data = data
			}
		}
	}

	// 正常的数据数据
	{

		for _, ruleInfo := range ruleMap {
			fileName := fmt.Sprintf("%s_%s.txt", ruleInfo.NetType, ruleInfo.RuleType)
			err := utils.FileWrite(
				fileName,
				ruleInfo.Data.
					FilterNot(func(s string) bool {
						return s == ""
					}).Sort().Join("\n"),
			)
			if err != nil {
				log.Errorf("err:%v", err)
				continue
			}
		}
	}

	// clash的数据
	{

		err := filepath.WalkDir("clash", func(path string, d fs.DirEntry, err error) error {
			if filepath.Ext(path) != ".txt" {
				return nil
			}

			err = os.Remove(path)
			if err != nil {
				log.Errorf("err:%v", err)
				return err
			}

			return nil
		})
		if err != nil {
			log.Errorf("err:%v", err)
			return
		}

		for _, ruleInfo := range ruleMap {
			fileName := fmt.Sprintf("clash/%s.txt", ruleInfo.NetType)

			var data pie.Strings

			switch ruleInfo.RuleType {
			case RuleTypeDomain:
				ruleInfo.Data.Each(func(s string) {
					if strings.Contains(s, ".") {
						data = append(data, "DOMAIN-SUFFIX,"+s)
					} else {
						data = append(data, "DOMAIN,"+s)
					}
				})

			case RuleTypeCIDR:
				ruleInfo.Data.Each(func(s string) {
					ip, _, err := net.ParseCIDR(s)
					if err != nil {
						log.Errorf("err:%v", err)
					} else if ip.To4() != nil {
						data = append(data, "IP-CIDR,"+s)
					} else if ip.To16() != nil {
						data = append(data, "IP-CIDR6,"+s)
					}
				})
			case RuleTypeProcessName:
				ruleInfo.Data.Each(func(s string) {
					data = append(data, "PROCESS-NAME,"+s)
				})
			default:
				ruleInfo.Data.Each(func(s string) {
					data = append(data, string(ruleInfo.RuleType)+","+s)
				})
			}

			err = utils.FileAppend(
				fileName,
				data.FilterNot(func(s string) bool {
					return s == ""
				}).Sort().Join("\n")+"\n",
			)
			if err != nil {
				log.Errorf("err:%v", err)
				continue
			}
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
		FileUrl:  "https://raw.githubusercontent.com/darabuchi/mappu/master/serufu/Direct_Domain.txt",
		RuleType: RuleTypeDomain,
		NetType:  NetTypeDirect,
	},
	{
		Type:     RuleConfigTypeList,
		FileUrl:  "https://raw.githubusercontent.com/darabuchi/mappu/master/serufu/Proxy_Domain.txt",
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
		Proxy:         "socket5://127.0.0.1:7890",
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
