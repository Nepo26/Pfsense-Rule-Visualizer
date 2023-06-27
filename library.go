package main

import "encoding/xml"
type Pfsense struct {
	XMLName    xml.Name `xml:"pfsense"`
	Text       string   `xml:",chardata"`
	Version    string   `xml:"version"`
	Lastchange string   `xml:"lastchange"`
	System     struct {
		Text         string `xml:",chardata"`
		Optimization string `xml:"optimization"`
		Hostname     string `xml:"hostname"`
		Domain       string `xml:"domain"`
		Group        []struct {
			Text        string   `xml:",chardata"`
			Name        string   `xml:"name"`
			Description string   `xml:"description"`
			Scope       string   `xml:"scope"`
			Gid         string   `xml:"gid"`
			Priv        []string `xml:"priv"`
			Member      string   `xml:"member"`
		} `xml:"group"`
		User []struct {
			Text             string `xml:",chardata"`
			Name             string `xml:"name"`
			Descr            string `xml:"descr"`
			Scope            string `xml:"scope"`
			Groupname        string `xml:"groupname"`
			BcryptHash       string `xml:"bcrypt-hash"`
			Uid              string `xml:"uid"`
			Priv             string `xml:"priv"`
			Expires          string `xml:"expires"`
			Dashboardcolumns string `xml:"dashboardcolumns"`
			Authorizedkeys   string `xml:"authorizedkeys"`
			Ipsecpsk         string `xml:"ipsecpsk"`
			Webguicss        string `xml:"webguicss"`
		} `xml:"user"`
		Nextuid     string `xml:"nextuid"`
		Nextgid     string `xml:"nextgid"`
		Timeservers string `xml:"timeservers"`
		Webgui      struct {
			Text                           string `xml:",chardata"`
			Protocol                       string `xml:"protocol"`
			Loginautocomplete              string `xml:"loginautocomplete"`
			SslCertref                     string `xml:"ssl-certref"`
			Port                           string `xml:"port"`
			MaxProcs                       string `xml:"max_procs"`
			Althostnames                   string `xml:"althostnames"`
			Dashboardcolumns               string `xml:"dashboardcolumns"`
			Webguileftcolumnhyper          string `xml:"webguileftcolumnhyper"`
			Dashboardavailablewidgetspanel string `xml:"dashboardavailablewidgetspanel"`
			Systemlogsfilterpanel          string `xml:"systemlogsfilterpanel"`
			Systemlogsmanagelogpanel       string `xml:"systemlogsmanagelogpanel"`
			Statusmonitoringsettingspanel  string `xml:"statusmonitoringsettingspanel"`
			Webguicss                      string `xml:"webguicss"`
			Logincss                       string `xml:"logincss"`
			Loginshowhost                  string `xml:"loginshowhost"`
			Webguifixedmenu                string `xml:"webguifixedmenu"`
			Webguihostnamemenu             string `xml:"webguihostnamemenu"`
			Authmode                       string `xml:"authmode"`
		} `xml:"webgui"`
		Disablesegmentationoffloading string `xml:"disablesegmentationoffloading"`
		Disablelargereceiveoffloading string `xml:"disablelargereceiveoffloading"`
		Ipv6allow                     string `xml:"ipv6allow"`
		Maximumtableentries           string `xml:"maximumtableentries"`
		PowerdAcMode                  string `xml:"powerd_ac_mode"`
		PowerdBatteryMode             string `xml:"powerd_battery_mode"`
		PowerdNormalMode              string `xml:"powerd_normal_mode"`
		Bogons                        struct {
			Text     string `xml:",chardata"`
			Interval string `xml:"interval"`
		} `xml:"bogons"`
		AlreadyRunConfigUpgrade    string `xml:"already_run_config_upgrade"`
		Serialspeed                string `xml:"serialspeed"`
		Primaryconsole             string `xml:"primaryconsole"`
		Language                   string `xml:"language"`
		Timezone                   string `xml:"timezone"`
		Dnsallowoverride           string `xml:"dnsallowoverride"`
		Dns1gw                     string `xml:"dns1gw"`
		Scrubnodf                  string `xml:"scrubnodf"`
		Maximumstates              string `xml:"maximumstates"`
		Aliasesresolveinterval     string `xml:"aliasesresolveinterval"`
		Maximumfrags               string `xml:"maximumfrags"`
		Enablenatreflectionpurenat string `xml:"enablenatreflectionpurenat"`
		Enablebinatreflection      string `xml:"enablebinatreflection"`
		Enablenatreflectionhelper  string `xml:"enablenatreflectionhelper"`
		Reflectiontimeout          string `xml:"reflectiontimeout"`
		Disablechecksumoffloading  string `xml:"disablechecksumoffloading"`
		CryptoHardware             string `xml:"crypto_hardware"`
		ThermalHardware            string `xml:"thermal_hardware"`
		UseMfsTmpSize              string `xml:"use_mfs_tmp_size"`
		UseMfsVarSize              string `xml:"use_mfs_var_size"`
		Authserver                 struct {
			Text                 string `xml:",chardata"`
			Refid                string `xml:"refid"`
			Type                 string `xml:"type"`
			Name                 string `xml:"name"`
			RadiusProtocol       string `xml:"radius_protocol"`
			Host                 string `xml:"host"`
			RadiusNasipAttribute string `xml:"radius_nasip_attribute"`
			RadiusSecret         string `xml:"radius_secret"`
			RadiusTimeout        string `xml:"radius_timeout"`
			RadiusAuthPort       string `xml:"radius_auth_port"`
			RadiusAcctPort       string `xml:"radius_acct_port"`
		} `xml:"authserver"`
		PkgRepoConfPath string `xml:"pkg_repo_conf_path"`
		Ssh             struct {
			Text   string `xml:",chardata"`
			Enable string `xml:"enable"`
			Port   string `xml:"port"`
		} `xml:"ssh"`
		SshguardThreshold     string `xml:"sshguard_threshold"`
		SshguardBlocktime     string `xml:"sshguard_blocktime"`
		SshguardDetectionTime string `xml:"sshguard_detection_time"`
		SshguardWhitelist     string `xml:"sshguard_whitelist"`
		Gitsync               struct {
			Text          string `xml:",chardata"`
			Repositoryurl string `xml:"repositoryurl"`
			Branch        string `xml:"branch"`
		} `xml:"gitsync"`
		HnAltqEnable string `xml:"hn_altq_enable"`
		Acb          string `xml:"acb"`
	} `xml:"system"`
	Interfaces struct {
		Text string `xml:",chardata"`
		Wan  struct {
			Text         string `xml:",chardata"`
			If           string `xml:"if"`
			Descr        string `xml:"descr"`
			AliasAddress string `xml:"alias-address"`
			AliasSubnet  string `xml:"alias-subnet"`
			Spoofmac     string `xml:"spoofmac"`
		} `xml:"wan"`
		Lan struct {
			Text     string `xml:",chardata"`
			Descr    string `xml:"descr"`
			If       string `xml:"if"`
			Enable   string `xml:"enable"`
			Spoofmac string `xml:"spoofmac"`
			Ipaddr   string `xml:"ipaddr"`
			Subnet   string `xml:"subnet"`
		} `xml:"lan"`
		Opt1 struct {
			Text     string `xml:",chardata"`
			Descr    string `xml:"descr"`
			If       string `xml:"if"`
			Spoofmac string `xml:"spoofmac"`
			Enable   string `xml:"enable"`
			Ipaddr   string `xml:"ipaddr"`
			Subnet   string `xml:"subnet"`
			Gateway  string `xml:"gateway"`
		} `xml:"opt1"`
		Opt2 struct {
			Text        string `xml:",chardata"`
			Descr       string `xml:"descr"`
			If          string `xml:"if"`
			Spoofmac    string `xml:"spoofmac"`
			Enable      string `xml:"enable"`
			Blockbogons string `xml:"blockbogons"`
			Ipaddr      string `xml:"ipaddr"`
			Subnet      string `xml:"subnet"`
			Gateway     string `xml:"gateway"`
			Blockpriv   string `xml:"blockpriv"`
		} `xml:"opt2"`
		Opt3 struct {
			Text        string `xml:",chardata"`
			Descr       string `xml:"descr"`
			If          string `xml:"if"`
			Spoofmac    string `xml:"spoofmac"`
			Enable      string `xml:"enable"`
			Blockbogons string `xml:"blockbogons"`
			Ipaddr      string `xml:"ipaddr"`
			Blockpriv   string `xml:"blockpriv"`
		} `xml:"opt3"`
		Opt4 struct {
			Text     string `xml:",chardata"`
			Descr    string `xml:"descr"`
			If       string `xml:"if"`
			Enable   string `xml:"enable"`
			Spoofmac string `xml:"spoofmac"`
			Ipaddr   string `xml:"ipaddr"`
			Subnet   string `xml:"subnet"`
		} `xml:"opt4"`
		Opt5 struct {
			Text     string `xml:",chardata"`
			Descr    string `xml:"descr"`
			If       string `xml:"if"`
			Spoofmac string `xml:"spoofmac"`
			Enable   string `xml:"enable"`
			Ipaddr   string `xml:"ipaddr"`
			Subnet   string `xml:"subnet"`
		} `xml:"opt5"`
		Opt6 struct {
			Text     string `xml:",chardata"`
			Descr    string `xml:"descr"`
			If       string `xml:"if"`
			Enable   string `xml:"enable"`
			Spoofmac string `xml:"spoofmac"`
			Ipaddr   string `xml:"ipaddr"`
			Subnet   string `xml:"subnet"`
		} `xml:"opt6"`
		Opt7 struct {
			Text     string `xml:",chardata"`
			Descr    string `xml:"descr"`
			If       string `xml:"if"`
			Enable   string `xml:"enable"`
			Spoofmac string `xml:"spoofmac"`
			Ipaddr   string `xml:"ipaddr"`
			Subnet   string `xml:"subnet"`
		} `xml:"opt7"`
		Opt8 struct {
			Text     string `xml:",chardata"`
			Descr    string `xml:"descr"`
			If       string `xml:"if"`
			Enable   string `xml:"enable"`
			Spoofmac string `xml:"spoofmac"`
		} `xml:"opt8"`
		Opt9 struct {
			Text     string `xml:",chardata"`
			Descr    string `xml:"descr"`
			If       string `xml:"if"`
			Spoofmac string `xml:"spoofmac"`
		} `xml:"opt9"`
		Opt10 struct {
			Text  string `xml:",chardata"`
			Descr string `xml:"descr"`
			If    string `xml:"if"`
		} `xml:"opt10"`
		Opt11 struct {
			Text     string `xml:",chardata"`
			Descr    string `xml:"descr"`
			If       string `xml:"if"`
			Enable   string `xml:"enable"`
			Spoofmac string `xml:"spoofmac"`
		} `xml:"opt11"`
		Opt12 struct {
			Text     string `xml:",chardata"`
			Descr    string `xml:"descr"`
			If       string `xml:"if"`
			Enable   string `xml:"enable"`
			Spoofmac string `xml:"spoofmac"`
		} `xml:"opt12"`
		Opt13 struct {
			Text     string `xml:",chardata"`
			Descr    string `xml:"descr"`
			If       string `xml:"if"`
			Enable   string `xml:"enable"`
			Spoofmac string `xml:"spoofmac"`
		} `xml:"opt13"`
		Opt14 struct {
			Text     string `xml:",chardata"`
			Descr    string `xml:"descr"`
			If       string `xml:"if"`
			Spoofmac string `xml:"spoofmac"`
		} `xml:"opt14"`
		Opt15 struct {
			Text     string `xml:",chardata"`
			Descr    string `xml:"descr"`
			If       string `xml:"if"`
			Enable   string `xml:"enable"`
			Spoofmac string `xml:"spoofmac"`
		} `xml:"opt15"`
		Opt16 struct {
			Text     string `xml:",chardata"`
			Descr    string `xml:"descr"`
			If       string `xml:"if"`
			Enable   string `xml:"enable"`
			Spoofmac string `xml:"spoofmac"`
		} `xml:"opt16"`
	} `xml:"interfaces"`
	Staticroutes struct {
		Text  string `xml:",chardata"`
		Route []struct {
			Text    string `xml:",chardata"`
			Network string `xml:"network"`
			Gateway string `xml:"gateway"`
			Descr   string `xml:"descr"`
		} `xml:"route"`
	} `xml:"staticroutes"`
	Dhcpd struct {
		Text string `xml:",chardata"`
		Opt4 struct {
			Text  string `xml:",chardata"`
			Range struct {
				Text string `xml:",chardata"`
				From string `xml:"from"`
				To   string `xml:"to"`
			} `xml:"range"`
			Enable                 string `xml:"enable"`
			FailoverPeerip         string `xml:"failover_peerip"`
			Defaultleasetime       string `xml:"defaultleasetime"`
			Maxleasetime           string `xml:"maxleasetime"`
			Netmask                string `xml:"netmask"`
			Gateway                string `xml:"gateway"`
			Domain                 string `xml:"domain"`
			Domainsearchlist       string `xml:"domainsearchlist"`
			Ddnsdomain             string `xml:"ddnsdomain"`
			Ddnsdomainprimary      string `xml:"ddnsdomainprimary"`
			Ddnsdomainsecondary    string `xml:"ddnsdomainsecondary"`
			Ddnsdomainkeyname      string `xml:"ddnsdomainkeyname"`
			Ddnsdomainkeyalgorithm string `xml:"ddnsdomainkeyalgorithm"`
			Ddnsdomainkey          string `xml:"ddnsdomainkey"`
			MacAllow               string `xml:"mac_allow"`
			MacDeny                string `xml:"mac_deny"`
			Ddnsclientupdates      string `xml:"ddnsclientupdates"`
			Tftp                   string `xml:"tftp"`
			Ldap                   string `xml:"ldap"`
			Nextserver             string `xml:"nextserver"`
			Filename               string `xml:"filename"`
			Filename32             string `xml:"filename32"`
			Filename64             string `xml:"filename64"`
			Rootpath               string `xml:"rootpath"`
			Numberoptions          string `xml:"numberoptions"`
			Staticmap              []struct {
				Text                   string `xml:",chardata"`
				Mac                    string `xml:"mac"`
				Cid                    string `xml:"cid"`
				Ipaddr                 string `xml:"ipaddr"`
				Hostname               string `xml:"hostname"`
				Descr                  string `xml:"descr"`
				Filename               string `xml:"filename"`
				Rootpath               string `xml:"rootpath"`
				Defaultleasetime       string `xml:"defaultleasetime"`
				Maxleasetime           string `xml:"maxleasetime"`
				Gateway                string `xml:"gateway"`
				Domain                 string `xml:"domain"`
				Domainsearchlist       string `xml:"domainsearchlist"`
				Ddnsdomain             string `xml:"ddnsdomain"`
				Ddnsdomainprimary      string `xml:"ddnsdomainprimary"`
				Ddnsdomainsecondary    string `xml:"ddnsdomainsecondary"`
				Ddnsdomainkeyname      string `xml:"ddnsdomainkeyname"`
				Ddnsdomainkeyalgorithm string `xml:"ddnsdomainkeyalgorithm"`
				Ddnsdomainkey          string `xml:"ddnsdomainkey"`
				Tftp                   string `xml:"tftp"`
				Ldap                   string `xml:"ldap"`
				Nextserver             string `xml:"nextserver"`
				Filename32             string `xml:"filename32"`
				Filename64             string `xml:"filename64"`
				Filename32arm          string `xml:"filename32arm"`
				Filename64arm          string `xml:"filename64arm"`
				Uefihttpboot           string `xml:"uefihttpboot"`
				Numberoptions          string `xml:"numberoptions"`
			} `xml:"staticmap"`
			Dhcpleaseinlocaltime string   `xml:"dhcpleaseinlocaltime"`
			Dnsserver            []string `xml:"dnsserver"`
		} `xml:"opt4"`
		Opt6 struct {
			Text  string `xml:",chardata"`
			Range struct {
				Text string `xml:",chardata"`
				From string `xml:"from"`
				To   string `xml:"to"`
			} `xml:"range"`
			Enable                 string   `xml:"enable"`
			FailoverPeerip         string   `xml:"failover_peerip"`
			Defaultleasetime       string   `xml:"defaultleasetime"`
			Maxleasetime           string   `xml:"maxleasetime"`
			Netmask                string   `xml:"netmask"`
			Dnsserver              []string `xml:"dnsserver"`
			Gateway                string   `xml:"gateway"`
			Domain                 string   `xml:"domain"`
			Domainsearchlist       string   `xml:"domainsearchlist"`
			Ddnsdomain             string   `xml:"ddnsdomain"`
			Ddnsdomainprimary      string   `xml:"ddnsdomainprimary"`
			Ddnsdomainsecondary    string   `xml:"ddnsdomainsecondary"`
			Ddnsdomainkeyname      string   `xml:"ddnsdomainkeyname"`
			Ddnsdomainkeyalgorithm string   `xml:"ddnsdomainkeyalgorithm"`
			Ddnsdomainkey          string   `xml:"ddnsdomainkey"`
			MacAllow               string   `xml:"mac_allow"`
			MacDeny                string   `xml:"mac_deny"`
			Ddnsclientupdates      string   `xml:"ddnsclientupdates"`
			Tftp                   string   `xml:"tftp"`
			Ldap                   string   `xml:"ldap"`
			Nextserver             string   `xml:"nextserver"`
			Filename               string   `xml:"filename"`
			Filename32             string   `xml:"filename32"`
			Filename64             string   `xml:"filename64"`
			Rootpath               string   `xml:"rootpath"`
			Numberoptions          string   `xml:"numberoptions"`
			Dhcpleaseinlocaltime   string   `xml:"dhcpleaseinlocaltime"`
		} `xml:"opt6"`
		Opt7 struct {
			Text  string `xml:",chardata"`
			Range struct {
				Text string `xml:",chardata"`
				From string `xml:"from"`
				To   string `xml:"to"`
			} `xml:"range"`
			Enable                 string   `xml:"enable"`
			FailoverPeerip         string   `xml:"failover_peerip"`
			Defaultleasetime       string   `xml:"defaultleasetime"`
			Maxleasetime           string   `xml:"maxleasetime"`
			Netmask                string   `xml:"netmask"`
			Dnsserver              []string `xml:"dnsserver"`
			Gateway                string   `xml:"gateway"`
			Domain                 string   `xml:"domain"`
			Domainsearchlist       string   `xml:"domainsearchlist"`
			Ddnsdomain             string   `xml:"ddnsdomain"`
			Ddnsdomainprimary      string   `xml:"ddnsdomainprimary"`
			Ddnsdomainsecondary    string   `xml:"ddnsdomainsecondary"`
			Ddnsdomainkeyname      string   `xml:"ddnsdomainkeyname"`
			Ddnsdomainkeyalgorithm string   `xml:"ddnsdomainkeyalgorithm"`
			Ddnsdomainkey          string   `xml:"ddnsdomainkey"`
			MacAllow               string   `xml:"mac_allow"`
			MacDeny                string   `xml:"mac_deny"`
			Ddnsclientupdates      string   `xml:"ddnsclientupdates"`
			Ntpserver              []string `xml:"ntpserver"`
			Tftp                   string   `xml:"tftp"`
			Ldap                   string   `xml:"ldap"`
			Nextserver             string   `xml:"nextserver"`
			Filename               string   `xml:"filename"`
			Filename32             string   `xml:"filename32"`
			Filename64             string   `xml:"filename64"`
			Rootpath               string   `xml:"rootpath"`
			Numberoptions          string   `xml:"numberoptions"`
			Dhcpleaseinlocaltime   string   `xml:"dhcpleaseinlocaltime"`
		} `xml:"opt7"`
		Lan struct {
			Text  string `xml:",chardata"`
			Range struct {
				Text string `xml:",chardata"`
				From string `xml:"from"`
				To   string `xml:"to"`
			} `xml:"range"`
			Enable                 string `xml:"enable"`
			FailoverPeerip         string `xml:"failover_peerip"`
			Defaultleasetime       string `xml:"defaultleasetime"`
			Maxleasetime           string `xml:"maxleasetime"`
			Netmask                string `xml:"netmask"`
			Gateway                string `xml:"gateway"`
			Domain                 string `xml:"domain"`
			Domainsearchlist       string `xml:"domainsearchlist"`
			Ddnsdomain             string `xml:"ddnsdomain"`
			Ddnsdomainprimary      string `xml:"ddnsdomainprimary"`
			Ddnsdomainsecondary    string `xml:"ddnsdomainsecondary"`
			Ddnsdomainkeyname      string `xml:"ddnsdomainkeyname"`
			Ddnsdomainkeyalgorithm string `xml:"ddnsdomainkeyalgorithm"`
			Ddnsdomainkey          string `xml:"ddnsdomainkey"`
			MacAllow               string `xml:"mac_allow"`
			MacDeny                string `xml:"mac_deny"`
			Ddnsclientupdates      string `xml:"ddnsclientupdates"`
			Tftp                   string `xml:"tftp"`
			Ldap                   string `xml:"ldap"`
			Nextserver             string `xml:"nextserver"`
			Filename               string `xml:"filename"`
			Filename32             string `xml:"filename32"`
			Filename64             string `xml:"filename64"`
			Rootpath               string `xml:"rootpath"`
			Numberoptions          string `xml:"numberoptions"`
			Staticmap              []struct {
				Text                   string `xml:",chardata"`
				Mac                    string `xml:"mac"`
				Cid                    string `xml:"cid"`
				Ipaddr                 string `xml:"ipaddr"`
				Hostname               string `xml:"hostname"`
				Descr                  string `xml:"descr"`
				Filename               string `xml:"filename"`
				Rootpath               string `xml:"rootpath"`
				Defaultleasetime       string `xml:"defaultleasetime"`
				Maxleasetime           string `xml:"maxleasetime"`
				Gateway                string `xml:"gateway"`
				Domain                 string `xml:"domain"`
				Domainsearchlist       string `xml:"domainsearchlist"`
				Ddnsdomain             string `xml:"ddnsdomain"`
				Ddnsdomainprimary      string `xml:"ddnsdomainprimary"`
				Ddnsdomainkeyname      string `xml:"ddnsdomainkeyname"`
				Ddnsdomainkey          string `xml:"ddnsdomainkey"`
				Tftp                   string `xml:"tftp"`
				Ldap                   string `xml:"ldap"`
				Ddnsdomainsecondary    string `xml:"ddnsdomainsecondary"`
				Ddnsdomainkeyalgorithm string `xml:"ddnsdomainkeyalgorithm"`
				Nextserver             string `xml:"nextserver"`
				Filename32             string `xml:"filename32"`
				Filename64             string `xml:"filename64"`
				Filename32arm          string `xml:"filename32arm"`
				Filename64arm          string `xml:"filename64arm"`
				Uefihttpboot           string `xml:"uefihttpboot"`
				Numberoptions          string `xml:"numberoptions"`
			} `xml:"staticmap"`
			Dhcpleaseinlocaltime string   `xml:"dhcpleaseinlocaltime"`
			Winsserver           string   `xml:"winsserver"`
			Dnsserver            []string `xml:"dnsserver"`
		} `xml:"lan"`
	} `xml:"dhcpd"`
	Dhcpdv6 string `xml:"dhcpdv6"`
	Snmpd   struct {
		Text        string `xml:",chardata"`
		Syslocation string `xml:"syslocation"`
		Syscontact  string `xml:"syscontact"`
		Rocommunity string `xml:"rocommunity"`
		Modules     struct {
			Text     string `xml:",chardata"`
			Mibii    string `xml:"mibii"`
			Netgraph string `xml:"netgraph"`
			Pf       string `xml:"pf"`
			Hostres  string `xml:"hostres"`
			Ucd      string `xml:"ucd"`
			Regex    string `xml:"regex"`
		} `xml:"modules"`
		Enable         string `xml:"enable"`
		Pollport       string `xml:"pollport"`
		Trapserver     string `xml:"trapserver"`
		Trapserverport string `xml:"trapserverport"`
		Trapstring     string `xml:"trapstring"`
		Bindip         string `xml:"bindip"`
		Ipprotocol     string `xml:"ipprotocol"`
	} `xml:"snmpd"`
	Diag struct {
		Text    string `xml:",chardata"`
		Ipv6nat string `xml:"ipv6nat"`
	} `xml:"diag"`
	Syslog struct {
		Text               string `xml:",chardata"`
		Filterdescriptions string `xml:"filterdescriptions"`
		Nentries           string `xml:"nentries"`
		Logcompressiontype string `xml:"logcompressiontype"`
		Format             string `xml:"format"`
		Rotatecount        string `xml:"rotatecount"`
		Sourceip           string `xml:"sourceip"`
		Ipproto            string `xml:"ipproto"`
		Logconfigchanges   string `xml:"logconfigchanges"`
		Logfilesize        string `xml:"logfilesize"`
	} `xml:"syslog"`
	Nat struct {
		Text     string `xml:",chardata"`
		Outbound struct {
			Text string `xml:",chardata"`
			Mode string `xml:"mode"`
			Rule []struct {
				Text   string `xml:",chardata"`
				Source struct {
					Text    string `xml:",chardata"`
					Network string `xml:"network"`
				} `xml:"source"`
				Sourceport     string `xml:"sourceport"`
				Descr          string `xml:"descr"`
				Target         string `xml:"target"`
				Targetip       string `xml:"targetip"`
				TargetipSubnet string `xml:"targetip_subnet"`
				Interface      string `xml:"interface"`
				Poolopts       string `xml:"poolopts"`
				SourceHashKey  string `xml:"source_hash_key"`
				Ipprotocol     string `xml:"ipprotocol"`
				Protocol       string `xml:"protocol"`
				Destination    struct {
					Text    string `xml:",chardata"`
					Address string `xml:"address"`
					Any     string `xml:"any"`
				} `xml:"destination"`
				Updated struct {
					Text     string `xml:",chardata"`
					Time     string `xml:"time"`
					Username string `xml:"username"`
				} `xml:"updated"`
				Created struct {
					Text     string `xml:",chardata"`
					Time     string `xml:"time"`
					Username string `xml:"username"`
				} `xml:"created"`
				Disabled      string `xml:"disabled"`
				Dstport       string `xml:"dstport"`
				Staticnatport string `xml:"staticnatport"`
			} `xml:"rule"`
		} `xml:"outbound"`
		Rule []struct {
			Text   string `xml:",chardata"`
			Source struct {
				Text    string `xml:",chardata"`
				Address string `xml:"address"`
				Any     string `xml:"any"`
			} `xml:"source"`
			Destination struct {
				Text    string `xml:",chardata"`
				Network string `xml:"network"`
				Port    string `xml:"port"`
				Address string `xml:"address"`
			} `xml:"destination"`
			Ipprotocol       string `xml:"ipprotocol"`
			Protocol         string `xml:"protocol"`
			Target           string `xml:"target"`
			LocalPort        string `xml:"local-port"`
			Interface        string `xml:"interface"`
			Descr            string `xml:"descr"`
			AssociatedRuleID string `xml:"associated-rule-id"`
			Created          struct {
				Text     string `xml:",chardata"`
				Time     string `xml:"time"`
				Username string `xml:"username"`
			} `xml:"created"`
			Updated struct {
				Text     string `xml:",chardata"`
				Time     string `xml:"time"`
				Username string `xml:"username"`
			} `xml:"updated"`
		} `xml:"rule"`
		Separator struct {
			Text string `xml:",chardata"`
			Sep0 struct {
				Chardata string `xml:",chardata"`
				Row      string `xml:"row"`
				Text     string `xml:"text"`
				Color    string `xml:"color"`
				If       string `xml:"if"`
			} `xml:"sep0"`
			Sep1 struct {
				Chardata string `xml:",chardata"`
				Row      string `xml:"row"`
				Text     string `xml:"text"`
				Color    string `xml:"color"`
				If       string `xml:"if"`
			} `xml:"sep1"`
			Sep2 struct {
				Chardata string `xml:",chardata"`
				Row      string `xml:"row"`
				Text     string `xml:"text"`
				Color    string `xml:"color"`
				If       string `xml:"if"`
			} `xml:"sep2"`
			Sep3 struct {
				Chardata string `xml:",chardata"`
				Row      string `xml:"row"`
				Text     string `xml:"text"`
				Color    string `xml:"color"`
				If       string `xml:"if"`
			} `xml:"sep3"`
			Sep4 struct {
				Chardata string `xml:",chardata"`
				Row      string `xml:"row"`
				Text     string `xml:"text"`
				Color    string `xml:"color"`
				If       string `xml:"if"`
			} `xml:"sep4"`
		} `xml:"separator"`
		Onetoone []struct {
			Text       string `xml:",chardata"`
			Disabled   string `xml:"disabled"`
			External   string `xml:"external"`
			Descr      string `xml:"descr"`
			Interface  string `xml:"interface"`
			Ipprotocol string `xml:"ipprotocol"`
			Source     struct {
				Text    string `xml:",chardata"`
				Address string `xml:"address"`
				Network string `xml:"network"`
				Any     string `xml:"any"`
			} `xml:"source"`
			Destination struct {
				Text    string `xml:",chardata"`
				Any     string `xml:"any"`
				Address string `xml:"address"`
			} `xml:"destination"`
			Natreflection string `xml:"natreflection"`
		} `xml:"onetoone"`
	} `xml:"nat"`
	Filter struct {
		Text string `xml:",chardata"`
		Rule []struct {
			Text         string `xml:",chardata"`
			ID           string `xml:"id"`
			Tracker      string `xml:"tracker"`
			Type         string `xml:"type"`
			Interface    string `xml:"interface"`
			Ipprotocol   string `xml:"ipprotocol"`
			Tag          string `xml:"tag"`
			Tagged       string `xml:"tagged"`
			Direction    string `xml:"direction"`
			Floating     string `xml:"floating"`
			Max          string `xml:"max"`
			MaxSrcNodes  string `xml:"max-src-nodes"`
			MaxSrcConn   string `xml:"max-src-conn"`
			MaxSrcStates string `xml:"max-src-states"`
			Statetimeout string `xml:"statetimeout"`
			Statetype    string `xml:"statetype"`
			Os           string `xml:"os"`
			Source       struct {
				Text    string `xml:",chardata"`
				Address string `xml:"address"`
				Network string `xml:"network"`
				Any     string `xml:"any"`
			} `xml:"source"`
			Destination struct {
				Text    string `xml:",chardata"`
				Address string `xml:"address"`
				Any     string `xml:"any"`
				Port    string `xml:"port"`
				Network string `xml:"network"`
			} `xml:"destination"`
			Descr   string `xml:"descr"`
			Created struct {
				Text     string `xml:",chardata"`
				Time     string `xml:"time"`
				Username string `xml:"username"`
			} `xml:"created"`
			Updated struct {
				Text     string `xml:",chardata"`
				Time     string `xml:"time"`
				Username string `xml:"username"`
			} `xml:"updated"`
			Protocol         string `xml:"protocol"`
			Log              string `xml:"log"`
			Gateway          string `xml:"gateway"`
			Disabled         string `xml:"disabled"`
			AssociatedRuleID string `xml:"associated-rule-id"`
			Icmptype         string `xml:"icmptype"`
		} `xml:"rule"`
		Separator struct {
			Text string `xml:",chardata"`
			Wan  string `xml:"wan"`
			Lan  struct {
				Text string `xml:",chardata"`
				Sep0 struct {
					Chardata string `xml:",chardata"`
					Row      string `xml:"row"`
					Text     string `xml:"text"`
					Color    string `xml:"color"`
					If       string `xml:"if"`
				} `xml:"sep0"`
				Sep1 struct {
					Chardata string `xml:",chardata"`
					Row      string `xml:"row"`
					Text     string `xml:"text"`
					Color    string `xml:"color"`
					If       string `xml:"if"`
				} `xml:"sep1"`
			} `xml:"lan"`
			Opt2 struct {
				Text string `xml:",chardata"`
				Sep0 struct {
					Chardata string `xml:",chardata"`
					Row      string `xml:"row"`
					Text     string `xml:"text"`
					Color    string `xml:"color"`
					If       string `xml:"if"`
				} `xml:"sep0"`
				Sep1 struct {
					Chardata string `xml:",chardata"`
					Row      string `xml:"row"`
					Text     string `xml:"text"`
					Color    string `xml:"color"`
					If       string `xml:"if"`
				} `xml:"sep1"`
			} `xml:"opt2"`
			Floatingrules string `xml:"floatingrules"`
			Opt4          struct {
				Text string `xml:",chardata"`
				Sep0 struct {
					Chardata string `xml:",chardata"`
					Row      string `xml:"row"`
					Text     string `xml:"text"`
					Color    string `xml:"color"`
					If       string `xml:"if"`
				} `xml:"sep0"`
				Sep1 struct {
					Chardata string `xml:",chardata"`
					Row      string `xml:"row"`
					Text     string `xml:"text"`
					Color    string `xml:"color"`
					If       string `xml:"if"`
				} `xml:"sep1"`
				Sep2 struct {
					Chardata string `xml:",chardata"`
					Row      string `xml:"row"`
					Text     string `xml:"text"`
					Color    string `xml:"color"`
					If       string `xml:"if"`
				} `xml:"sep2"`
				Sep3 struct {
					Chardata string `xml:",chardata"`
					Row      string `xml:"row"`
					Text     string `xml:"text"`
					Color    string `xml:"color"`
					If       string `xml:"if"`
				} `xml:"sep3"`
			} `xml:"opt4"`
			Opt6    string `xml:"opt6"`
			Enc0    string `xml:"enc0"`
			Openvpn string `xml:"openvpn"`
			Opt10   string `xml:"opt10"`
			Opt3    string `xml:"opt3"`
			Opt16   string `xml:"opt16"`
			Opt1    struct {
				Text string `xml:",chardata"`
				Sep0 struct {
					Chardata string `xml:",chardata"`
					Row      string `xml:"row"`
					Text     string `xml:"text"`
					Color    string `xml:"color"`
					If       string `xml:"if"`
				} `xml:"sep0"`
			} `xml:"opt1"`
		} `xml:"separator"`
	} `xml:"filter"`
	Shaper string `xml:"shaper"`
	Ipsec  struct {
		Text   string `xml:",chardata"`
		Phase1 []struct {
			Text          string `xml:",chardata"`
			Ikeid         string `xml:"ikeid"`
			Iketype       string `xml:"iketype"`
			Mode          string `xml:"mode"`
			Interface     string `xml:"interface"`
			RemoteGateway string `xml:"remote-gateway"`
			Protocol      string `xml:"protocol"`
			MyidType      string `xml:"myid_type"`
			MyidData      string `xml:"myid_data"`
			PeeridType    string `xml:"peerid_type"`
			PeeridData    string `xml:"peerid_data"`
			Encryption    struct {
				Text string `xml:",chardata"`
				Item []struct {
					Text                string `xml:",chardata"`
					EncryptionAlgorithm struct {
						Text   string `xml:",chardata"`
						Name   string `xml:"name"`
						Keylen string `xml:"keylen"`
					} `xml:"encryption-algorithm"`
					HashAlgorithm string `xml:"hash-algorithm"`
					PrfAlgorithm  string `xml:"prf-algorithm"`
					Dhgroup       string `xml:"dhgroup"`
				} `xml:"item"`
			} `xml:"encryption"`
			Lifetime             string `xml:"lifetime"`
			RekeyTime            string `xml:"rekey_time"`
			ReauthTime           string `xml:"reauth_time"`
			RandTime             string `xml:"rand_time"`
			PreSharedKey         string `xml:"pre-shared-key"`
			PrivateKey           string `xml:"private-key"`
			Certref              string `xml:"certref"`
			Pkcs11certref        string `xml:"pkcs11certref"`
			Pkcs11pin            string `xml:"pkcs11pin"`
			Caref                string `xml:"caref"`
			AuthenticationMethod string `xml:"authentication_method"`
			Descr                string `xml:"descr"`
			NatTraversal         string `xml:"nat_traversal"`
			Mobike               string `xml:"mobike"`
			Startaction          string `xml:"startaction"`
			Closeaction          string `xml:"closeaction"`
			DpdDelay             string `xml:"dpd_delay"`
			DpdMaxfail           string `xml:"dpd_maxfail"`
			Splitconn            string `xml:"splitconn"`
			Disabled             string `xml:"disabled"`
			Mobile               string `xml:"mobile"`
		} `xml:"phase1"`
		Client struct {
			Text        string `xml:",chardata"`
			UserSource  string `xml:"user_source"`
			GroupSource string `xml:"group_source"`
			PoolAddress string `xml:"pool_address"`
			PoolNetbits string `xml:"pool_netbits"`
			NetList     string `xml:"net_list"`
			SavePasswd  string `xml:"save_passwd"`
			DnsDomain   string `xml:"dns_domain"`
			DnsServer1  string `xml:"dns_server1"`
			DnsServer2  string `xml:"dns_server2"`
			DnsServer3  string `xml:"dns_server3"`
			DnsServer4  string `xml:"dns_server4"`
			LoginBanner string `xml:"login_banner"`
		} `xml:"client"`
		Phase2 []struct {
			Text    string `xml:",chardata"`
			Ikeid   string `xml:"ikeid"`
			Uniqid  string `xml:"uniqid"`
			Mode    string `xml:"mode"`
			Reqid   string `xml:"reqid"`
			Localid struct {
				Text    string `xml:",chardata"`
				Type    string `xml:"type"`
				Address string `xml:"address"`
				Netbits string `xml:"netbits"`
			} `xml:"localid"`
			Remoteid struct {
				Text    string `xml:",chardata"`
				Type    string `xml:"type"`
				Address string `xml:"address"`
				Netbits string `xml:"netbits"`
			} `xml:"remoteid"`
			Protocol                  string `xml:"protocol"`
			EncryptionAlgorithmOption struct {
				Text   string `xml:",chardata"`
				Name   string `xml:"name"`
				Keylen string `xml:"keylen"`
			} `xml:"encryption-algorithm-option"`
			HashAlgorithmOption []string `xml:"hash-algorithm-option"`
			Pfsgroup            string   `xml:"pfsgroup"`
			Lifetime            string   `xml:"lifetime"`
			RekeyTime           string   `xml:"rekey_time"`
			RandTime            string   `xml:"rand_time"`
			Pinghost            string   `xml:"pinghost"`
			Keepalive           string   `xml:"keepalive"`
			Descr               string   `xml:"descr"`
			Natlocalid          struct {
				Text    string `xml:",chardata"`
				Type    string `xml:"type"`
				Address string `xml:"address"`
				Netbits string `xml:"netbits"`
			} `xml:"natlocalid"`
			Disabled string `xml:"disabled"`
			Mobile   string `xml:"mobile"`
		} `xml:"phase2"`
		Logging struct {
			Text string `xml:",chardata"`
			Dmn  string `xml:"dmn"`
			Mgr  string `xml:"mgr"`
			Ike  string `xml:"ike"`
			Chd  string `xml:"chd"`
			Job  string `xml:"job"`
			Cfg  string `xml:"cfg"`
			Knl  string `xml:"knl"`
			Net  string `xml:"net"`
			Asn  string `xml:"asn"`
			Enc  string `xml:"enc"`
			Imc  string `xml:"imc"`
			Imv  string `xml:"imv"`
			Pts  string `xml:"pts"`
			Tls  string `xml:"tls"`
			Esp  string `xml:"esp"`
			Lib  string `xml:"lib"`
		} `xml:"logging"`
		AsyncCrypto string `xml:"async_crypto"`
		Uniqueids   string `xml:"uniqueids"`
		Vtimaps     struct {
			Text string `xml:",chardata"`
			Item []struct {
				Text  string `xml:",chardata"`
				Reqid string `xml:"reqid"`
				Index string `xml:"index"`
				Ifnum string `xml:"ifnum"`
			} `xml:"item"`
		} `xml:"vtimaps"`
		Filtermode  string `xml:"filtermode"`
		Bypassrules string `xml:"bypassrules"`
	} `xml:"ipsec"`
	Aliases struct {
		Text  string `xml:",chardata"`
		Alias []struct {
			Text     string `xml:",chardata"`
			Name     string `xml:"name"`
			Type     string `xml:"type"`
			Address  string `xml:"address"`
			Descr    string `xml:"descr"`
			Detail   string `xml:"detail"`
			Aliasurl string `xml:"aliasurl"`
		} `xml:"alias"`
	} `xml:"aliases"`
	Proxyarp string `xml:"proxyarp"`
	Cron     struct {
		Text string `xml:",chardata"`
		Item []struct {
			Text    string `xml:",chardata"`
			Minute  string `xml:"minute"`
			Hour    string `xml:"hour"`
			Mday    string `xml:"mday"`
			Month   string `xml:"month"`
			Wday    string `xml:"wday"`
			Who     string `xml:"who"`
			Command string `xml:"command"`
		} `xml:"item"`
	} `xml:"cron"`
	Wol string `xml:"wol"`
	Rrd struct {
		Text     string `xml:",chardata"`
		Enable   string `xml:"enable"`
		Category string `xml:"category"`
	} `xml:"rrd"`
	Widgets struct {
		Text          string `xml:",chardata"`
		Sequence      string `xml:"sequence"`
		Period        string `xml:"period"`
		TrafficGraphs struct {
			Text             string `xml:",chardata"`
			Refreshinterval  string `xml:"refreshinterval"`
			Invert           string `xml:"invert"`
			Backgroundupdate string `xml:"backgroundupdate"`
			Smoothfactor     string `xml:"smoothfactor"`
			Size             string `xml:"size"`
			Filter           string `xml:"filter"`
		} `xml:"traffic_graphs"`
	} `xml:"widgets"`
	Openvpn struct {
		Text          string `xml:",chardata"`
		OpenvpnServer []struct {
			Text                     string `xml:",chardata"`
			Vpnid                    string `xml:"vpnid"`
			Mode                     string `xml:"mode"`
			Authmode                 string `xml:"authmode"`
			Protocol                 string `xml:"protocol"`
			DevMode                  string `xml:"dev_mode"`
			Interface                string `xml:"interface"`
			Ipaddr                   string `xml:"ipaddr"`
			LocalPort                string `xml:"local_port"`
			Description              string `xml:"description"`
			CustomOptions            string `xml:"custom_options"`
			Tls                      string `xml:"tls"`
			TlsType                  string `xml:"tls_type"`
			TlsauthKeydir            string `xml:"tlsauth_keydir"`
			Caref                    string `xml:"caref"`
			Crlref                   string `xml:"crlref"`
			Ocspurl                  string `xml:"ocspurl"`
			Certref                  string `xml:"certref"`
			DhLength                 string `xml:"dh_length"`
			EcdhCurve                string `xml:"ecdh_curve"`
			CertDepth                string `xml:"cert_depth"`
			RemoteCertTls            string `xml:"remote_cert_tls"`
			DataCiphersFallback      string `xml:"data_ciphers_fallback"`
			Digest                   string `xml:"digest"`
			Engine                   string `xml:"engine"`
			TunnelNetwork            string `xml:"tunnel_network"`
			TunnelNetworkv6          string `xml:"tunnel_networkv6"`
			RemoteNetwork            string `xml:"remote_network"`
			RemoteNetworkv6          string `xml:"remote_networkv6"`
			Gwredir                  string `xml:"gwredir"`
			Gwredir6                 string `xml:"gwredir6"`
			LocalNetwork             string `xml:"local_network"`
			LocalNetworkv6           string `xml:"local_networkv6"`
			Maxclients               string `xml:"maxclients"`
			AllowCompression         string `xml:"allow_compression"`
			Compression              string `xml:"compression"`
			CompressionPush          string `xml:"compression_push"`
			Passtos                  string `xml:"passtos"`
			Client2client            string `xml:"client2client"`
			DynamicIp                string `xml:"dynamic_ip"`
			Topology                 string `xml:"topology"`
			ServerbridgeDhcp         string `xml:"serverbridge_dhcp"`
			ServerbridgeInterface    string `xml:"serverbridge_interface"`
			ServerbridgeRoutegateway string `xml:"serverbridge_routegateway"`
			ServerbridgeDhcpStart    string `xml:"serverbridge_dhcp_start"`
			ServerbridgeDhcpEnd      string `xml:"serverbridge_dhcp_end"`
			DnsDomain                string `xml:"dns_domain"`
			DnsServer1               string `xml:"dns_server1"`
			DnsServer2               string `xml:"dns_server2"`
			DnsServer3               string `xml:"dns_server3"`
			DnsServer4               string `xml:"dns_server4"`
			PushBlockoutsidedns      string `xml:"push_blockoutsidedns"`
			UsernameAsCommonName     string `xml:"username_as_common_name"`
			Sndrcvbuf                string `xml:"sndrcvbuf"`
			PushRegisterDns          string `xml:"push_register_dns"`
			NetbiosEnable            string `xml:"netbios_enable"`
			NetbiosNtype             string `xml:"netbios_ntype"`
			NetbiosScope             string `xml:"netbios_scope"`
			CreateGw                 string `xml:"create_gw"`
			VerbosityLevel           string `xml:"verbosity_level"`
			DataCiphers              string `xml:"data_ciphers"`
			NcpEnable                string `xml:"ncp_enable"`
			PingMethod               string `xml:"ping_method"`
			KeepaliveInterval        string `xml:"keepalive_interval"`
			KeepaliveTimeout         string `xml:"keepalive_timeout"`
			PingSeconds              string `xml:"ping_seconds"`
			PingPush                 string `xml:"ping_push"`
			PingAction               string `xml:"ping_action"`
			PingActionSeconds        string `xml:"ping_action_seconds"`
			PingActionPush           string `xml:"ping_action_push"`
			InactiveSeconds          string `xml:"inactive_seconds"`
			DuplicateCn              string `xml:"duplicate_cn"`
		} `xml:"openvpn-server"`
		OpenvpnClient []struct {
			Text                string `xml:",chardata"`
			AuthUser            string `xml:"auth_user"`
			AuthPass            string `xml:"auth_pass"`
			ProxyUser           string `xml:"proxy_user"`
			ProxyPasswd         string `xml:"proxy_passwd"`
			Vpnid               string `xml:"vpnid"`
			Protocol            string `xml:"protocol"`
			DevMode             string `xml:"dev_mode"`
			Interface           string `xml:"interface"`
			Ipaddr              string `xml:"ipaddr"`
			LocalPort           string `xml:"local_port"`
			ServerAddr          string `xml:"server_addr"`
			ServerPort          string `xml:"server_port"`
			ProxyAddr           string `xml:"proxy_addr"`
			ProxyPort           string `xml:"proxy_port"`
			ProxyAuthtype       string `xml:"proxy_authtype"`
			Description         string `xml:"description"`
			Mode                string `xml:"mode"`
			Topology            string `xml:"topology"`
			CustomOptions       string `xml:"custom_options"`
			Caref               string `xml:"caref"`
			Certref             string `xml:"certref"`
			Crlref              string `xml:"crlref"`
			RemoteCertTls       string `xml:"remote_cert_tls"`
			DataCiphersFallback string `xml:"data_ciphers_fallback"`
			Digest              string `xml:"digest"`
			Engine              string `xml:"engine"`
			TunnelNetwork       string `xml:"tunnel_network"`
			TunnelNetworkv6     string `xml:"tunnel_networkv6"`
			RemoteNetwork       string `xml:"remote_network"`
			RemoteNetworkv6     string `xml:"remote_networkv6"`
			UseShaper           string `xml:"use_shaper"`
			AllowCompression    string `xml:"allow_compression"`
			Compression         string `xml:"compression"`
			AuthRetryNone       string `xml:"auth-retry-none"`
			Passtos             string `xml:"passtos"`
			UdpFastIo           string `xml:"udp_fast_io"`
			ExitNotify          string `xml:"exit_notify"`
			Sndrcvbuf           string `xml:"sndrcvbuf"`
			RouteNoPull         string `xml:"route_no_pull"`
			RouteNoExec         string `xml:"route_no_exec"`
			DnsAdd              string `xml:"dns_add"`
			VerbosityLevel      string `xml:"verbosity_level"`
			CreateGw            string `xml:"create_gw"`
			DataCiphers         string `xml:"data_ciphers"`
			NcpEnable           string `xml:"ncp_enable"`
			PingMethod          string `xml:"ping_method"`
			KeepaliveInterval   string `xml:"keepalive_interval"`
			KeepaliveTimeout    string `xml:"keepalive_timeout"`
			PingSeconds         string `xml:"ping_seconds"`
			PingAction          string `xml:"ping_action"`
			PingActionSeconds   string `xml:"ping_action_seconds"`
			InactiveSeconds     string `xml:"inactive_seconds"`
			Disable             string `xml:"disable"`
			Tls                 string `xml:"tls"`
			TlsType             string `xml:"tls_type"`
			TlsauthKeydir       string `xml:"tlsauth_keydir"`
		} `xml:"openvpn-client"`
	} `xml:"openvpn"`
	Dnshaper struct {
		Text  string `xml:",chardata"`
		Queue []struct {
			Text        string `xml:",chardata"`
			Name        string `xml:"name"`
			Number      string `xml:"number"`
			Qlimit      string `xml:"qlimit"`
			Plr         string `xml:"plr"`
			Description string `xml:"description"`
			Bandwidth   struct {
				Text string `xml:",chardata"`
				Item struct {
					Text    string `xml:",chardata"`
					Bw      string `xml:"bw"`
					Burst   string `xml:"burst"`
					Bwscale string `xml:"bwscale"`
					Bwsched string `xml:"bwsched"`
				} `xml:"item"`
			} `xml:"bandwidth"`
			Enabled    string `xml:"enabled"`
			Buckets    string `xml:"buckets"`
			Mask       string `xml:"mask"`
			Maskbits   string `xml:"maskbits"`
			Maskbitsv6 string `xml:"maskbitsv6"`
			Delay      string `xml:"delay"`
			Sched      string `xml:"sched"`
			Aqm        string `xml:"aqm"`
			Ecn        string `xml:"ecn"`
		} `xml:"queue"`
	} `xml:"dnshaper"`
	Unbound struct {
		Text                      string `xml:",chardata"`
		Dnssec                    string `xml:"dnssec"`
		ActiveInterface           string `xml:"active_interface"`
		OutgoingInterface         string `xml:"outgoing_interface"`
		CustomOptions             string `xml:"custom_options"`
		Hideidentity              string `xml:"hideidentity"`
		Hideversion               string `xml:"hideversion"`
		Dnssecstripped            string `xml:"dnssecstripped"`
		Port                      string `xml:"port"`
		Tlsport                   string `xml:"tlsport"`
		Sslcertref                string `xml:"sslcertref"`
		SystemDomainLocalZoneType string `xml:"system_domain_local_zone_type"`
		Enable                    string `xml:"enable"`
	} `xml:"unbound"`
	Revision struct {
		Text        string `xml:",chardata"`
		Time        string `xml:"time"`
		Description string `xml:"description"`
		Username    string `xml:"username"`
	} `xml:"revision"`
	Cert []struct {
		Text  string `xml:",chardata"`
		Refid string `xml:"refid"`
		Descr string `xml:"descr"`
		Type  string `xml:"type"`
		Crt   string `xml:"crt"`
		Prv   string `xml:"prv"`
		Caref string `xml:"caref"`
	} `xml:"cert"`
	Vlans struct {
		Text string `xml:",chardata"`
		Vlan []struct {
			Text   string `xml:",chardata"`
			If     string `xml:"if"`
			Tag    string `xml:"tag"`
			Pcp    string `xml:"pcp"`
			Descr  string `xml:"descr"`
			Vlanif string `xml:"vlanif"`
		} `xml:"vlan"`
	} `xml:"vlans"`
	Ppps struct {
		Text string `xml:",chardata"`
		Ppp  struct {
			Text      string `xml:",chardata"`
			Ptpid     string `xml:"ptpid"`
			Type      string `xml:"type"`
			If        string `xml:"if"`
			Ports     string `xml:"ports"`
			Username  string `xml:"username"`
			Password  string `xml:"password"`
			Descr     string `xml:"descr"`
			Provider  string `xml:"provider"`
			Bandwidth string `xml:"bandwidth"`
			Mtu       string `xml:"mtu"`
			Mru       string `xml:"mru"`
			Mrru      string `xml:"mrru"`
			Hostuniq  string `xml:"hostuniq"`
		} `xml:"ppp"`
	} `xml:"ppps"`
	Gateways struct {
		Text        string `xml:",chardata"`
		GatewayItem []struct {
			Text           string `xml:",chardata"`
			Interface      string `xml:"interface"`
			Gateway        string `xml:"gateway"`
			Name           string `xml:"name"`
			Weight         string `xml:"weight"`
			Ipprotocol     string `xml:"ipprotocol"`
			Descr          string `xml:"descr"`
			Monitor        string `xml:"monitor"`
			Disabled       string `xml:"disabled"`
			MonitorDisable string `xml:"monitor_disable"`
			ActionDisable  string `xml:"action_disable"`
		} `xml:"gateway_item"`
		GatewayGroup []struct {
			Text    string   `xml:",chardata"`
			Name    string   `xml:"name"`
			Item    []string `xml:"item"`
			Trigger string   `xml:"trigger"`
			Descr   string   `xml:"descr"`
		} `xml:"gateway_group"`
		Defaultgw4 string `xml:"defaultgw4"`
		Defaultgw6 string `xml:"defaultgw6"`
	} `xml:"gateways"`
	Ca []struct {
		Text         string `xml:",chardata"`
		Refid        string `xml:"refid"`
		Descr        string `xml:"descr"`
		Crt          string `xml:"crt"`
		Serial       string `xml:"serial"`
		Prv          string `xml:"prv"`
		Trust        string `xml:"trust"`
		Randomserial string `xml:"randomserial"`
	} `xml:"ca"`
	Virtualip struct {
		Text string `xml:",chardata"`
		Vip  []struct {
			Text       string `xml:",chardata"`
			Mode       string `xml:"mode"`
			Interface  string `xml:"interface"`
			Uniqid     string `xml:"uniqid"`
			Descr      string `xml:"descr"`
			Type       string `xml:"type"`
			SubnetBits string `xml:"subnet_bits"`
			Subnet     string `xml:"subnet"`
		} `xml:"vip"`
	} `xml:"virtualip"`
	Ovpnserver struct {
		Text  string `xml:",chardata"`
		Step1 struct {
			Text string `xml:",chardata"`
			Type string `xml:"type"`
		} `xml:"step1"`
		Step2 struct {
			Text     string `xml:",chardata"`
			Authserv string `xml:"authserv"`
		} `xml:"step2"`
	} `xml:"ovpnserver"`
	Installedpackages struct {
		Text    string `xml:",chardata"`
		Package []struct {
			Text              string `xml:",chardata"`
			Name              string `xml:"name"`
			Descr             string `xml:"descr"`
			Website           string `xml:"website"`
			Version           string `xml:"version"`
			Configurationfile string `xml:"configurationfile"`
			Pkginfolink       string `xml:"pkginfolink"`
			IncludeFile       string `xml:"include_file"`
			InternalName      string `xml:"internal_name"`
			Tabs              struct {
				Text string `xml:",chardata"`
				Tab  []struct {
					Chardata string `xml:",chardata"`
					Name     string `xml:"name"`
					Tabgroup string `xml:"tabgroup"`
					URL      string `xml:"url"`
					Text     string `xml:"text"`
					Active   string `xml:"active"`
				} `xml:"tab"`
			} `xml:"tabs"`
			Plugins struct {
				Text string `xml:",chardata"`
				Item struct {
					Text string `xml:",chardata"`
					Type string `xml:"type"`
				} `xml:"item"`
			} `xml:"plugins"`
			FilterRuleFunction string `xml:"filter_rule_function"`
			Logging            struct {
				Text        string `xml:",chardata"`
				Logfilename string `xml:"logfilename"`
			} `xml:"logging"`
			Noembedded string `xml:"noembedded"`
		} `xml:"package"`
		Menu []struct {
			Text        string `xml:",chardata"`
			Name        string `xml:"name"`
			Tooltiptext string `xml:"tooltiptext"`
			Section     string `xml:"section"`
			URL         string `xml:"url"`
			Configfile  string `xml:"configfile"`
		} `xml:"menu"`
		Miniupnpd struct {
			Text   string `xml:",chardata"`
			Config struct {
				Text          string `xml:",chardata"`
				Enable        string `xml:"enable"`
				EnableUpnp    string `xml:"enable_upnp"`
				EnableNatpmp  string `xml:"enable_natpmp"`
				ExtIface      string `xml:"ext_iface"`
				IfaceArray    string `xml:"iface_array"`
				Download      string `xml:"download"`
				Upload        string `xml:"upload"`
				Overridewanip string `xml:"overridewanip"`
				Upnpqueue     string `xml:"upnpqueue"`
				Logpackets    string `xml:"logpackets"`
				Sysuptime     string `xml:"sysuptime"`
				Permdefault   string `xml:"permdefault"`
				Row           struct {
					Text     string `xml:",chardata"`
					Permuser string `xml:"permuser"`
				} `xml:"row"`
				Presentationurl string `xml:"presentationurl"`
				Modelnumber     string `xml:"modelnumber"`
			} `xml:"config"`
		} `xml:"miniupnpd"`
		Zabbixagentlts struct {
			Text   string `xml:",chardata"`
			Config struct {
				Text             string `xml:",chardata"`
				Agentenabled     string `xml:"agentenabled"`
				Server           string `xml:"server"`
				Serveractive     string `xml:"serveractive"`
				Hostname         string `xml:"hostname"`
				Listenip         string `xml:"listenip"`
				Listenport       string `xml:"listenport"`
				Refreshactchecks string `xml:"refreshactchecks"`
				Timeout          string `xml:"timeout"`
				Buffersend       string `xml:"buffersend"`
				Buffersize       string `xml:"buffersize"`
				Startagents      string `xml:"startagents"`
				Tlsconnect       string `xml:"tlsconnect"`
				Tlsaccept        string `xml:"tlsaccept"`
				Tlscafile        string `xml:"tlscafile"`
				Tlscaso          string `xml:"tlscaso"`
				Tlscrlfile       string `xml:"tlscrlfile"`
				Tlscertfile      string `xml:"tlscertfile"`
				Tlspskidentity   string `xml:"tlspskidentity"`
				Tlspskfile       string `xml:"tlspskfile"`
				Userparams       string `xml:"userparams"`
			} `xml:"config"`
		} `xml:"zabbixagentlts"`
		Syslogng struct {
			Text   string `xml:",chardata"`
			Config struct {
				Text             string `xml:",chardata"`
				Enable           string `xml:"enable"`
				Interfaces       string `xml:"interfaces"`
				DefaultProtocol  string `xml:"default_protocol"`
				DefaultPort      string `xml:"default_port"`
				DefaultLogdir    string `xml:"default_logdir"`
				DefaultLogfile   string `xml:"default_logfile"`
				ArchiveFrequency string `xml:"archive_frequency"`
				CompressArchives string `xml:"compress_archives"`
				CompressType     string `xml:"compress_type"`
				MaxArchives      string `xml:"max_archives"`
			} `xml:"config"`
		} `xml:"syslogng"`
		Syslogngadvanced struct {
			Text   string `xml:",chardata"`
			Config []struct {
				Text             string `xml:",chardata"`
				Objecttype       string `xml:"objecttype"`
				Objectname       string `xml:"objectname"`
				Objectparameters string `xml:"objectparameters"`
			} `xml:"config"`
		} `xml:"syslogngadvanced"`
		VpnOpenvpnExport struct {
			Text   string `xml:",chardata"`
			Config string `xml:"config"`
		} `xml:"vpn_openvpn_export"`
		Service []struct {
			Text         string `xml:",chardata"`
			Name         string `xml:"name"`
			Rcfile       string `xml:"rcfile"`
			Executable   string `xml:"executable"`
			Description  string `xml:"description"`
			Stopcmd      string `xml:"stopcmd"`
			StartsOnSync string `xml:"starts_on_sync"`
		} `xml:"service"`
		Ntopng struct {
			Text   string `xml:",chardata"`
			Config struct {
				Text               string   `xml:",chardata"`
				Enable             string   `xml:"enable"`
				Keepdata           string   `xml:"keepdata"`
				RedisPassword      string   `xml:"redis_password"`
				RedisPasswordagain string   `xml:"redis_passwordagain"`
				InterfaceArray     []string `xml:"interface_array"`
				DnsMode            string   `xml:"dns_mode"`
				LocalNetworks      string   `xml:"local_networks"`
				Row                struct {
					Text string `xml:",chardata"`
					Cidr string `xml:"cidr"`
				} `xml:"row"`
				MaxmindKey string `xml:"maxmind_key"`
			} `xml:"config"`
		} `xml:"ntopng"`
		Arpwatch struct {
			Text   string `xml:",chardata"`
			Config struct {
				Text                   string `xml:",chardata"`
				Enable                 string `xml:"enable"`
				ActiveInterfaces       string `xml:"active_interfaces"`
				NotificationsRecipient string `xml:"notifications_recipient"`
				DisableCron            string `xml:"disable_cron"`
				Zeropad                string `xml:"zeropad"`
				DisableCarp            string `xml:"disable_carp"`
				DisableBogons          string `xml:"disable_bogons"`
				DisableZero            string `xml:"disable_zero"`
				UpdateVendors          string `xml:"update_vendors"`
				ClearDatabase          string `xml:"clear_database"`
				Row                    struct {
					Text             string `xml:",chardata"`
					Mac              string `xml:"mac"`
					NotificationType string `xml:"notification_type"`
				} `xml:"row"`
			} `xml:"config"`
		} `xml:"arpwatch"`
	} `xml:"installedpackages"`
	Dnsmasq struct {
		Text          string `xml:",chardata"`
		CustomOptions string `xml:"custom_options"`
		Interface     string `xml:"interface"`
		Hosts         struct {
			Text    string `xml:",chardata"`
			Host    string `xml:"host"`
			Domain  string `xml:"domain"`
			Ip      string `xml:"ip"`
			Descr   string `xml:"descr"`
			Aliases string `xml:"aliases"`
			Idx     string `xml:"idx"`
		} `xml:"hosts"`
	} `xml:"dnsmasq"`
	Ntpd struct {
		Text string `xml:",chardata"`
		Gps  struct {
			Text string `xml:",chardata"`
			Type string `xml:"type"`
		} `xml:"gps"`
	} `xml:"ntpd"`
	Checkipservices struct {
		Text                  string `xml:",chardata"`
		DisableFactoryDefault string `xml:"disable_factory_default"`
	} `xml:"checkipservices"`
	TrafficGraphs struct {
		Text             string `xml:",chardata"`
		If               string `xml:"if"`
		Sort             string `xml:"sort"`
		Filter           string `xml:"filter"`
		Hostipformat     string `xml:"hostipformat"`
		Backgroundupdate string `xml:"backgroundupdate"`
		Smoothfactor     string `xml:"smoothfactor"`
		Invert           string `xml:"invert"`
		Mode             string `xml:"mode"`
	} `xml:"traffic_graphs"`
	Sshdata struct {
		Text       string `xml:",chardata"`
		Sshkeyfile []struct {
			Text     string `xml:",chardata"`
			Filename string `xml:"filename"`
			Xmldata  string `xml:"xmldata"`
		} `xml:"sshkeyfile"`
	} `xml:"sshdata"`
} 
