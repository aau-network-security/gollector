package main

import (
	"flag"
	"fmt"
	"github.com/aau-network-security/go-domains/generic"
	"github.com/aau-network-security/go-domains/store"
	"github.com/aau-network-security/go-domains/zone"
	"github.com/aau-network-security/go-domains/zone/czds"
	"github.com/aau-network-security/go-domains/zone/ftp"
	"github.com/aau-network-security/go-domains/zone/http"
	"github.com/aau-network-security/go-domains/zone/ssh"
	"github.com/rs/zerolog/log"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net"
	"os"
	"sync"
	"time"
)

const (
	ComFtpPass = "COM_FTP_PASS"
	CzdsPass   = "CZDS_PASS"
	DkSshPass  = "DK_SSH_PASS"
)

type Com struct {
	Ftp        ftp.Config `yaml:"ftp"`
	SshEnabled bool       `yaml:"ssh-enabled"`
	Ssh        ssh.Config `yaml:"ssh"`
}

type Dk struct {
	Http http.Config `yaml:"http"`
	Ssh  ssh.Config  `yaml:"ssh"`
}

type Czds struct {
	Tlds  []string         `yaml:"tlds"`
	Creds czds.Credentials `yaml:"credentials"`
}

type config struct {
	Com   Com          `yaml:"com"`
	Czds  Czds         `yaml:"czds"`
	Dk    Dk           `yaml:"dk"`
	Store store.Config `yaml:"store"`
}

func readConfig(path string) (config, error) {
	var conf config
	f, err := ioutil.ReadFile(path)
	if err != nil {
		return conf, err
	}
	if err := yaml.Unmarshal(f, &conf); err != nil {
		return conf, err
	}

	conf.Com.Ftp.Password = os.Getenv(ComFtpPass)
	conf.Czds.Creds.Password = os.Getenv(CzdsPass)
	conf.Dk.Ssh.Password = os.Getenv(DkSshPass)

	for _, env := range []string{ComFtpPass, CzdsPass, DkSshPass} {
		os.Setenv(env, "")
	}

	return conf, nil
}

type zoneConfig struct {
	zone           zone.Zone
	streamWrappers []zone.StreamWrapper
	streamHandler  zone.StreamHandler
	decoder        *encoding.Decoder
}

func main() {
	confFile := flag.String("config", "config/config.yml", "location of configuration file")
	flag.Parse()

	conf, err := readConfig(*confFile)
	if err != nil {
		log.Fatal().Msgf("error while reading configuration: %s", err)
	}

	s, err := store.NewStore(conf.Store, 20000, time.Hour*36)
	if err != nil {
		log.Fatal().Msgf("error while creating store: %s", err)
	}
	_ = s

	f := func(t time.Time) error {
		wg := sync.WaitGroup{}
		var zoneConfigs []zoneConfig

		for _, tld := range conf.Czds.Tlds {
			cred := czds.Credentials{
				Username: conf.Czds.Creds.Username,
				Password: conf.Czds.Creds.Password,
			}
			z := czds.New(cred, tld)
			zc := zoneConfig{
				z,
				[]zone.StreamWrapper{zone.GzipWrapper},
				zone.ZoneFileHandler,
				nil,
			}

			zoneConfigs = append(zoneConfigs, zc)
		}

		var sshDialFunc func(network, address string) (net.Conn, error)
		if conf.Com.SshEnabled {
			sshDialFunc, err = ssh.DialFunc(conf.Com.Ssh)
			if err != nil {
				log.Fatal().Msgf("failed to create SSH dial func: %s", err)
			}
		}
		comZone, err := ftp.New(conf.Com.Ftp, sshDialFunc)
		if err != nil {
			log.Fatal().Msgf("failed to create .com zone retriever: %s", err)
		}

		httpClient, err := ssh.HttpClient(conf.Dk.Ssh)
		dkZone, err := http.New(conf.Dk.Http, httpClient)
		if err != nil {
			log.Fatal().Msgf("failed to create .dk zone retriever: %s", err)
		}

		zoneConfigs = append(zoneConfigs, []zoneConfig{
			{
				comZone,
				[]zone.StreamWrapper{zone.GzipWrapper},
				zone.ZoneFileHandler,
				nil,
			},
			{
				dkZone,
				nil,
				zone.ListHandler,
				charmap.ISO8859_1.NewDecoder(),
			},
		}...)
		wg.Add(len(zoneConfigs))
		progress := 0
		for _, zc := range zoneConfigs {
			go func(zc zoneConfig) {
				defer wg.Done()

				c := 0
				domainFunc := func(domain []byte) error {
					c++
					if zc.decoder != nil {
						var err error
						domain, err = zc.decoder.Bytes(domain)
						if err != nil {
							return err
						}
					}

					_, err := s.StoreZoneEntry(t, string(domain))
					if err != nil {
						log.Debug().Msgf("failed to store domain '%s': %s", domain, err)
					}
					return nil
				}

				opts := zone.ProcessOpts{
					DomainFunc:     domainFunc,
					StreamWrappers: zc.streamWrappers,
					StreamHandler:  zc.streamHandler,
				}

				resultStatus := "ok"
				if err := zone.Process(zc.zone, opts); err != nil {
					log.Error().Msgf("error while processing zone file: %s", err)
					resultStatus = "failed"
				}
				progress++

				log.Info().
					Str("status", resultStatus).
					Str("progress", fmt.Sprintf("%d/%d", progress, len(zoneConfigs))).
					Int("processed domains", c).
					Msgf("finished zone '%s'", zc.zone.Tld())
			}(zc)
		}

		wg.Wait()

		return s.RunPostHooks()
	}

	// retrieve all zone files on a daily basis
	if err := generic.Repeat(f, time.Now(), time.Hour*24, -1); err != nil {
		log.Fatal().Msgf("error while retrieving zone files: %s", err)
	}
}
