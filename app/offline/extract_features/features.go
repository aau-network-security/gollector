package extract_features

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/rs/zerolog/log"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

type DomainType int

type ValidationLevel int

const (
	DV ValidationLevel = 1
	OV ValidationLevel = 2
	EV ValidationLevel = 3
)

var (
	dv = asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1}
	ov = asn1.ObjectIdentifier{2, 23, 140, 1, 2, 2}
	ev = asn1.ObjectIdentifier{2, 23, 140, 1, 1}
)

func getValidationLevel(c *x509.Certificate) sql.NullInt64 {
	vl := sql.NullInt64{
		Int64: 0,
		Valid: true,
	}
	for _, pi := range c.PolicyIdentifiers {
		if pi.Equal(dv) {
			vl.Int64 = int64(DV)
			break
		} else if pi.Equal(ov) {
			vl.Int64 = int64(OV)
			break
		} else if pi.Equal(ev) {
			vl.Int64 = int64(EV)
			break
		}
	}

	if vl.Int64 == 0 {
		vl.Valid = false
	}
	return vl
}

type SanFeatures struct {
	lcs             LcsStats
	apexes          StringStats
	tlds            StringStats
	slds            StringStats
	subdomainLabels IntStats
	sans            IntStats
}

func isIp(name *publicsuffix.DomainName) bool {
	_, err := strconv.Atoi(name.TLD)
	return err == nil
}

func isSuffixErr(err error) bool {
	return err != nil && strings.HasSuffix(err.Error(), "is a suffix")
}

func getSanFeatures(c *x509.Certificate) SanFeatures {
	lcs := NewLcsStats()
	tlds := NewStringStats()
	apexes := NewStringStats()
	slds := NewStringStats()
	subdomainLabels := NewIntStats()
	sans := NewIntStats()

	for _, san := range c.DNSNames {
		sans.Add(utf8.RuneCountInString(san))

		domain, err := publicsuffix.Parse(san)

		if err != nil {
			if isSuffixErr(err) {
				tlds.Add(san)
				apexes.Add(san)
				log.Debug().Msgf("SAN is suffix: %s", san)
			} else {
				log.Warn().Msgf("Failed to parse SAN '%s': %s", san, err)
			}
			continue
		} else if domain.Rule.Type == 2 && isIp(domain) {
			log.Debug().Msgf("SAN '%s' is an IP address (will be ignored for tld count, apex counts and LCS", san)
			continue
		}

		apex := fmt.Sprintf("%s.%s", domain.SLD, domain.TLD)
		apexes.Add(apex)
		tlds.Add(domain.TLD)
		slds.Add(domain.SLD)

		nSubdomainLabels := 0
		if domain.TRD != "" {
			nSubdomainLabels = len(strings.Split(domain.TRD, "."))
		}
		subdomainLabels.Add(nSubdomainLabels)

		lcs.Add(domain.SLD)
	}

	return SanFeatures{
		lcs:             lcs,
		tlds:            tlds,
		apexes:          apexes,
		slds:            slds,
		subdomainLabels: subdomainLabels,
		sans:            sans,
	}
}
