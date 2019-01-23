package main

import "C"
import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"strings"
)

type rawWithOID struct {
	OID asn1.ObjectIdentifier
	Raw asn1.RawValue
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}
func createKeyValuePairs(m map[string]string) string {
	b := new(bytes.Buffer)
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {

		fmt.Fprintf(b, "%s:\"%s\"\n", name, m[name])

	}
	return b.String()
}

//export GetPSD2Cert
func GetPSD2Cert(inputString string) *C.char {
	return C.CString(parseCrt(inputString))
}

//export GetPSD2CertMap
func GetPSD2CertMap(inputString string, keys []string, values []string) int {

	mm := getPSD2Ext(inputString)
	println("delka:", len(mm))
	//m.length =0
	i := 0
	//keys_ := make([]string, len(mm) )
	//values_ := make([]string, len(mm))
	for name := range mm {
		println("key:", i, keys[i])
		keys[i] = name
		values[i] = mm[name]
		i++

	}

	return i
}

func parseCrt(inputStr string) string {

	certInfo := getPSD2Ext(inputStr)
	crtS := createKeyValuePairs(certInfo)
	return crtS

}
func readCRT(r io.Reader) string {
	str, err := ioutil.ReadAll(r)
	inputStr := string(str)
	check(err)
	return parseCrt(inputStr)
}

func getPSD2Ext(pemData string) map[string]string {

	certInfo := make(map[string]string)
	if !strings.Contains(pemData, "BEGIN CERTIFICATE") {
		pemData = strings.Replace(pemData, "%0A", "\n", -1)
		pemData = "-----BEGIN CERTIFICATE-----\n" + pemData + "-----END CERTIFICATE-----"
	}

	block, rest := pem.Decode([]byte(pemData))
	if block == nil || len(rest) > 0 {
		log.Fatal("Certificate decoding error")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	check(err)
	certInfo["certSubjectName"] = cert.Subject.Organization[0]
	certInfo["certIssuerOrganization"] = cert.Issuer.Organization[0]
	certInfo["certIssuerCommonName"] = cert.Issuer.Organization[0]
	certInfo["certSubjectCountry"] = cert.Subject.Country[0]
	certInfo["certSubjectSerialNumber"] = cert.Subject.SerialNumber
	certInfo["certValidFrom"] = cert.NotBefore.String()
	certInfo["certValidTo"] = cert.NotAfter.String()
	for e := range cert.Extensions {
		ext := cert.Extensions[e]
		if ext.Id.String() == "2.5.29.17" {
			var good []asn1.RawValue
			_, e := asn1.Unmarshal(ext.Value, &good)
			check(e)
			for _, element := range good {
				var good2 []asn1.RawValue
				_, e = asn1.Unmarshal(element.Bytes, &good2)
				if e == nil {
					for _, element2 := range good2 {
						var b rawWithOID
						_, e = asn1.Unmarshal(element2.Bytes, &b)
						check(e)
						if b.OID.String() == "2.5.4.54" {
							certInfo["certLicenceID"] = string(b.Raw.Bytes)
						}
						if b.OID.String() == "2.5.4.13" {
							certInfo["certRole"] = string(b.Raw.Bytes)
						}
					}
				} else {
					//var good2 asn1.ObjectIdentifier
					//_, e = asn1.Unmarshal(element.Bytes, &good2)
					//check(e)
					//fmt.Println(good2.String() + ":" + string(good2.String()))

				}

			}

		}
	}
	return certInfo
}

func main() {

	res := readCRT(os.Stdin)
	os.Stdout.WriteString(res)

}
