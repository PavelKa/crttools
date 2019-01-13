package main

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

type RawWithOID struct {
	OID asn1.ObjectIdentifier
	Raw asn1.RawValue
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func readCRT(r io.Reader) string {
	str, err := ioutil.ReadAll(r)
	inputStr := string(str)
	check(err)
	certSubjectName, certLicenceID, certRole := getPSD2Ext(inputStr)
	return fmt.Sprintf("certSubjectName:\"%v\"\ncertLicenceID:\"%v\"\ncertRole:\"%v\"", certSubjectName, certLicenceID, certRole)
}

func getPSD2Ext(pemData string) (certSubjectName, certLicenceID, certRole string) {
	pemDatar := strings.Replace(pemData, "%0A", "\n", -1)
	pemDataC := "-----BEGIN CERTIFICATE-----\n" + pemDatar + "-----END CERTIFICATE-----"
	//	fmt.Println(pemDataC)

	block, rest := pem.Decode([]byte(pemDataC))
	if block == nil || len(rest) > 0 {
		log.Fatal("Certificate decoding error")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	check(err)
	certSubjectName = cert.Subject.Organization[0]
	println(cert)
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
						var b RawWithOID
						_, e = asn1.Unmarshal(element2.Bytes, &b)
						check(e)
						if b.OID.String() == "2.5.4.54" {
							certLicenceID = string(b.Raw.Bytes)
						}
						if b.OID.String() == "2.5.4.13" {
							certRole = string(b.Raw.Bytes)
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
	return certSubjectName, certLicenceID, certRole
}

func main() {

	res := readCRT(os.Stdin)
	os.Stdout.WriteString(res + "neco je blbe\n")

}
