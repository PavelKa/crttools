package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"testing"
)

func TestParseCRT(t *testing.T) {
	expected := "{certSubjectName:\"Československá obchodní banka, a. s.\", certLicenceID:\"PS:CZ-00001350\", certRole:\"payment initiation, account servicing, account information, issuing of card-based payment instruments\"}"
	input := "MIIKMTCCCBmgAwIBAgIJAxuK3FSziFp5MA0GCSqGSIb3DQEBCwUAMHoxCzAJBgNV%0ABAYTAkNaMSMwIQYDVQQDDBpJLkNBIFNTTCBFViBDQS9SU0EgMTAvMjAxNzEtMCsG%0AA1UECgwkUHJ2bsOtIGNlcnRpZmlrYcSNbsOtIGF1dG9yaXRhLCBhLnMuMRcwFQYD%0AVQRhDA5OVFJDWi0yNjQzOTM5NTAeFw0xODA2MjExMjQyMzJaFw0xOTA2MjExMjQy%0AMzJaMIHmMQswCQYDVQQGEwJDWjEwMC4GA1UECgwnxIxlc2tvc2xvdmVuc2vDoSBv%0AYmNob2Ruw60gYmFua2EsIGEuIHMuMRowGAYDVQQJDBFSYWRsaWNrw6EgMzMzLzE1%0AMDERMA8GA1UEBwwIUHJhaGHCoDUxEDAOBgNVBBEMBzE1MMKgNTcxETAPBgNVBAUT%0ACDAwMDAxMzUwMR0wGwYDVQQPExRQcml2YXRlIE9yZ2FuaXphdGlvbjETMBEGCysG%0AAQQBgjc8AgEDEwJDWjEdMBsGA1UECAwUSGxhdm7DrSBtxJtzdG8gUHJhaGEwggIi%0AMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDDYB+4Ka8F9JcFsdW/QyhhGAMr%0AFsagI16gEAuhwgpF+pCK95K0fsLGy/+qVQhbXlsQWW3qrNiFQVw53In1TEwOatX9%0A70rIZyZmKc43F8ZvScwAukrwRJSImh19bE1jis4aPyGPGv0yFx9jpIFgfn/VcQmT%0AFlroIh5tDes2YcN4smaGZRKMuQ8pJQ2ySjYgKiUr2smglLuGe22QyaapACY73xPl%0AdJbrgoGQfq8fa+qu+RslSAYst1d+rZgsLstLjtvq6nlNZOgf3FFWjfghqzqaoGQo%0ANVS19NZQeS7iuSO1oXoGZgWKaKwmUfvR1BUK6XhcxM+mkVV8+yowtC25sMuDT4bL%0AkYAIIJi5akezDZsm+VQHiBoCLQdR6JX7QE4x7sv4dIRSQqUXD501V9IBmSbiQMtd%0AIwz9dYC/Ijw22RiqT6e1P2px2HpYvl7ZiktJjv+siWdN+ceuzYgIix13wvhrJPov%0Apj2n6E+mrPlLU0WnY6jhlDWN2gMErfh1q6u6x1MOXz/uqSBG1QVbCKJI4DFfVPE7%0AX8AJE0D2L5TvzUACBpNd5Pj5sBXhxZzH08LfLqy9mzzpHaQVkghqGuVpnkRMeHxI%0Aqns6+rok2z0/bOnZLMYv3ovvczeJFoTZ/fJZAdIysiAOE87cxI5rletaqx9pAJGD%0Ah1cIxVX+E5HK7nzl7wIDAQABo4IESzCCBEcwgeQGA1UdEQSB3DCB2aSBqjCBpzEX%0AMBUGA1UENhMOUFM6Q1otMDAwMDEzNTAxHDAaBgNVBC4TE0N6ZWNoIE5hdGlvbmFs%0AIEJhbmsxbjBsBgNVBA0TZXBheW1lbnQgaW5pdGlhdGlvbiwgYWNjb3VudCBzZXJ2%0AaWNpbmcsIGFjY291bnQgaW5mb3JtYXRpb24sIGlzc3Vpbmcgb2YgY2FyZC1iYXNl%0AZCBwYXltZW50IGluc3RydW1lbnRzghBiYXBpdGVzdC5jc29iLmN6oBgGCisGAQQB%0AgbhIBAagCgwIMTA0NjQ3NzMwCQYDVR0TBAIwADCCAUIGA1UdIASCATkwggE1MIIB%0AHQYNKwYBBAGBuEgKASMBADCCAQowHQYIKwYBBQUHAgEWEWh0dHA6Ly93d3cuaWNh%0ALmN6MIHoBggrBgEFBQcCAjCB2xqB2FRlbnRvIGt2YWxpZmlrb3ZhbnkgY2VydGlm%0AaWthdCBwcm8gYXV0ZW50aXphY2kgaW50ZXJuZXRvdnljaCBzdHJhbmVrIGJ5bCB2%0AeWRhbiB2IHNvdWxhZHUgcyBuYXJpemVuaW0gRVUgYy4gOTEwLzIwMTQuVGhpcyBp%0AcyBhIHF1YWxpZmllZCBjZXJ0aWZpY2F0ZSBmb3Igd2Vic2l0ZSBhdXRoZW50aWNh%0AdGlvbiBhY2NvcmRpbmcgdG8gUmVndWxhdGlvbiAoRVUpIE5vIDkxMC8yMDE0LjAH%0ABgVngQwBATAJBgcEAIvsQAEEMIGMBgNVHR8EgYQwgYEwKaAnoCWGI2h0dHA6Ly9x%0AY3JsZHAxLmljYS5jei9xY3cxN19yc2EuY3JsMCmgJ6AlhiNodHRwOi8vcWNybGRw%0AMi5pY2EuY3ovcWN3MTdfcnNhLmNybDApoCegJYYjaHR0cDovL3FjcmxkcDMuaWNh%0ALmN6L3FjdzE3X3JzYS5jcmwwYwYIKwYBBQUHAQEEVzBVMCkGCCsGAQUFBzAChh1o%0AdHRwOi8vcS5pY2EuY3ovcWN3MTdfcnNhLmNlcjAoBggrBgEFBQcwAYYcaHR0cDov%0AL29jc3AuaWNhLmN6L3FjdzE3X3JzYTAOBgNVHQ8BAf8EBAMCBaAwgakGCCsGAQUF%0ABwEDBIGcMIGZMAgGBgQAjkYBATATBgYEAI5GAQYwCQYHBACORgEGAzBVBgYEAI5G%0AAQUwSzAsFiZodHRwOi8vd3d3LmljYS5jei9acHJhdnktcHJvLXV6aXZhdGVsZRMC%0AY3MwGxYVaHR0cDovL3d3dy5pY2EuY3ovUERTEwJlbjAhBggrBgEFBQcLAjAVMBOG%0AEWh0dHA6Ly93d3cuY25iLmN6MB8GA1UdIwQYMBaAFD2vGQiXehCMvCjBRm2XSFpI%0A/ALKMB0GA1UdDgQWBBRIHOAdAYezK2lraTUzMXofKF5QnjAdBgNVHSUEFjAUBggr%0ABgEFBQcDAQYIKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADggIBAJ7HMT46RFZB5m4N%0As/3kK7yTWts+qxZmNS8hl6wEuEbJSBLipXCJ1mldGhdwqfUtfzb/BvV5nAs1nGp5%0A18vukEUzFUIGn/nulEc5Vxw4AoZcIljC8h7CwbnqxmcPfwAxlYNe+YBSxWCtN1ZI%0AIVsgE6g5XGd2eSV7Y9up+V6uQAwXM2BGE8ezfcV1NiWjBDY+m/Zq1/euJ/MfvzM4%0AtqYiiruMLC2xqKVZcFFtznOiMc16Wc9ShSccf+bganzdMphq5XFQAEmGTavHgyFQ%0ALvSGmSYrkOxsL4dEmadTHSdc4FkLWEEX9dRsMgn7hktUUivyD69JyFOWyxreIito%0AgAs8BCDvvaymvokSm0Y78t2o3wfE2zh6Lw4Aac4giI2nhzC20BqzvQhKbSlQ2RNA%0AQ+ww3+f21cg9lUP6dNkJ8emfCOQZhptjI2D7E4pzy3GHlYfIrAxKlE1OZcXkNhV0%0AelxYpW7hFiRCF79mRIcKgSJv3lmgS/T88v3HuTAC8ppB4yJfG+U51XyVkkAlonkg%0AJ/T2LUsOJ/YRL6Ct6JRx6DI95ROktdqh1uoTU51b1qeyHJsY544G6K0B2YFFi5T4%0AOn+EPvYK8xR8/8/h2RTXbWScrt4DLGVvgTkEBfZb/YvgnV9yzW/szwounD67zo4j%0AxNJAztggXV7VczEBv4oGnyP7n61E%0A"
	stdin := strings.NewReader(input)

	result := readCRT(stdin)

	if expected != result {
		t.Errorf("Wanted: %v, Got: %v", expected+"\n", result)
	}

}

type SAN struct {
	Extensions []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

func Check(e error, s string) {
	if e != nil {
		fmt.Println(s+": ", e)
	}
}
func checkP(e error) {
	if e != nil {
		panic(e)
	}
}
func TestParseCRT2(*testing.T) {
	// Read and parse the PEM certificate file

	pemData := "MIIKMTCCCBmgAwIBAgIJAxuK3FSziFp5MA0GCSqGSIb3DQEBCwUAMHoxCzAJBgNV%0ABAYTAkNaMSMwIQYDVQQDDBpJLkNBIFNTTCBFViBDQS9SU0EgMTAvMjAxNzEtMCsG%0AA1UECgwkUHJ2bsOtIGNlcnRpZmlrYcSNbsOtIGF1dG9yaXRhLCBhLnMuMRcwFQYD%0AVQRhDA5OVFJDWi0yNjQzOTM5NTAeFw0xODA2MjExMjQyMzJaFw0xOTA2MjExMjQy%0AMzJaMIHmMQswCQYDVQQGEwJDWjEwMC4GA1UECgwnxIxlc2tvc2xvdmVuc2vDoSBv%0AYmNob2Ruw60gYmFua2EsIGEuIHMuMRowGAYDVQQJDBFSYWRsaWNrw6EgMzMzLzE1%0AMDERMA8GA1UEBwwIUHJhaGHCoDUxEDAOBgNVBBEMBzE1MMKgNTcxETAPBgNVBAUT%0ACDAwMDAxMzUwMR0wGwYDVQQPExRQcml2YXRlIE9yZ2FuaXphdGlvbjETMBEGCysG%0AAQQBgjc8AgEDEwJDWjEdMBsGA1UECAwUSGxhdm7DrSBtxJtzdG8gUHJhaGEwggIi%0AMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDDYB+4Ka8F9JcFsdW/QyhhGAMr%0AFsagI16gEAuhwgpF+pCK95K0fsLGy/+qVQhbXlsQWW3qrNiFQVw53In1TEwOatX9%0A70rIZyZmKc43F8ZvScwAukrwRJSImh19bE1jis4aPyGPGv0yFx9jpIFgfn/VcQmT%0AFlroIh5tDes2YcN4smaGZRKMuQ8pJQ2ySjYgKiUr2smglLuGe22QyaapACY73xPl%0AdJbrgoGQfq8fa+qu+RslSAYst1d+rZgsLstLjtvq6nlNZOgf3FFWjfghqzqaoGQo%0ANVS19NZQeS7iuSO1oXoGZgWKaKwmUfvR1BUK6XhcxM+mkVV8+yowtC25sMuDT4bL%0AkYAIIJi5akezDZsm+VQHiBoCLQdR6JX7QE4x7sv4dIRSQqUXD501V9IBmSbiQMtd%0AIwz9dYC/Ijw22RiqT6e1P2px2HpYvl7ZiktJjv+siWdN+ceuzYgIix13wvhrJPov%0Apj2n6E+mrPlLU0WnY6jhlDWN2gMErfh1q6u6x1MOXz/uqSBG1QVbCKJI4DFfVPE7%0AX8AJE0D2L5TvzUACBpNd5Pj5sBXhxZzH08LfLqy9mzzpHaQVkghqGuVpnkRMeHxI%0Aqns6+rok2z0/bOnZLMYv3ovvczeJFoTZ/fJZAdIysiAOE87cxI5rletaqx9pAJGD%0Ah1cIxVX+E5HK7nzl7wIDAQABo4IESzCCBEcwgeQGA1UdEQSB3DCB2aSBqjCBpzEX%0AMBUGA1UENhMOUFM6Q1otMDAwMDEzNTAxHDAaBgNVBC4TE0N6ZWNoIE5hdGlvbmFs%0AIEJhbmsxbjBsBgNVBA0TZXBheW1lbnQgaW5pdGlhdGlvbiwgYWNjb3VudCBzZXJ2%0AaWNpbmcsIGFjY291bnQgaW5mb3JtYXRpb24sIGlzc3Vpbmcgb2YgY2FyZC1iYXNl%0AZCBwYXltZW50IGluc3RydW1lbnRzghBiYXBpdGVzdC5jc29iLmN6oBgGCisGAQQB%0AgbhIBAagCgwIMTA0NjQ3NzMwCQYDVR0TBAIwADCCAUIGA1UdIASCATkwggE1MIIB%0AHQYNKwYBBAGBuEgKASMBADCCAQowHQYIKwYBBQUHAgEWEWh0dHA6Ly93d3cuaWNh%0ALmN6MIHoBggrBgEFBQcCAjCB2xqB2FRlbnRvIGt2YWxpZmlrb3ZhbnkgY2VydGlm%0AaWthdCBwcm8gYXV0ZW50aXphY2kgaW50ZXJuZXRvdnljaCBzdHJhbmVrIGJ5bCB2%0AeWRhbiB2IHNvdWxhZHUgcyBuYXJpemVuaW0gRVUgYy4gOTEwLzIwMTQuVGhpcyBp%0AcyBhIHF1YWxpZmllZCBjZXJ0aWZpY2F0ZSBmb3Igd2Vic2l0ZSBhdXRoZW50aWNh%0AdGlvbiBhY2NvcmRpbmcgdG8gUmVndWxhdGlvbiAoRVUpIE5vIDkxMC8yMDE0LjAH%0ABgVngQwBATAJBgcEAIvsQAEEMIGMBgNVHR8EgYQwgYEwKaAnoCWGI2h0dHA6Ly9x%0AY3JsZHAxLmljYS5jei9xY3cxN19yc2EuY3JsMCmgJ6AlhiNodHRwOi8vcWNybGRw%0AMi5pY2EuY3ovcWN3MTdfcnNhLmNybDApoCegJYYjaHR0cDovL3FjcmxkcDMuaWNh%0ALmN6L3FjdzE3X3JzYS5jcmwwYwYIKwYBBQUHAQEEVzBVMCkGCCsGAQUFBzAChh1o%0AdHRwOi8vcS5pY2EuY3ovcWN3MTdfcnNhLmNlcjAoBggrBgEFBQcwAYYcaHR0cDov%0AL29jc3AuaWNhLmN6L3FjdzE3X3JzYTAOBgNVHQ8BAf8EBAMCBaAwgakGCCsGAQUF%0ABwEDBIGcMIGZMAgGBgQAjkYBATATBgYEAI5GAQYwCQYHBACORgEGAzBVBgYEAI5G%0AAQUwSzAsFiZodHRwOi8vd3d3LmljYS5jei9acHJhdnktcHJvLXV6aXZhdGVsZRMC%0AY3MwGxYVaHR0cDovL3d3dy5pY2EuY3ovUERTEwJlbjAhBggrBgEFBQcLAjAVMBOG%0AEWh0dHA6Ly93d3cuY25iLmN6MB8GA1UdIwQYMBaAFD2vGQiXehCMvCjBRm2XSFpI%0A/ALKMB0GA1UdDgQWBBRIHOAdAYezK2lraTUzMXofKF5QnjAdBgNVHSUEFjAUBggr%0ABgEFBQcDAQYIKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADggIBAJ7HMT46RFZB5m4N%0As/3kK7yTWts+qxZmNS8hl6wEuEbJSBLipXCJ1mldGhdwqfUtfzb/BvV5nAs1nGp5%0A18vukEUzFUIGn/nulEc5Vxw4AoZcIljC8h7CwbnqxmcPfwAxlYNe+YBSxWCtN1ZI%0AIVsgE6g5XGd2eSV7Y9up+V6uQAwXM2BGE8ezfcV1NiWjBDY+m/Zq1/euJ/MfvzM4%0AtqYiiruMLC2xqKVZcFFtznOiMc16Wc9ShSccf+bganzdMphq5XFQAEmGTavHgyFQ%0ALvSGmSYrkOxsL4dEmadTHSdc4FkLWEEX9dRsMgn7hktUUivyD69JyFOWyxreIito%0AgAs8BCDvvaymvokSm0Y78t2o3wfE2zh6Lw4Aac4giI2nhzC20BqzvQhKbSlQ2RNA%0AQ+ww3+f21cg9lUP6dNkJ8emfCOQZhptjI2D7E4pzy3GHlYfIrAxKlE1OZcXkNhV0%0AelxYpW7hFiRCF79mRIcKgSJv3lmgS/T88v3HuTAC8ppB4yJfG+U51XyVkkAlonkg%0AJ/T2LUsOJ/YRL6Ct6JRx6DI95ROktdqh1uoTU51b1qeyHJsY544G6K0B2YFFi5T4%0AOn+EPvYK8xR8/8/h2RTXbWScrt4DLGVvgTkEBfZb/YvgnV9yzW/szwounD67zo4j%0AxNJAztggXV7VczEBv4oGnyP7n61E%0A"
	pemDatar := strings.Replace(pemData, "%0A", "\n", -1)
	pemDataC := "-----BEGIN CERTIFICATE-----\n" + pemDatar + "-----END CERTIFICATE-----"
	// 	fmt.Println(pemDataC)

	block, rest := pem.Decode([]byte(pemDataC))
	if block == nil || len(rest) > 0 {
		log.Fatal("Certificate decoding error")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	for e := range cert.Extensions {
		ext := cert.Extensions[e]
		if ext.Id.String() == "2.5.29.17" {
			var good []asn1.RawValue
			fmt.Println(ext.Value)
			_, e := asn1.Unmarshal(ext.Value, &good)
			Check(e, "good RawValue")
			for _, element := range good {
				var good2 []asn1.RawValue
				_, e = asn1.Unmarshal(element.Bytes, &good2)
				if e == nil {
					for _, element2 := range good2 {
						var b RawWithOID
						_, e = asn1.Unmarshal(element2.Bytes, &b)

						Check(e, "good 2 RawWithOID")

						fmt.Println(b.OID.String() + ":" + string(b.Raw.Bytes))
					}
				} else {
					var good2 asn1.ObjectIdentifier
					_, e = asn1.Unmarshal(element.Bytes, &good2)
					Check(e, "good2 asn1.ObjectIdentifier")
					fmt.Println(good2.String() + ":" + string(good2.String()))

				}

			}

		}
	}
}
