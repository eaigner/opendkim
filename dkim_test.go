package opendkim

import (
	"bytes"
	"strings"
	"testing"
	// "unsafe"
)

var msgHdr = map[string]string{
	"Date":                      "Sun, 3 Mar 2013 16:43:40 +0100",
	"From":                      "Chocomoko <a@b.com>",
	"To":                        "Erik Aigner <b@c.com>",
	"Subject":                   "Fw: Homepage",
	"MIME-Version":              "1.0",
	"Content-Type":              "text/plain; charset=\"utf-8\"",
	"Content-Transfer-Encoding": "quoted-printable",
	"Content-Disposition":       "inline",
}

var msgBody = "> B=C3=BCro\r\n"

const (
	domain   = "erikk.org"
	selector = "odktest"
)

// Private key for test TXT entry
//
// http://www.port25.com/support/domainkeysdkim-wizard/
//
// odktest._domainkey.erikk.org IN TXT "k=rsa\; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtVt0PPhhNRO4hgbDPyS2BsoiHslcq3TFe4jYaTntjh47U2wH5QbdGXke+zRQ14PT5CNU9nJg48+tRjSOgKR/Bu+D5XmNbB+pNYEoafKDZky8BHRthQ6hyAbhF9QypDkvzavRENLK68M01IfGA2l3CpClyfMs8/gkB0Grp9tQSSMVQdo5Cse93ikLM22MggilCeFqAVc5d2ATC0gT90edq46ImzOQk10VZ8avJx2bu/Sve+3GLirppB0/gXga/80i3NNIlHq0S4LeMScIQxXCY4c6/zfCiLKKm57aXLClMYPivi/TpfwaEWPbB/cRmpy3ZfLlAMA4LO+7+iJ1dy5aCQIDAQAB"
//
var testKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAtVt0PPhhNRO4hgbDPyS2BsoiHslcq3TFe4jYaTntjh47U2wH
5QbdGXke+zRQ14PT5CNU9nJg48+tRjSOgKR/Bu+D5XmNbB+pNYEoafKDZky8BHRt
hQ6hyAbhF9QypDkvzavRENLK68M01IfGA2l3CpClyfMs8/gkB0Grp9tQSSMVQdo5
Cse93ikLM22MggilCeFqAVc5d2ATC0gT90edq46ImzOQk10VZ8avJx2bu/Sve+3G
LirppB0/gXga/80i3NNIlHq0S4LeMScIQxXCY4c6/zfCiLKKm57aXLClMYPivi/T
pfwaEWPbB/cRmpy3ZfLlAMA4LO+7+iJ1dy5aCQIDAQABAoIBAQCC72hYrKrh+z75
5OAKMqMI+97ug0rYrxH1QrOcJSqRtNn4PMLmY7I1tfDcRMUpFBBjYe7xj1rMnx/m
1AMedaUQiNSdVMj6C1HLQ1i+RU0BCt2kCbsYmZvMIstYvOdjEbalsyraDpZa6TC3
UN9xjy9W/V/1EhCeg8TfSFZ6dijc47RMfVKX1VwE7Q1KY16TdsBjLcHd611ccyTc
7LKEhrJmaO9eVsh0TnB9FWRIeUfic7/dyO3/o8k+XRuK6xCFpAIsRSDpR9HdwJar
LWQoJ3hsA51kwdgch3DpHQa+WDPcAwjhd+sLLJcOsTa4J3Jikvdu/2JVeQMM+24y
WcYUsbRBAoGBANlIbkIjhuz7PEIWRdn9ajh/8LbW+x81s+pm2gf+kTc2EcsSLSX8
CHZQyy7yzCHJv11gGX81OaYQRps03szwcO3Q1jM5ZTlao5J/nuFTMSPCE+LgIwJV
pY3sp7GKv8so/vChGvHOiFVpp9mu15aNxlt3StulnIqL0sIaZ9HXnhNlAoGBANWs
PRJhz4AsC+qClhYpsdvrGZjZ0wGQd6CPChYuB/lFOtTpiRh8wq/dXKot4disZOBw
JB1fuyIblZOR7MIp/49bM3v9TmybByLFLqVAYXIubLFOEcJv8/YfffHlk1j1+nSc
SY4t+lMKPv642rCEE3FeWxJEjIeSiO3wkQUQCWvVAoGBAIh++dTOoKoqwZX6i/L/
QUUxCjSyJJtcjyOHbRxsjSkT7GWXi4k7JM2+v4VEvXvUU0UDY8EH3Kk3vEMwGW7A
9RBQit8vBSnciLk1NsfyDQKbnwZ9K0ECMLhRnJ7pvMaRgGYFrvmMdxTBBNK5BXHs
qlk3PW1yQj6+y61oDSRDwWgJAoGAbh4w7ztHRAfvMDGSheOBDRSRgYuoyiKY9D8j
dKDObTG3iyi8BcmuUBImAnJY9WCLMHu6sQS4HXDX2lCXEs2wLkJTOzAlbaVLvSif
zHxse/re+1V/o5Qsx4gdUT/+exdxtw0gf0zEuG0MYBwGYHgAySlWiAiZ3/it5upW
4qQMJu0CgYAI/dGo46K4aHW8t6QDY9YaOAJ6MIshavEQySIxcWw81gNhjVOM/QWf
+j90ZVKzmmPJbC170i6RNl5QRPLhxlx4uzflMKaGvR4ffqqlasUv3okV74IBuo7+
nSZOSkTBu27e+ZRMa+5VEZchWazUlixTxvPl6T7dK1kVPZ5vRioFSA==
-----END RSA PRIVATE KEY-----`

func process(hdr map[string]string, body string, d *Dkim, t *testing.T) {
	for h, line := range hdr {
		err := d.Header(h + `: ` + line)
		if err != nil {
			t.Fatal(err)
		}
	}
	err := d.Eoh()
	if err != nil {
		t.Fatal(err)
	}
	err = d.Body([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	var testKey bool
	err = d.Eom(&testKey)
	if err != nil {
		t.Log(d.GetError())
		t.Fatal(err)
	}
}

func logMsg(hdr map[string]string, body string, t *testing.T) {
	var buf bytes.Buffer
	for k, v := range hdr {
		buf.WriteString(k + `: ` + v + "\r\n")
	}
	buf.WriteString("\r\n")
	buf.WriteString(body)

	t.Log(buf.String())
}

func TestSignAndVerify(t *testing.T) {
	lib := Init()
	defer lib.Close()

	d, err := lib.NewSigner(
		testKey,
		selector,
		domain,
		CanonRELAXED,
		CanonRELAXED,
		SignRSASHA1,
		-1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if d == nil {
		t.Fatal()
	}

	process(msgHdr, msgBody, d, t)

	h, err := d.GetSigHdr()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "v=1") {
		t.Fatal(h)
	}

	t.Log("VERIFY")
	t.Log(h)
	d.Destroy()

	var hdr = make(map[string]string)
	for k, v := range msgHdr {
		hdr[k] = v
	}
	hdr["DKIM-Signature"] = h

	logMsg(hdr, msgBody, t)

	d2, err := lib.NewVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if d2 == nil {
		t.Fatal()
	}

	process(hdr, msgBody, d2, t)

	sig, err := d2.GetSignature()
	if err != nil {
		t.Fatal(err)
	}
	err = sig.Process()
	if err != nil {
		t.Fatal(err)
	}
	flags := sig.Flags()

	/*
		assert((flags & DKIM_SIGFLAG_PROCESSED) != 0);
		assert((flags & DKIM_SIGFLAG_IGNORE) == 0);
		assert((flags & DKIM_SIGFLAG_PASSED) != 0);
		assert(dkim_sig_getbh(sigs[0]) == DKIM_SIGBH_MATCH);
	*/

	if x := (flags & SigflagPROCESSED); x == 0 {
		t.Fatal(x)
	}
	if x := (flags & SigflagIGNORE); x != 0 {
		t.Fatal(x)
	}
	if x := (flags & SigflagPASSED); x == 0 {
		t.Fatal(x)
	}
}
