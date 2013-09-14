package opendkim

import (
	"strings"
	"testing"
)

var msgHdr = []string{
	"Date: Sun, 3 Mar 2013 16:43:40 +0100",
	"From: Chocomoko <a@b.com>",
	"To: Erik Aigner <b@c.com>",
	"Subject: Fw: Homepage",
	"MIME-Version: 1.0",
	"Content-Type: text/plain; charset=\"utf-8\"",
	"Content-Transfer-Encoding: quoted-printable",
	"Content-Disposition: inline",
}

var msgBody = "> B=C3=BCro\r\n"

var testKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3QsuCnwzngDy9n1evQqnETIfRV98wRQFhJoB9v/CRoyApd8L
iJkTXXTYhiJuM/4hR/7Jt3hoKNQ0jXVPMdibNfyWFPrNzUEMTuGs68C0Sa0kr/Bp
L+MT5UBNqm6wqNCTYyzrroDC88bXfN5gu298K5Qp2/nFpnyUrGBkWBfi7eBhrrv+
KgtI0PbkYG8XDXt9T7EkYJDFgFzsoC1d8Y+5HbaV/WzOSjAW28V0jVl3OfEr1/tl
BtlYy8zmH0PLG/RjVKW9pdtt8LpUmqRJWCPQGLRnCtqMjlhA/BeUS7gdb3XkHM9M
rST46VwLjp6EFSeqZyX5SLUXWbBVpsu0ArGtiQIDAQABAoIBAQCddMVLOsYaG1r3
Mr81skzn9uhHpolbkEON/ZbAt9dQIe3SOlwg5cnhnMZQZl5SMwjKHDjctKydyOvW
iGXtf/qwLklKkI3hVCDMX/2pwg+rG+cyXPLQ5dTaTUAF0+uLlWgoEWuhVp+Iv2/o
xw/o9LVi5Zwb0oR03/GYCOHxzrIb95L84suQF6AnLYuyuKIgVy2v7Pc57XYy6POY
0MDMmiIdVGS5zOvQXUyEQG+4MJYeYHkstOhhouUwvpdaHqp2HJ2O8ieHOJIXb5Tt
+dpaaebP9zcV+Vdt8yqACyc8uO6t4cC20SolPLAUpqUVFG5fS+IQQ9pJvL2ZJPta
Iu78yOgBAoGBAPawYA2+AtBcu06cueV0pljEwPwaMP7WtkW0KZS6KCJZReIL3/TH
dRKCIs0jhObh31S4WvlQ4uO9JJ60B1nfEyKcxqZHBm8Vg5+4Wy+12b8kGf4fw/+F
i+jM+44ciZtiU0EBzOoA7QGDgXNGu96mPsKUJwmxsVIHPxIwH16k/qbJAoGBAOVj
AfuBUG/cuGvu+6/vguua6fn0cbfJ9ykd3tbO+rZKXB3rh/MJHk+DCvnAu+WFrf74
8b+ptIcnxhZ065DdB8AB/YuHdF2uFbb7KosULEWtIPZpoIjTqHqPXzEy7nvfShVc
O5uaIP5YBSOAfZL3OL2OId0n8VPMsT6OFkAAznDBAoGAfIJtGMKMvQnw6C6mjS+h
PjCgjx3RGO7aNLhIPG7xDtUsNnlz4iJB7sOMOSnyTG44wJQEJs4ylmvC7e9DvpKf
H9stUIOMtciQFK+CJsSMULMyA1eZH4ESKsA7P3Eb6zdneeokuP8aoKb1UW+kJy6V
grQwN+5d518M8GsliimQ9jECgYEAzYMy13437sC1ih4G6M2RYjzcu9DBwYP1KKVW
bOXrwT5F4ZiPqLLWsS4au0BuF2j5RqMLFEibMSv1UVFXa+Zbdy9RVZz6KKQ7WEEX
EJv2PkaqbZqc9XmMTKH/CzkyaVDYMuL7lKE2RineELyhxPYxo8KfnGCY2hdeBUmP
rbALRQECgYBSEbvBZaRjkc6tjBUzw1aa2xSuIb9Funiq3PSgZe8cBzNGkyGEiQ+/
mhYWtlsGKiCC9zzkBuVG1YLWDFrur6Lf5/XO+Mgnz896g2njrQdX9ZAJ3fNjh0IW
S8a5cVHhcMY+6k3RcP9xncgY8vsZGxhnfH+b4haCm6RprplNY+4wQA==
-----END RSA PRIVATE KEY-----`

func TestSign(t *testing.T) {
	newSigner := func() *Dkim {
		return NewSigner(
			testKey,
			"tsel",
			"erikk.org",
			CanonRELAXED,
			CanonRELAXED,
			SignRSASHA1,
			-1,
		)
	}

	d := newSigner()
	if d == nil {
		t.Fatal()
	}
	for i, hdrLine := range msgHdr {
		err := d.Header(hdrLine)
		if err != nil {
			t.Log(i)
			t.Fatal(err)
		}
	}
	err := d.Eoh()
	if err != nil {
		t.Fatal(err)
	}
	err = d.Body([]byte(msgBody))
	if err != nil {
		t.Fatal(err)
	}
	var testKey bool
	err = d.Eom(&testKey)
	if err != nil {
		t.Fatal(err)
	}
	h, err := d.GetSigHdr()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "v=1") {
		t.Fatal(h)
	}

	// TODO: Test using Chunk
	// For some reason it won't work using Chunk, investigate why
	//
	// d = newSigner()

	// var buf bytes.Buffer
	// buf.WriteString(strings.Join(msgHdr, "\r\n"))
	// buf.WriteString("\r\n\r\n")
	// buf.WriteString(msgBody)

	// err = d.Chunk(buf.Bytes())
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// err = d.Eom(&testKey)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// h, err = d.GetSigHdr()
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// if !strings.HasPrefix(h, "v=1") {
	// 	t.Fatal(h)
	// }
}
