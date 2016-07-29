// +build !windows

package opendkim

/*
#cgo LDFLAGS: -L/usr/local/opt/opendkim/lib -lopendkim
#cgo CFLAGS: -g -O2 -Wno-error -I/opt/local/include/opendkim/ -I/usr/include/opendkim/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <opendkim/dkim.h>
*/
import "C"

import (
	"bytes"
	"fmt"
	"io"
	"net/mail"
	"runtime"
	"sync"
	"unsafe"
)

type (
	Canon   int
	Sign    int
	Op      int
	Option  int
	Sigflag uint
)

const (
	CanonUNKNOWN Canon = (-1) // unknown method
	CanonSIMPLE  Canon = 0    // as specified in DKIM spec
	CanonRELAXED Canon = 1    // as specified in DKIM spec
)

const (
	SignUNKNOWN   Sign = -2 // unknown method
	SignDEFAULT   Sign = -1 // use internal default
	SignRSASHA1   Sign = 0  // an RSA-signed SHA1 digest
	SignRSASHA256 Sign = 1  // an RSA-signed SHA256 digest
)

const (
	StatusOK            = 0  // function completed successfully
	StatusBADSIG        = 1  // signature available but failed
	StatusNOSIG         = 2  // no signature available
	StatusNOKEY         = 3  // public key not found
	StatusCANTVRFY      = 4  // can't get domain key to verify
	StatusSYNTAX        = 5  // message is not valid syntax
	StatusNORESOURCE    = 6  // resource unavailable
	StatusINTERNAL      = 7  // internal error
	StatusREVOKED       = 8  // key found, but revoked
	StatusINVALID       = 9  // invalid function parameter
	StatusNOTIMPLEMENT  = 10 // function not implemented
	StatusKEYFAIL       = 11 // key retrieval failed
	StatusCBREJECT      = 12 // callback requested reject
	StatusCBINVALID     = 13 // callback gave invalid result
	StatusCBTRYAGAIN    = 14 // callback says try again later
	StatusCBERROR       = 15 // callback error
	StatusMULTIDNSREPLY = 16 // multiple DNS replies
	StatusSIGGEN        = 17 // signature generation failed
)

const (
	OptionFLAGS        Option = 0
	OptionTMPDIR       Option = 1
	OptionTIMEOUT      Option = 2
	OptionSENDERHDRS   Option = 3
	OptionSIGNHDRS     Option = 4
	OptionOVERSIGNHDRS Option = 5
	OptionQUERYMETHOD  Option = 6
	OptionQUERYINFO    Option = 7
	OptionFIXEDTIME    Option = 8
	OptionSKIPHDRS     Option = 9
	OptionALWAYSHDRS   Option = 10 // obsolete
	OptionSIGNATURETTL Option = 11
	OptionCLOCKDRIFT   Option = 12
	OptionMUSTBESIGNED Option = 13
	OptionMINKEYBITS   Option = 14
	OptionREQUIREDHDRS Option = 15
)

const (
	LibflagsNONE          = 0x0000
	LibflagsTMPFILES      = 0x0001
	LibflagsKEEPFILES     = 0x0002
	LibflagsSIGNLEN       = 0x0004
	LibflagsCACHE         = 0x0008
	LibflagsZTAGS         = 0x0010
	LibflagsDELAYSIGPROC  = 0x0020
	LibflagsEOHCHECK      = 0x0040
	LibflagsACCEPTV05     = 0x0080
	LibflagsFIXCRLF       = 0x0100
	LibflagsACCEPTDK      = 0x0200
	LibflagsBADSIGHANDLES = 0x0400
	LibflagsVERIFYONE     = 0x0800
	LibflagsSTRICTHDRS    = 0x1000
	LibflagsREPORTBADADSP = 0x2000
	LibflagsDROPSIGNER    = 0x4000
	LibflagsSTRICTRESIGN  = 0x8000
)

const (
	SigflagIGNORE      = 0x01
	SigflagPROCESSED   = 0x02
	SigflagPASSED      = 0x04
	SigflagTESTKEY     = 0x08
	SigflagNOSUBDOMAIN = 0x10
	SigflagKEYLOADED   = 0x20
)

const (
	QueryUNKNOWN = (-1) // unknown method
	QueryDNS     = 0    // DNS query method (per the draft)
	QueryFILE    = 1    // text file method (for testing)
)

const (
	GetOpt Op = 0
	SetOpt Op = 1
)

// Lib is a dkim library handle
type Lib struct {
	lib *C.DKIM_LIB
	mtx sync.Mutex
}

// Init inits a new dkim library handle
func Init() *Lib {
	lib := new(Lib)
	lib.lib = C.dkim_init(nil, nil)
	if lib.lib == nil {
		panic("could not init libopendkim")
	}
	runtime.SetFinalizer(lib, func(l *Lib) {
		l.Close()
	})
	return lib
}

// Options sets or gets library options
func (lib *Lib) Options(op Op, opt Option, ptr unsafe.Pointer, size uintptr) {
	lib.mtx.Lock()
	defer lib.mtx.Unlock()

	C.dkim_options(lib.lib, C.int(op), C.dkim_opts_t(opt), ptr, C.size_t(size))
}

// Close closes the dkim lib
func (lib *Lib) Close() {
	lib.mtx.Lock()
	defer lib.mtx.Unlock()

	if lib.lib != nil {
		C.dkim_close(lib.lib)
		lib.lib = nil
	}
}

// Dkim handle
type Dkim struct {
	dkim *C.DKIM
	mtx  sync.Mutex
}

// NewSigner creates a new DKIM handle for message signing.
// If -1 is specified for bytesToSign, the whole message body will be signed.
func (lib *Lib) NewSigner(secret, selector, domain string, hdrCanon, bodyCanon Canon, algo Sign, bytesToSign int64) (*Dkim, Status) {
	var stat C.DKIM_STAT

	signer := new(Dkim)
	signer.dkim = C.dkim_sign(
		lib.lib,
		nil,
		nil,
		(*C.uchar)(unsafe.Pointer(C.CString(secret))),
		(*C.uchar)(unsafe.Pointer(C.CString(selector))),
		(*C.uchar)(unsafe.Pointer(C.CString(domain))),
		C.dkim_canon_t(hdrCanon),
		C.dkim_canon_t(bodyCanon),
		C.dkim_alg_t(algo),
		C.ssize_t(bytesToSign),
		&stat,
	)

	s := Status(stat)
	if s != StatusOK {
		return nil, s
	}
	runtime.SetFinalizer(signer, func(s *Dkim) {
		s.Destroy()
	})
	return signer, s
}

// NewVerifier creates a new DKIM verifier
func (lib *Lib) NewVerifier() (*Dkim, Status) {
	var stat C.DKIM_STAT

	vrfy := new(Dkim)
	vrfy.dkim = C.dkim_verify(lib.lib, nil, nil, &stat)

	s := Status(stat)
	if s != StatusOK {
		return nil, s
	}
	runtime.SetFinalizer(vrfy, func(s *Dkim) {
		s.Destroy()
	})
	return vrfy, s
}

// Sign is a helper method for signing a block of message data.
// The message data includes header and body.
func (d *Dkim) Sign(r io.Reader) ([]byte, error) {
	hdr, body, stat := d.process(r)
	if stat != StatusOK {
		return nil, stat
	}

	sigHdr, stat := d.GetSigHdr()
	if stat != StatusOK {
		return nil, stat
	}

	hdr.WriteString(`DKIM-Signature: ` + sigHdr + "\r\n\r\n")

	var out bytes.Buffer
	io.Copy(&out, hdr)
	io.Copy(&out, body)

	return out.Bytes(), nil
}

// Verify is a helper method for verifying a message in one step
func (d *Dkim) Verify(r io.Reader) Status {
	_, _, stat := d.process(r)
	return stat
}

func (d *Dkim) process(r io.Reader) (hdr, body *bytes.Buffer, stat Status) {
	msg, err := mail.ReadMessage(r)
	if err != nil {
		return nil, nil, Status(StatusINTERNAL)
	}
	hdr = bytes.NewBuffer(nil)
	for k, vv := range msg.Header {
		for _, v := range vv {
			h := k + `: ` + v
			stat = d.Header(h)
			if stat != StatusOK {
				return
			}
			hdr.WriteString(h + "\r\n")
		}
	}

	stat = d.Eoh()
	if stat != StatusOK {
		return
	}

	body = bytes.NewBuffer(nil)
	io.Copy(body, msg.Body)

	stat = d.Body(body.Bytes())
	if stat != StatusOK {
		return
	}
	stat = d.Eom(nil)
	return
}

// Header processes a single header line.
// May be invoked multiple times.
func (d *Dkim) Header(line string) Status {
	data := []byte(line)
	return Status(C.dkim_header(d.dkim, (*C.u_char)(unsafe.Pointer(&data[0])), C.size_t(len(data))))
}

// Eoh is called to signal end of header.
func (d *Dkim) Eoh() Status {
	return Status(C.dkim_eoh(d.dkim))
}

// Body processes the message body.
func (d *Dkim) Body(data []byte) Status {
	return Status(C.dkim_body(d.dkim, (*C.u_char)(unsafe.Pointer(&data[0])), C.size_t(len(data))))
}

// Eom is called to signal end of message.
func (d *Dkim) Eom(testKey *bool) Status {
	return Status(C.dkim_eom(d.dkim, (*C._Bool)(testKey)))
}

// Chunk processes a chunk of message data.
// Can include header and body data.
//
// TODO: disabled until I figure out what's fould here
//
// func (d *Dkim) Chunk(data []byte) error {
// 	var stat C.DKIM_STAT
// 	stat = C.dkim_chunk(d.dkim, (*C.u_char)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
// 	if stat != StatusOK {
// 		return fmt.Errorf("error processing chunk (%s)", getErr(stat))
// 	}
// 	return nil
// }

// GetSigHdr computes the signature header for a message.
func (d *Dkim) GetSigHdr() (string, Status) {
	var buf = make([]byte, 1024)
	stat := Status(C.dkim_getsighdr(d.dkim, (*C.u_char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), C.size_t(0)))
	if stat != StatusOK {
		return "", stat
	}
	i := bytes.Index(buf, []byte{0x0})
	if i >= 0 {
		return string(buf[:i]), stat
	}
	return string(buf), stat
}

// GetSignature returns the signature.
// Eom must be called before invoking GetSignature.
func (d *Dkim) GetSignature() *Signature {
	var sig *C.DKIM_SIGINFO
	sig = C.dkim_getsignature(d.dkim)
	if sig == nil {
		return nil
	}
	return &Signature{
		h:   d,
		sig: sig,
	}
}

// GetError gets the last error for the dkim handle
func (d *Dkim) GetError() string {
	return C.GoString(C.dkim_geterror(d.dkim))
}

// Destroy destroys the dkim handle.
func (d *Dkim) Destroy() Status {
	d.mtx.Lock()
	defer d.mtx.Unlock()

	if d.dkim != nil {
		stat := Status(C.dkim_free(d.dkim))
		if stat != StatusOK {
			return stat
		}
		d.dkim = nil
	}
	return Status(StatusOK)
}

// Signature is a DKIM signature
type Signature struct {
	h   *Dkim
	sig *C.DKIM_SIGINFO
}

// Process processes a signature for validity.
func (s *Signature) Process() Status {
	return Status(C.dkim_sig_process(s.h.dkim, s.sig))
}

// Flags returns the signature flags
func (s *Signature) Flags() Sigflag {
	var res C.uint
	res = C.dkim_sig_getflags(s.sig)
	return Sigflag(res)
}

func getErr(s C.DKIM_STAT) string {
	return Status(s).Error()
}

type Status int

func (s Status) String() string {
	return fmt.Sprintf("%d: %s", s, C.GoString(C.dkim_getresultstr(C.DKIM_STAT(s))))
}

func (s Status) Error() string {
	return s.String()
}
