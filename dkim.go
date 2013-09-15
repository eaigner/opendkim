// +build !windows

package opendkim

/*
#cgo LDFLAGS: -L/opt/local/lib -L/usr/lib -lopendkim
#cgo CFLAGS: -g -O2 -I/opt/local/include/opendkim/ -I/usr/include/opendkim/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dkim.h>
*/
import "C"

import (
	"bytes"
	"errors"
	"fmt"
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
	lib *C.struct_DKIM_LIB
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
func (lib *Lib) NewSigner(secret, selector, domain string, hdrCanon, bodyCanon Canon, algo Sign, bytesToSign int64) (*Dkim, error) {
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
	if stat != StatusOK {
		return nil, fmt.Errorf("could not create signing handle (%s)", getErr(stat))
	}
	runtime.SetFinalizer(signer, func(s *Dkim) {
		s.Destroy()
	})
	return signer, nil
}

// NewVerifier creates a new DKIM verifier
func (lib *Lib) NewVerifier() (*Dkim, error) {
	var stat C.DKIM_STAT

	vrfy := new(Dkim)
	vrfy.dkim = C.dkim_verify(lib.lib, nil, nil, &stat)
	if stat != StatusOK {
		return nil, fmt.Errorf("could not create verify handle (%s)", getErr(stat))
	}
	runtime.SetFinalizer(vrfy, func(s *Dkim) {
		s.Destroy()
	})
	return vrfy, nil
}

// Header processes a single header line.
// May be invoked multiple times.
func (d *Dkim) Header(line string) error {
	data := []byte(line)
	var stat C.DKIM_STAT
	stat = C.dkim_header(d.dkim, (*C.u_char)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	if stat != StatusOK {
		return fmt.Errorf("error processing header (%s)", getErr(stat))
	}
	return nil
}

// Eoh is called to signal end of header.
func (d *Dkim) Eoh() error {
	var stat C.DKIM_STAT
	stat = C.dkim_eoh(d.dkim)
	if stat != StatusOK {
		return fmt.Errorf("error closing header (%s)", getErr(stat))
	}
	return nil
}

// Body processes the message body.
func (d *Dkim) Body(data []byte) error {
	var stat C.DKIM_STAT
	stat = C.dkim_body(d.dkim, (*C.u_char)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	if stat != StatusOK {
		return fmt.Errorf("error processing body (%s)", getErr(stat))
	}
	return nil
}

// Eom is called to signal end of message.
func (d *Dkim) Eom(testKey *bool) error {
	var stat C.DKIM_STAT
	stat = C.dkim_eom(d.dkim, (*C._Bool)(testKey))
	if stat != StatusOK {
		return fmt.Errorf("error closing message (%s)", getErr(stat))
	}
	return nil
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
func (d *Dkim) GetSigHdr() (string, error) {
	var stat C.DKIM_STAT
	var buf = make([]byte, 1024)
	stat = C.dkim_getsighdr(d.dkim, (*C.u_char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), C.size_t(0))
	if stat != StatusOK {
		return "", fmt.Errorf("error computing signature header (%s)", getErr(stat))
	}
	i := bytes.Index(buf, []byte{0x0})
	if i >= 0 {
		return string(buf[:i]), nil
	}
	return string(buf), nil
}

// GetSignature returns the signature.
// Eom must be called before invoking GetSignature.
func (d *Dkim) GetSignature() (*Signature, error) {
	var sig *C.DKIM_SIGINFO
	sig = C.dkim_getsignature(d.dkim)
	if sig == nil {
		return nil, errors.New("could not get signature (did you call Eom?)")
	}
	return &Signature{
		h:   d,
		sig: sig,
	}, nil
}

// GetError gets the last error for the dkim handle
func (d *Dkim) GetError() string {
	return C.GoString(C.dkim_geterror(d.dkim))
}

// Destroy destroys the dkim handle
func (d *Dkim) Destroy() error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.dkim != nil {
		var stat C.DKIM_STAT
		stat = C.dkim_free(d.dkim)
		if stat != StatusOK {
			return fmt.Errorf("could not destroy DKIM handle (%s)", getErr(stat))
		}
		d.dkim = nil
	}
	return nil
}

// Signature is a DKIM signature
type Signature struct {
	h   *Dkim
	sig *C.DKIM_SIGINFO
}

// Process processes a signature for validity.
func (s *Signature) Process() error {
	var stat C.DKIM_STAT
	stat = C.dkim_sig_process(s.h.dkim, s.sig)
	if stat != StatusOK {
		return fmt.Errorf("could not process signature (%s)", getErr(stat))
	}
	return nil
}

// Flags returns the signature flags
func (s *Signature) Flags() Sigflag {
	var res C.uint
	res = C.dkim_sig_getflags(s.sig)
	return Sigflag(res)
}

func getErr(s C.DKIM_STAT) string {
	return (&dkimError{s}).Error()
}

type dkimError struct {
	stat C.DKIM_STAT
}

func (err *dkimError) Error() string {
	return fmt.Sprintf("%d: %s", err.stat, C.GoString(C.dkim_getresultstr(err.stat)))
}
