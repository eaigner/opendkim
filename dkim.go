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
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

type (
	Canon  int
	Sign   int
	Status int
	Op     int
	Option int
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
	StatusOK            Status = 0  // function completed successfully
	StatusBADSIG        Status = 1  // signature available but failed
	StatusNOSIG         Status = 2  // no signature available
	StatusNOKEY         Status = 3  // public key not found
	StatusCANTVRFY      Status = 4  // can't get domain key to verify
	StatusSYNTAX        Status = 5  // message is not valid syntax
	StatusNORESOURCE    Status = 6  // resource unavailable
	StatusINTERNAL      Status = 7  // internal error
	StatusREVOKED       Status = 8  // key found, but revoked
	StatusINVALID       Status = 9  // invalid function parameter
	StatusNOTIMPLEMENT  Status = 10 // function not implemented
	StatusKEYFAIL       Status = 11 // key retrieval failed
	StatusCBREJECT      Status = 12 // callback requested reject
	StatusCBINVALID     Status = 13 // callback gave invalid result
	StatusCBTRYAGAIN    Status = 14 // callback says try again later
	StatusCBERROR       Status = 15 // callback error
	StatusMULTIDNSREPLY Status = 16 // multiple DNS replies
	StatusSIGGEN        Status = 17 // signature generation failed
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
	GetOpt Op = 0
	SetOpt Op = 1
)

var lib *C.struct_DKIM_LIB

func init() {
	lib = C.dkim_init(nil, nil)
	if lib == nil {
		panic("could not init libopendkim")
	}
}

func SetOption(opt Option, data []byte) {
	C.dkim_options(lib, C.int(SetOpt), C.dkim_opts_t(opt), unsafe.Pointer(&data[0]), C.size_t(len(data)))
}

type Dkim struct {
	dkim *C.DKIM
	stat C.DKIM_STAT
	mtx  sync.Mutex
}

// NewSigner creates a new DKIM handle for message signing.
// If -1 is specified for bytesToSign, the whole message body will be signed.
func NewSigner(secret, selector, domain string, hdrCanon, bodyCanon Canon, algo Sign, bytesToSign int64) *Dkim {
	signer := new(Dkim)
	signer.dkim = C.dkim_sign(
		lib,
		nil,
		nil,
		(*C.uchar)(unsafe.Pointer(C.CString(secret))),
		(*C.uchar)(unsafe.Pointer(C.CString(selector))),
		(*C.uchar)(unsafe.Pointer(C.CString(domain))),
		C.dkim_canon_t(hdrCanon),
		C.dkim_canon_t(bodyCanon),
		C.dkim_alg_t(algo),
		C.ssize_t(bytesToSign),
		&signer.stat,
	)
	if signer.dkim == nil {
		panic("could not create DKIM handle")
	}
	runtime.SetFinalizer(signer, func(s *Dkim) {
		s.Destroy()
	})
	return signer
}

// Header processes a single header line.
// May be invoked multiple times.
func (d *Dkim) Header(line string) error {
	data := []byte(line)
	var stat C.DKIM_STAT
	stat = C.dkim_header(d.dkim, (*C.u_char)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	if Status(stat) != StatusOK {
		return fmt.Errorf("error processing header (%s)", getErr(stat))
	}
	return nil
}

// Eoh is called to signal end of header.
func (d *Dkim) Eoh() error {
	var stat C.DKIM_STAT
	stat = C.dkim_eoh(d.dkim)
	if Status(stat) != StatusOK {
		return fmt.Errorf("error closing header (%s)", getErr(stat))
	}
	return nil
}

// Body processes the message body.
func (d *Dkim) Body(data []byte) error {
	var stat C.DKIM_STAT
	stat = C.dkim_body(d.dkim, (*C.u_char)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	if Status(stat) != StatusOK {
		return fmt.Errorf("error processing body (%s)", getErr(stat))
	}
	return nil
}

// Eom is called to signal end of message.
func (d *Dkim) Eom(testKey *bool) error {
	var stat C.DKIM_STAT
	stat = C.dkim_eom(d.dkim, (*C._Bool)(testKey))
	if Status(stat) != StatusOK {
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
// 	if Status(stat) != StatusOK {
// 		return fmt.Errorf("error processing chunk (%s)", getErr(stat))
// 	}
// 	return nil
// }

// GetSigHdr computes the signature header for a message.
func (d *Dkim) GetSigHdr() (string, error) {
	var stat C.DKIM_STAT
	var buf = make([]byte, 1024)
	stat = C.dkim_getsighdr(d.dkim, (*C.u_char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), C.size_t(0))
	if Status(stat) != StatusOK {
		return "", fmt.Errorf("error computing signature header (%s)", getErr(stat))
	}
	i := bytes.Index(buf, []byte{0x0})
	if i >= 0 {
		return string(buf[:i]), nil
	}
	return string(buf), nil
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
		if Status(stat) != StatusOK {
			return fmt.Errorf("could not destroy DKIM handle (%s)", getErr(stat))
		}
		d.dkim = nil
	}
	return nil
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
