// baase64 encode and decode
package based

import (
	"encoding/base64"
)

var DefaultTable = "123QRSTUabcdVWXYZHijKLAWDCABDstEFGuvwxyzGHIJklmnopqr234560178912"

type BaseCoder struct {
	Encoding *base64.Encoding
}

// New return BaseCoder
func New(table string) *BaseCoder {
	return &BaseCoder{Encoding: base64.NewEncoding(table)}
}

func NewDefault() *BaseCoder {
	return New(DefaultTable)
}

// Encode
func (e *BaseCoder) Encode(src []byte) []byte {
	return []byte(e.Encoding.EncodeToString(src))
}

// EncodeString
func (e *BaseCoder) EncodeString(src string) string {
	return e.Encoding.EncodeToString([]byte(src))
}

// Decode
func (e *BaseCoder) Decode(src []byte) ([]byte, error) {
	return e.Encoding.DecodeString(string(src))
}

// DecodeString
func (e *BaseCoder) DecodeString(src string) (string, error) {
	b, err := e.Encoding.DecodeString(src)
	return string(b), err
}
