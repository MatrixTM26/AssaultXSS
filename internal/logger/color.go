package logger

import (
	"fmt"
	"io"
	"os"
)

const (
	ansiReset     = "\033[0m"
	ansiBold      = "\033[1m"
	ansiGray      = "\033[90m"
	ansiRed       = "\033[31;1m"
	ansiGreen     = "\033[32;1m"
	ansiYellow    = "\033[33;1m"
	ansiBlue      = "\033[34;1m"
	ansiCyan      = "\033[36;1m"
	ansiHiRed     = "\033[91;1m"
	ansiHiGreen   = "\033[92;1m"
	ansiHiWhite   = "\033[97;1m"
	ansiOrange    = "\033[33m"
	ansiMagenta   = "\033[35;1m"
)

type Pen struct {
	code string
	w    io.Writer
}

func NewPen(code string) *Pen {
	return &Pen{code: code, w: os.Stdout}
}

func NewPenErr(code string) *Pen {
	return &Pen{code: code, w: os.Stderr}
}

func (p *Pen) Sprintf(format string, args ...any) string {
	return p.code + fmt.Sprintf(format, args...) + ansiReset
}

func (p *Pen) Sprint(s string) string {
	return p.code + s + ansiReset
}

func (p *Pen) Printf(format string, args ...any) {
	fmt.Fprintf(p.w, p.code+format+ansiReset, args...)
}

func (p *Pen) Println(s string) {
	fmt.Fprintln(p.w, p.code+s+ansiReset)
}

func (p *Pen) Print(s string) {
	fmt.Fprint(p.w, p.code+s+ansiReset)
}
