package zone

import (
	"io"
)

type FtpClient interface {
	Retr(string) (io.Reader, error)
}
