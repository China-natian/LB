//go:build !tinygo
// +build !tinygo

package pkg

import (
	"net/http"

	"github.com/chainreactors/utils/httputils"
)

func newResponseFromRaw(raw []byte) *httputils.Response {
	return httputils.NewParsedResponse(raw)
}

func newResponseFromHTTP(resp *http.Response, size int64) *httputils.Response {
	return httputils.NewResponse(resp, size)
}
