//go:build tinygo
// +build tinygo

package pkg

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"

	"github.com/chainreactors/utils/httputils"
)

func newResponseFromRaw(raw []byte) *httputils.Response {
	if len(raw) == 0 {
		return nil
	}

	_, header, _ := httputils.SplitHttpRaw(raw)
	lines := bytes.Split(header, []byte{'\n'})
	if len(lines) == 0 {
		return nil
	}

	statusCode := 0
	statusLine := strings.TrimSpace(string(lines[0]))
	if ok, status := GetStatusCode(raw); ok {
		statusCode, _ = strconv.Atoi(status)
	}

	server := ""
	for _, line := range lines[1:] {
		text := strings.TrimSpace(string(line))
		if strings.HasPrefix(strings.ToLower(text), "server:") {
			server = strings.TrimSpace(text[len("server:"):])
			break
		}
	}

	content := httputils.NewContent(raw)
	result := &httputils.Response{
		Server:  server,
		History: nil,
		Resp: &http.Response{
			Status:     statusLine,
			StatusCode: statusCode,
			Header:     http.Header{},
		},
		Content: content,
	}

	if title := httputils.MatchTitle(raw); title != "" {
		result.HasTitle = true
		result.Title = title
	} else {
		result.Title = httputils.MatchCharacter(raw)
	}

	return result
}

func newResponseFromHTTP(resp *http.Response, size int64) *httputils.Response {
	return httputils.NewResponse(resp, size)
}
