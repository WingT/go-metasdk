package metasdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/go-querystring/query"
)

type ResponseChecker func(*http.Response) error

// NewClient returns a new client. If a nil httpClient is
// provided, http.DefaultClient will be used.
func NewClient(httpClient *http.Client, checker ResponseChecker) *Client {
  _ = `
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  abcdefg
  `
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if checker == nil {
		checker = DefaultResponseChecker
	}

	return &Client{client: httpClient, responseChecker: checker}
}

type Client struct {
	// HTTP client used to communicate with the API.
	client *http.Client

	// Base URL for API requests.
	baseURL *url.URL

	// ResponseChecker for API response.
	responseChecker ResponseChecker
}

// SetBaseURL sets the base URL for API requests to a custom endpoint. urlStr
// should always be specified with a trailing slash.
func (c *Client) SetBaseURL(urlStr string) error {
	// Make sure the given URL end with a slash
	if !strings.HasSuffix(urlStr, "/") {
		urlStr += "/"
	}

	baseURL, err := url.Parse(urlStr)
	if err != nil {
		return err
	}

	// Update the base URL of the client.
	c.baseURL = baseURL

	return nil
}

type OptionFunc func(*http.Request) error

// NewRequest creates an API request. A relative URL path can be provided in
// urlStr, in which case it is resolved relative to the base URL of the Client.
// Relative URL paths should always be specified without a preceding slash. If
// specified, the value pointed to by body is JSON encoded and included as the
// request body.
func (c *Client) NewRequest(method, path string, opt interface{}, options []OptionFunc) (*http.Request, error) {
	u := *c.baseURL
	unescaped, err := url.PathUnescape(path)
	if err != nil {
		return nil, err
	}

	// Set the encoded path data
	u.RawPath = c.baseURL.Path + path
	u.Path = c.baseURL.Path + unescaped

	if opt != nil {
		q, err := query.Values(opt)
		if err != nil {
			return nil, err
		}
		u.RawQuery = q.Encode()
	}

	req := &http.Request{
		Method:     method,
		URL:        &u,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Host:       u.Host,
	}

	for _, fn := range options {
		if fn == nil {
			continue
		}

		if err := fn(req); err != nil {
			return nil, err
		}
	}

	if method == "POST" || method == "PUT" {
		bodyBytes, err := json.Marshal(opt)
		if err != nil {
			return nil, err
		}
		bodyReader := bytes.NewReader(bodyBytes)

		u.RawQuery = ""
		req.Body = ioutil.NopCloser(bodyReader)
		req.GetBody = func() (io.ReadCloser, error) {
			return ioutil.NopCloser(bodyReader), nil
		}
		req.ContentLength = int64(bodyReader.Len())
		req.Header.Set("Content-Type", "application/json")
	}

	req.Header.Set("Accept", "application/json")
	return req, nil
}

type Response struct {
	*http.Response
}

// Do sends an API request and returns the API response. The API response is
// JSON decoded and stored in the value pointed to by v, or returned as an
// error if an API error has occurred. If v implements the io.Writer
// interface, the raw response body will be written to v, without attempting to
// first decode it.
func (c *Client) Do(req *http.Request, v interface{}) (*Response, error) {
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	response := &Response{
		Response: resp,
	}

	err = c.responseChecker(resp)
	if err != nil {
		// even though there was an error, we still return the response
		// in case the caller wants to inspect it further
		return response, err
	}

	if v != nil {
		if w, ok := v.(io.Writer); ok {
			_, err = io.Copy(w, resp.Body)
		} else {
			err = json.NewDecoder(resp.Body).Decode(v)
		}
	}

	return response, err
}

// CheckResponse checks the API response for errors, and returns them if present.
func DefaultResponseChecker(r *http.Response) error {
	switch r.StatusCode {
	case 200, 201, 202, 204, 304:
		return nil
	}

	errorResponse := &ErrorResponse{Response: r}
	data, err := ioutil.ReadAll(r.Body)
	if err == nil && data != nil {
		errorResponse.Body = data

		var m struct {
			Message string `json:"message,required"`
		}
		if err := json.Unmarshal(data, &m); err != nil {
			errorResponse.Message = "failed to parse unknown error format"
		} else {
			errorResponse.Message = m.Message
		}
	}

	return errorResponse
}

// An ErrorResponse reports one or more errors caused by an API request.
type ErrorResponse struct {
	Body     []byte
	Response *http.Response
	Message  string
}

func (e *ErrorResponse) Error() string {
	path, _ := url.QueryUnescape(e.Response.Request.URL.Path)
	u := fmt.Sprintf("%s://%s%s", e.Response.Request.URL.Scheme, e.Response.Request.URL.Host, path)
	return fmt.Sprintf("%s %s: %d %s", e.Response.Request.Method, u, e.Response.StatusCode, e.Message)
}
