//
// goamz - Go packages to interact with the Amazon Web Services.
//
//   https://wiki.ubuntu.com/goamz
//
// Copyright (c) 2011 Canonical Ltd.
//
// Written by Gustavo Niemeyer <gustavo.niemeyer@canonical.com>
//

package s3

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mattetti/goamz-fork/aws"
)

const debug = false

// The S3 type encapsulates operations with an S3 region.
type S3 struct {
	aws.Auth
	aws.Region
	private byte // Reserve the right of using private data.
}

// The Bucket type encapsulates operations with an S3 bucket.
type Bucket struct {
	*S3
	Name string
}

// The Owner type represents the owner of the object in an S3 bucket.
type Owner struct {
	ID          string
	DisplayName string
}

type CustomHeaders map[string][]string

var attempts = aws.AttemptStrategy{
	Min:   5,
	Total: 5 * time.Second,
	Delay: 200 * time.Millisecond,
}

// New creates a new S3.
func New(auth aws.Auth, region aws.Region) *S3 {
	return &S3{auth, region, 0}
}

// Bucket returns a Bucket with the given name.
func (s3 *S3) Bucket(name string) *Bucket {
	if s3.Region.S3BucketEndpoint != "" || s3.Region.S3LowercaseBucket {
		name = strings.ToLower(name)
	}
	return &Bucket{s3, name}
}

var createBucketConfiguration = `<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <LocationConstraint>%s</LocationConstraint>
</CreateBucketConfiguration>`

// locationConstraint returns an io.Reader specifying a LocationConstraint if
// required for the region.
//
// See http://goo.gl/bh9Kq for details.
func (s3 *S3) locationConstraint() io.Reader {
	constraint := ""
	if s3.Region.S3LocationConstraint {
		constraint = fmt.Sprintf(createBucketConfiguration, s3.Region.Name)
	}
	return strings.NewReader(constraint)
}

type ACL string

const (
	Private           = ACL("private")
	PublicRead        = ACL("public-read")
	PublicReadWrite   = ACL("public-read-write")
	AuthenticatedRead = ACL("authenticated-read")
	BucketOwnerRead   = ACL("bucket-owner-read")
	BucketOwnerFull   = ACL("bucket-owner-full-control")
)

// BucketAvailable verifies that a bucket already exists and if we have permission
// access to it.
//
// see http://goo.gl/iUJfX for details.
func (b *Bucket) BucketAvailable() bool {
	req := &request{
		method: "HEAD",
		bucket: b.Name,
	}
	return b.S3.query(req, nil) == nil
}

// PutBucket creates a new bucket.
//
// See http://goo.gl/ndjnR for details.
func (b *Bucket) PutBucket(perm ACL) error {
	headers := map[string][]string{
		"x-amz-acl": {string(perm)},
	}
	req := &request{
		method:  "PUT",
		bucket:  b.Name,
		path:    "/",
		headers: headers,
		payload: b.locationConstraint(),
	}
	return b.S3.query(req, nil)
}

// DelBucket removes an existing S3 bucket. All objects in the bucket must
// be removed before the bucket itself can be removed.
//
// See http://goo.gl/GoBrY for details.
func (b *Bucket) DelBucket() (err error) {
	req := &request{
		method: "DELETE",
		bucket: b.Name,
		path:   "/",
	}
	for attempt := attempts.Start(); attempt.Next(); {
		err = b.S3.query(req, nil)
		if !shouldRetry(err) {
			break
		}
	}
	return err
}

// Get retrieves an object from an S3 bucket.
//
// See http://goo.gl/isCO7 for details.
func (b *Bucket) Get(path string) (data []byte, err error) {
	body, err := b.GetReader(path)
	if err != nil {
		return nil, err
	}
	data, err = ioutil.ReadAll(body)
	body.Close()
	return data, err
}

// Metadata returns the metadata assigned to the key available at the designed path.
// see http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectHEAD.html for details.
func (b *Bucket) Metadata(path string) (map[string][]string, error) {
	req := &request{
		method:  "HEAD",
		bucket:  b.Name,
		baseurl: "s3.amazonaws.com",
		path:    path,
	}

	err := b.S3.prepare(req)
	if err != nil {
		return nil, err
	}
	hresp, err := b.S3.run(req)
	if err != nil {
		return nil, err
	}

	return hresp.Header, nil
}

// ObjectAvailable verifies that an object already exists and if we have permission
// access to it.
//
// see http://goo.gl/ZjZeF for details.
func (b *Bucket) ObjectAvailable(path string) bool {
	req := &request{
		method:  "HEAD",
		bucket:  b.Name,
		baseurl: "s3.amazonaws.com",
		path:    path,
	}
	return b.S3.query(req, nil) == nil
}

// GetReader retrieves an object from a S3 bucket.
// It is the caller's responsibility to call Close on rc when
// finished reading.
func (b *Bucket) GetReader(path string) (rc io.ReadCloser, err error) {
	return b.GetReaderWithHeaders(path, nil)
}

// GetReaderWithHeaders retrieves an object from a S3 bucket but also passes custom headers.
// It is the caller's responsibility to call Close on rc when
// finished reading.
// http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectGET.html explains the custom request headers one might want to use.
func (b *Bucket) GetReaderWithHeaders(path string, custHeaders CustomHeaders) (rc io.ReadCloser, err error) {
	headers := map[string][]string{}
	for k, v := range custHeaders {
		headers[k] = v
	}

	req := &request{
		bucket:  b.Name,
		path:    path,
		headers: headers,
	}

	if err := b.S3.prepare(req); err != nil {
		return nil, err
	}

	for attempt := attempts.Start(); attempt.Next(); {
		hresp, err := b.S3.run(req)
		if shouldRetry(err) && attempt.HasNext() {
			continue
		}
		if err != nil {
			return nil, err
		}
		return hresp.Body, nil
	}
	panic("unreachable")
}

// amazonShouldEscape returns true if byte should be escaped
// From https://github.com/mitchellh/goamz
func amazonShouldEscape(c byte) bool {
	return !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') || c == '_' || c == '-' || c == '~' || c == '.' || c == '/' || c == ':')
}

// amazonEscape does uri escaping exactly as Amazon does
// From https://github.com/mitchellh/goamz
func amazonEscape(s string) string {
	hexCount := 0

	for i := 0; i < len(s); i++ {
		if amazonShouldEscape(s[i]) {
			hexCount++
		}
	}

	if hexCount == 0 {
		return s
	}

	t := make([]byte, len(s)+2*hexCount)
	j := 0
	for i := 0; i < len(s); i++ {
		if c := s[i]; amazonShouldEscape(c) {
			t[j] = '%'
			t[j+1] = "0123456789ABCDEF"[c>>4]
			t[j+2] = "0123456789ABCDEF"[c&15]
			j += 3
		} else {
			t[j] = s[i]
			j++
		}
	}
	return string(t)
}

// Put inserts an object into the S3 bucket.
//
// See http://goo.gl/FEBPD for details.
func (b *Bucket) Put(path string, data []byte, contType string, perm ACL) error {
	body := bytes.NewBuffer(data)
	return b.PutReader(path, body, int64(len(data)), contType, perm)
}

func (b *Bucket) PutWithHeaders(path string, data []byte, custHeaders CustomHeaders, perm ACL) error {
	body := bytes.NewBuffer(data)
	return b.PutReaderWithHeaders(path, body, int64(len(data)), custHeaders, perm)
}

// Copy copies an object from another bucket into this bucket
// Note: fromPath does not assume this bucket and must include bucket name
// e.g. b.Copy('mypath/myfile', '/yourbucket/yourpath/yourfile', s3.AuthenticatedRead)
//
// See http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectCOPY.html for details
func (b *Bucket) Copy(path string, fromPath string, perm ACL) error {
	return b.CopyWithHeaders(path, fromPath, nil, perm)
}

// CopyWithHeaders copies an object from another bucket into this bucket and can set/pass custom headers.
// If you need to update an object's metadata, you need to use this method with the following custom header
// `x-amz-metadata-directive: REPLACE`.
//  Note that any metadata you do not include in the old dictionary will be dropped. So to preserve old attributes
//  you need to first collect the metadata you want to use and send it as a custom header.
// See http://stackoverflow.com/questions/4754383/how-to-change-metadata-on-an-object-in-amazon-s3
// Note: fromPath does not assume this bucket and must include bucket name
// e.g. b.Copy('mypath/myfile', '/yourbucket/yourpath/yourfile', s3.AuthenticatedRead, nil)
//
// See http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectCOPY.html for details
func (b *Bucket) CopyWithHeaders(path string, fromPath string, custHeaders CustomHeaders, perm ACL) error {
	headers := map[string][]string{
		// TODO : Here the `fromPath` should probably be amazonEscape`d, but
		// I don't want to introduce changes to what already works
		"x-amz-copy-source": {fromPath},
	}

	if custHeaders != nil {
		/*
					// get original headers since they don't get copied over when copy/editing headers
			    // this is disabled since it copies all metadata, not the one fields we need.
					originHeaders, err := b.Metadata(strings.TrimPrefix(fromPath, fmt.Sprintf("/%s/", b.Name)))
					if err != nil {
						return err
					}
					for k, v := range originHeaders {
						headers[k] = v
					}
		*/
		// update using the ones we just received.
		for k, v := range custHeaders {
			headers[k] = v
		}
	}

	headers["x-amz-acl"] = []string{string(perm)}
	headers["x-amz-server-side-encryption"] = []string{"AES256"}

	req := &request{
		method:  "PUT",
		bucket:  b.Name,
		path:    path,
		headers: headers,
	}

	// From http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectCOPY.html
	//
	// There are two opportunities for a copy request to return an error. One
	// can occur when Amazon S3 receives the copy request and the other can
	// occur while Amazon S3 is copying the files. If the error occurs before
	// the copy operation starts, you receive a standard Amazon S3 error. If
	// the error occurs during the copy operation, the error response is
	// embedded in the 200 OK response. This means that a 200 OK response can
	// contain either a success or an error. Make sure to design your
	// application to parse the contents of the response and handle it
	// appropriately.
	errRes := &Error{}
	if err := b.S3.query(req, errRes); err != nil {
		return err
	}
	// check if we have an errRes
	if errRes.Code != "" {
		return errRes
	}
	return nil
}

// PutReader inserts an object into the S3 bucket by consuming data
// from r until EOF.
func (b *Bucket) PutReader(path string, r io.Reader, length int64, contType string, perm ACL) error {
	customHeaders := map[string][]string{
		"Content-Type": {contType},
	}
	return b.PutReaderWithHeaders(path, r, length, customHeaders, perm)
}

// PutReaderWithHeaders is similar to PutReader but with custom headers
// the required, calculated headers are automatically assigned.
// Useful to set more than just Content-Type.
func (b *Bucket) PutReaderWithHeaders(path string, r io.Reader, length int64, custHeaders CustomHeaders, perm ACL) error {
	headers := map[string][]string{
		"Content-Length":               {strconv.FormatInt(length, 10)},
		"x-amz-acl":                    {string(perm)},
		"x-amz-server-side-encryption": {"AES256"},
	}
	for k, v := range custHeaders {
		headers[k] = v
	}

	req := &request{
		method:  "PUT",
		bucket:  b.Name,
		path:    path,
		headers: headers,
		payload: r,
	}
	return b.S3.query(req, nil)
}

// Del removes an object from the S3 bucket.
//
// See http://goo.gl/APeTt for details.
func (b *Bucket) Del(path string) error {
	req := &request{
		method: "DELETE",
		bucket: b.Name,
		path:   path,
	}
	return b.S3.query(req, nil)
}

// The ListResp type holds the results of a List bucket operation.
type ListResp struct {
	Name      string
	Prefix    string
	Delimiter string
	Marker    string
	MaxKeys   int
	// IsTruncated is true if the results have been truncated because
	// there are more keys and prefixes than can fit in MaxKeys.
	// N.B. this is the opposite sense to that documented (incorrectly) in
	// http://goo.gl/YjQTc
	IsTruncated    bool
	Contents       []Key
	CommonPrefixes []string `xml:">Prefix"`
}

// The Key type represents an item stored in an S3 bucket.
type Key struct {
	Key          string
	LastModified string
	Size         int64
	// ETag gives the hex-encoded MD5 sum of the contents,
	// surrounded with double-quotes.
	ETag         string
	StorageClass string
	Owner        Owner
}

// List returns information about objects in an S3 bucket.
//
// The prefix parameter limits the response to keys that begin with the
// specified prefix.
//
// The delim parameter causes the response to group all of the keys that
// share a common prefix up to the next delimiter in a single entry within
// the CommonPrefixes field. You can use delimiters to separate a bucket
// into different groupings of keys, similar to how folders would work.
//
// The marker parameter specifies the key to start with when listing objects
// in a bucket. Amazon S3 lists objects in alphabetical order and
// will return keys alphabetically greater than the marker.
//
// The max parameter specifies how many keys + common prefixes to return in
// the response. The default is 1000.
//
// For example, given these keys in a bucket:
//
//     index.html
//     index2.html
//     photos/2006/January/sample.jpg
//     photos/2006/February/sample2.jpg
//     photos/2006/February/sample3.jpg
//     photos/2006/February/sample4.jpg
//
// Listing this bucket with delimiter set to "/" would yield the
// following result:
//
//     &ListResp{
//         Name:      "sample-bucket",
//         MaxKeys:   1000,
//         Delimiter: "/",
//         Contents:  []Key{
//             {Key: "index.html", "index2.html"},
//         },
//         CommonPrefixes: []string{
//             "photos/",
//         },
//     }
//
// Listing the same bucket with delimiter set to "/" and prefix set to
// "photos/2006/" would yield the following result:
//
//     &ListResp{
//         Name:      "sample-bucket",
//         MaxKeys:   1000,
//         Delimiter: "/",
//         Prefix:    "photos/2006/",
//         CommonPrefixes: []string{
//             "photos/2006/February/",
//             "photos/2006/January/",
//         },
//     }
//
// See http://goo.gl/YjQTc for details.
func (b *Bucket) List(prefix, delim, marker string, max int) (result *ListResp, err error) {
	params := map[string][]string{
		"prefix":    {prefix},
		"delimiter": {delim},
		"marker":    {marker},
	}
	if max != 0 {
		params["max-keys"] = []string{strconv.FormatInt(int64(max), 10)}
	}
	req := &request{
		bucket: b.Name,
		params: params,
	}
	result = &ListResp{}
	for attempt := attempts.Start(); attempt.Next(); {
		err = b.S3.query(req, result)
		if !shouldRetry(err) {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	return result, nil
}

// URL returns a non-signed URL that allows retriving the
// object at path. It only works if the object is publicly
// readable (see SignedURL).
func (b *Bucket) URL(path string) string {
	req := &request{
		bucket: b.Name,
		path:   path,
	}
	err := b.S3.prepare(req)
	if err != nil {
		panic(err)
	}
	u, err := req.url()
	if err != nil {
		panic(err)
	}
	u.RawQuery = ""
	return u.String()
}

// SignedURL returns a signed URL that allows anyone holding the URL
// to retrieve the object at path. The signature is valid until expires.
func (b *Bucket) SignedURL(path string, expires time.Time) string {
	req := &request{
		bucket: b.Name,
		path:   path,
		params: url.Values{"Expires": {strconv.FormatInt(expires.Unix(), 10)}},
	}
	err := b.S3.prepare(req)
	if err != nil {
		panic(err)
	}
	u, err := req.url()
	if err != nil {
		panic(err)
	}
	return u.String()
}

// SignedHeadURL returns a signed URL to be used when performing a HEAD request.
// This is different from the Metadata function, which returns the actual headers.
// A use-case for this is, for example, when a front-end will need a URL that they
// can use to poll until the object is present.
func (b *Bucket) SignedHeadURL(path string, expires time.Time) string {
	req := &request{
		bucket: b.Name,
		path:   path,
		method: "HEAD",
		params: url.Values{"Expires": {strconv.FormatInt(expires.Unix(), 10)}},
	}
	err := b.S3.prepare(req)
	if err != nil {
		panic(err)
	}
	u, err := req.url()
	if err != nil {
		panic(err)
	}
	return u.String()
}

// SignedAttachmentURL returns a signed url that causes the object to be downloaded instead of
// accessed through the web interface.
func (b *Bucket) SignedAttachmentURL(path, filename string, expires time.Time) string {
	req := &request{
		bucket: b.Name,
		path:   path,
		params: url.Values{
			"Expires":                      {strconv.FormatInt(expires.Unix(), 10)},
			"response-content-disposition": {fmt.Sprintf("attachment; filename=\"%s\"", filename)},
		},
	}
	err := b.S3.prepare(req)
	if err != nil {
		panic(err)
	}
	u, err := req.url()
	if err != nil {
		panic(err)
	}
	return u.String()
}

type request struct {
	method   string
	bucket   string
	path     string
	signpath string
	params   url.Values
	headers  http.Header
	baseurl  string
	payload  io.Reader
	prepared bool
}

func (req *request) url() (*url.URL, error) {
	u, err := url.Parse(req.baseurl)
	if err != nil {
		return nil, fmt.Errorf("bad S3 endpoint URL %q: %v", req.baseurl, err)
	}
	u.RawQuery = req.params.Encode()
	u.Path = req.path
	return u, nil
}

// query prepares and runs the req request.
// If resp is not nil, the XML data contained in the response
// body will be unmarshalled on it.
func (s3 *S3) query(req *request, resp interface{}) error {
	err := s3.prepare(req)
	if err != nil {
		return err
	}
	hresp, err := s3.run(req)
	if err != nil {
		return err
	}
	if resp != nil {
		err = xml.NewDecoder(hresp.Body).Decode(resp)
	}
	hresp.Body.Close()
	return nil
}

// prepare sets up req to be delivered to S3.
func (s3 *S3) prepare(req *request) error {
	if !req.prepared {
		req.prepared = true
		if req.method == "" {
			req.method = "GET"
		}
		// Copy so they can be mutated without affecting on retries.
		params := make(url.Values)
		headers := make(http.Header)
		for k, v := range req.params {
			params[k] = v
		}
		for k, v := range req.headers {
			headers[k] = v
		}
		req.params = params
		req.headers = headers
		if !strings.HasPrefix(req.path, "/") {
			req.path = "/" + req.path
		}
		req.signpath = req.path
		if req.bucket != "" {
			req.baseurl = s3.Region.S3BucketEndpoint
			if req.baseurl == "" {
				// Use the path method to address the bucket.
				req.baseurl = s3.Region.S3Endpoint
				req.path = "/" + req.bucket + req.path
			} else {
				// Just in case, prevent injection.
				if strings.IndexAny(req.bucket, "/:@") >= 0 {
					return fmt.Errorf("bad S3 bucket: %q", req.bucket)
				}
				req.baseurl = strings.Replace(req.baseurl, "${bucket}", req.bucket, -1)
			}
			req.signpath = "/" + req.bucket + req.signpath
		}
	}

	// Always sign again as it's not clear how far the
	// server has handled a previous attempt.
	u, err := url.Parse(req.baseurl)
	if err != nil {
		return fmt.Errorf("bad S3 endpoint URL %q: %v", req.baseurl, err)
	}
	req.headers["Host"] = []string{u.Host}
	req.headers["Date"] = []string{time.Now().In(time.UTC).Format(time.RFC1123)}
	sign(s3.Auth, req.method, amazonEscape(req.signpath), req.params, req.headers)
	return nil
}

// run sends req and returns the http response from the server.
func (s3 *S3) run(req *request) (*http.Response, error) {
	if debug {
		log.Printf("Running S3 request: %#v", req)
	}

	u, err := req.url()
	if err != nil {
		return nil, err
	}

	hreq := http.Request{
		URL:        u,
		Method:     req.method,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Close:      true,
		Header:     req.headers,
	}

	if v, ok := req.headers["Content-Length"]; ok {
		hreq.ContentLength, _ = strconv.ParseInt(v[0], 10, 64)
		delete(req.headers, "Content-Length")
	}
	if req.payload != nil {
		hreq.Body = ioutil.NopCloser(req.payload)
	}

	hresp, err := http.DefaultClient.Do(&hreq)
	if err != nil {
		return nil, err
	}
	if debug {
		dump, _ := httputil.DumpResponse(hresp, true)
		log.Printf("} -> %s\n", dump)
	}
	if hresp.StatusCode != 200 && hresp.StatusCode != 204 && hresp.StatusCode != 206 {
		// the Body is closed in buildError
		return nil, buildError(hresp)
	}
	return hresp, err
}

// Error represents an error in an operation with S3.
type Error struct {
	StatusCode int    // HTTP status code (200, 403, ...)
	Code       string // EC2 error code ("UnsupportedOperation", ...)
	Message    string // The human-oriented error message
	BucketName string
	RequestId  string
	HostId     string
}

func (e *Error) Error() string {
	return fmt.Sprintf("S3:%s: %s", e.Code, e.Message)
}

func buildError(r *http.Response) error {
	if debug {
		log.Printf("got error (status code %v)", r.StatusCode)
		data, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Printf("\tread error: %v", err)
		} else {
			log.Printf("\tdata:\n%s\n\n", data)
		}
		r.Body = ioutil.NopCloser(bytes.NewBuffer(data))
	}

	err := Error{}
	// TODO return error if Unmarshal fails?
	xml.NewDecoder(r.Body).Decode(&err)
	r.Body.Close()
	err.StatusCode = r.StatusCode
	if err.Message == "" {
		err.Message = r.Status
	}
	if debug {
		log.Printf("err: %#v\n", err)
	}
	return &err
}

func shouldRetry(err error) bool {
	if err == nil {
		return false
	}
	switch err {
	case io.ErrUnexpectedEOF, io.EOF:
		return true
	}
	switch e := err.(type) {
	case *net.DNSError:
		return true
	case *net.OpError:
		switch e.Op {
		case "read", "write":
			return true
		}
	case *Error:
		switch e.Code {
		case "InternalError", "NoSuchUpload", "NoSuchBucket":
			return true
		}
	}
	return false
}

func hasCode(err error, code string) bool {
	s3err, ok := err.(*Error)
	return ok && s3err.Code == code
}
