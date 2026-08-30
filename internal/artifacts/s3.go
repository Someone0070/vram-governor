package artifacts

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"vram-governor/internal/domain"
)

type S3Options struct {
	Endpoint     string
	Bucket       string
	Region       string
	AccessKey    string
	SecretKey    string
	SessionToken string
	Prefix       string
	Client       *http.Client
}

// S3Store is a small S3-compatible ArtifactStore. It uses path-style URLs
// (supported by S3, MinIO, Garage, and most home-lab object stores) and AWS
// Signature Version 4 without requiring a provider-specific SDK.
type S3Store struct {
	endpoint     *url.URL
	bucket       string
	region       string
	accessKey    string
	secretKey    string
	sessionToken string
	prefix       string
	client       *http.Client
}

func NewS3Store(options S3Options) (*S3Store, error) {
	endpoint, err := url.Parse(strings.TrimRight(options.Endpoint, "/"))
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" {
		return nil, fmt.Errorf("invalid S3 endpoint")
	}
	if endpoint.Scheme != "https" && endpoint.Scheme != "http" {
		return nil, fmt.Errorf("S3 endpoint must use HTTP or HTTPS")
	}
	if options.Bucket == "" || strings.ContainsAny(options.Bucket, `/\\`) {
		return nil, fmt.Errorf("invalid S3 bucket")
	}
	if options.Region == "" {
		options.Region = "us-east-1"
	}
	if options.AccessKey == "" || options.SecretKey == "" {
		return nil, fmt.Errorf("S3 access and secret keys are required")
	}
	if options.Client == nil {
		options.Client = &http.Client{Timeout: 30 * time.Minute}
	}
	return &S3Store{endpoint: endpoint, bucket: options.Bucket, region: options.Region, accessKey: options.AccessKey, secretKey: options.SecretKey, sessionToken: options.SessionToken, prefix: strings.Trim(options.Prefix, "/"), client: options.Client}, nil
}

func (s *S3Store) objectURL(id string) (*url.URL, string, error) {
	if !strings.HasPrefix(id, "art-") || strings.ContainsAny(id, `/\\`) {
		return nil, "", fmt.Errorf("invalid artifact id")
	}
	key := id
	if s.prefix != "" {
		key = s.prefix + "/" + id
	}
	objectURL := *s.endpoint
	objectURL.Path = path.Join(s.endpoint.Path, s.bucket, key)
	return &objectURL, key, nil
}

func (s *S3Store) Put(ctx context.Context, ownerID, workloadID, name, mediaType string, src io.Reader) (*domain.Artifact, error) {
	id := artifactID()
	objectURL, key, err := s.objectURL(id)
	if err != nil {
		return nil, err
	}
	temporary, err := os.CreateTemp("", "vram-artifact-*")
	if err != nil {
		return nil, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	hash := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(temporary, hash), &contextReader{ctx: ctx, reader: io.LimitReader(src, 2<<30)})
	if closeErr := temporary.Close(); copyErr != nil || closeErr != nil {
		if copyErr != nil {
			return nil, copyErr
		}
		return nil, closeErr
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	artifact := &domain.Artifact{ID: id, OwnerID: ownerID, WorkloadID: workloadID, Name: path.Base(name), MediaType: mediaType, Size: size, StorageRef: "s3://" + s.bucket + "/" + key, SHA256: digest, CreatedAt: time.Now().UTC()}
	metadata, _ := json.Marshal(artifact)
	file, err := os.Open(temporaryPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, objectURL.String(), file)
	if err != nil {
		return nil, err
	}
	req.ContentLength = size
	if mediaType != "" {
		req.Header.Set("Content-Type", mediaType)
	}
	req.Header.Set("X-Amz-Meta-Vram-Governor", base64.RawURLEncoding.EncodeToString(metadata))
	s.sign(req, digest, time.Now().UTC())
	response, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("S3 put returned %d: %s", response.StatusCode, strings.TrimSpace(string(message)))
	}
	return artifact, nil
}

func (s *S3Store) Open(ctx context.Context, id string) (*domain.Artifact, io.ReadCloser, error) {
	objectURL, _, err := s.objectURL(id)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, objectURL.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	emptyHash := sha256.Sum256(nil)
	s.sign(req, hex.EncodeToString(emptyHash[:]), time.Now().UTC())
	response, err := s.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		defer response.Body.Close()
		return nil, nil, fmt.Errorf("S3 get returned %d", response.StatusCode)
	}
	encoded := response.Header.Get("X-Amz-Meta-Vram-Governor")
	metadata, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		response.Body.Close()
		return nil, nil, fmt.Errorf("S3 object metadata is invalid")
	}
	var artifact domain.Artifact
	if err := json.Unmarshal(metadata, &artifact); err != nil || artifact.ID != id {
		response.Body.Close()
		return nil, nil, fmt.Errorf("S3 artifact metadata mismatch")
	}
	return &artifact, response.Body, nil
}

func (s *S3Store) sign(req *http.Request, payloadHash string, now time.Time) {
	amzDate := now.Format("20060102T150405Z")
	shortDate := now.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if s.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", s.sessionToken)
	}
	headers := map[string]string{"host": req.URL.Host}
	for key, values := range req.Header {
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "x-amz-") || lower == "content-type" {
			headers[lower] = strings.Join(strings.Fields(strings.Join(values, ",")), " ")
		}
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var canonicalHeaders strings.Builder
	for _, key := range keys {
		canonicalHeaders.WriteString(key)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(strings.TrimSpace(headers[key]))
		canonicalHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(keys, ";")
	canonicalRequest := req.Method + "\n" + req.URL.EscapedPath() + "\n" + req.URL.RawQuery + "\n" + canonicalHeaders.String() + "\n" + signedHeaders + "\n" + payloadHash
	requestHash := sha256.Sum256([]byte(canonicalRequest))
	scope := shortDate + "/" + s.region + "/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(requestHash[:])
	dateKey := hmacSHA256([]byte("AWS4"+s.secretKey), shortDate)
	regionKey := hmacSHA256(dateKey, s.region)
	serviceKey := hmacSHA256(regionKey, "s3")
	signingKey := hmacSHA256(serviceKey, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+s.accessKey+"/"+scope+", SignedHeaders="+signedHeaders+", Signature="+signature)
}

func hmacSHA256(key []byte, value string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(value))
	return h.Sum(nil)
}
