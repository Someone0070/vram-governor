package api

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenAISpeechRejectsBadRequests(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	cases := map[string]struct {
		body map[string]any
		code int
	}{
		"no input":       {map[string]any{"model": "tts-1", "voice": "alloy"}, http.StatusBadRequest},
		"wav format":     {map[string]any{"model": "tts-1", "input": "hi", "response_format": "wav"}, http.StatusBadRequest},
		"no workflow":    {map[string]any{"model": "tts-1", "input": "hi"}, http.StatusNotFound},
		"image workflow": {map[string]any{"model": "image-test", "input": "hi"}, http.StatusNotFound},
	}
	withTestWorkflow(t, srv)
	for name, c := range cases {
		response := request(t, srv.Handler(), http.MethodPost, "/v1/audio/speech", "alice-token", c.body)
		if response.Code != c.code {
			t.Errorf("%s: status=%d body=%s", name, response.Code, response.Body.String())
		}
	}
}

func TestOpenAITranscriptionsRejectsBadRequests(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	post := func(fields map[string]string, filename, contentType string, data []byte) int {
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		for k, v := range fields {
			_ = writer.WriteField(k, v)
		}
		if filename != "" {
			header := make(map[string][]string)
			header["Content-Disposition"] = []string{`form-data; name="file"; filename="` + filename + `"`}
			header["Content-Type"] = []string{contentType}
			part, _ := writer.CreatePart(header)
			_, _ = part.Write(data)
		}
		_ = writer.Close()
		req := httptest.NewRequest(http.MethodPost, "/v1/audio/transcriptions", &body)
		req.Header.Set("Authorization", "Bearer alice-token")
		req.Header.Set("Content-Type", writer.FormDataContentType())
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	if code := post(map[string]string{"model": "whisper-1"}, "", "", nil); code != http.StatusNotFound && code != http.StatusBadRequest {
		t.Errorf("no file: %d", code)
	}
	withTestWorkflow(t, srv)
	if code := post(map[string]string{"model": "whisper-1", "response_format": "srt"}, "a.mp3", "audio/mpeg", []byte("x")); code != http.StatusBadRequest {
		t.Errorf("srt format: %d", code)
	}
	if code := post(map[string]string{"model": "whisper-1"}, "a.mp3", "audio/mpeg", []byte("x")); code != http.StatusNotFound {
		t.Errorf("no transcription workflow: %d", code)
	}
	if code := post(map[string]string{"model": "image-test"}, "a.mp3", "audio/mpeg", []byte("x")); code != http.StatusNotFound {
		t.Errorf("image workflow as transcriber: %d", code)
	}
}
