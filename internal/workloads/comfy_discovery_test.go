package workloads

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
)

func newComfyDiscoveryTestManager(t *testing.T, endpoint string) *Manager {
	t.Helper()
	m := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	m.RegisterAdapter(NewHTTPAdapter("comfy", "comfy", http.DefaultClient))
	m.RegisterTarget(Target{ID: "comfy-a", Adapter: "comfy", Endpoint: endpoint, RuntimeProtocol: "raw_comfy_v1", Enabled: true, Models: []string{"checkpoint.safetensors"}})
	t.Cleanup(func() { m.Close() })
	return m
}

func TestComfyFleetDiscoveryEligibility(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) }))
	defer server.Close()
	m := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	defer m.Close()
	m.RegisterTarget(Target{ID: "z", Adapter: "comfy", Endpoint: server.URL, Enabled: true})
	m.RegisterTarget(Target{ID: "disabled", Adapter: "comfy", Endpoint: server.URL, Enabled: false})
	m.RegisterTarget(Target{ID: "bad-url", Adapter: "comfy", Endpoint: server.URL+"?token=secret", Enabled: true})
	m.RegisterTarget(Target{ID: "cloud", Adapter: "comfy", Endpoint: server.URL, Cloud: true, Enabled: true})
	m.RegisterTarget(Target{ID: "quarantined", Adapter: "comfy", Endpoint: server.URL, Quarantined: true, Enabled: true})
	m.providerMu.Lock(); m.providerCircuits["circuit-open"] = providerCircuit{OpenUntil: time.Now().Add(time.Minute)}; m.providerMu.Unlock()
	m.RegisterTarget(Target{ID: "circuit-open", Adapter: "comfy", Endpoint: server.URL, Enabled: true})
	got, err := m.ComfyDiscoveryTargets(context.Background(), string(domain.EgressLocalOnly))
	if err != nil { t.Fatal(err) }
	if len(got) != 1 || got[0].Target.ID != "z" || got[0].Generation == 0 { t.Fatalf("unexpected eligible snapshot: %+v", got) }
	profilesTarget := Target{Profiles: []domain.RuntimeProfile{{Operations: []string{"image.generate"}, Features: []string{"a"}, AcceptedArtifactTypes:[]string{"image/png"}, ProducedArtifactTypes:[]string{"image/webp"}, CompatibilityOperations:[]string{"image.edit"}, InputSchema: domain.JSONSchema{"properties": map[string]any{"prompt": map[string]any{"type":"string"}}}, OutputSchema:domain.JSONSchema{"required":[]any{"outputs"}}, Availability: &domain.RuntimeAvailability{Status:"ready"}}}}
	cloned := cloneComfyTarget(profilesTarget)
	cloned.Profiles[0].Operations[0] = "changed"
	cloned.Profiles[0].Features[0] = "changed"
	cloned.Profiles[0].AcceptedArtifactTypes[0] = "changed"
	cloned.Profiles[0].ProducedArtifactTypes[0] = "changed"
	cloned.Profiles[0].CompatibilityOperations[0] = "changed"
	cloned.Profiles[0].InputSchema["properties"].(map[string]any)["prompt"].(map[string]any)["type"] = "changed"
	cloned.Profiles[0].OutputSchema["required"].([]any)[0] = "changed"
	cloned.Profiles[0].Availability.Status = "changed"
	if profilesTarget.Profiles[0].Operations[0] != "image.generate" || profilesTarget.Profiles[0].Features[0] != "a" || profilesTarget.Profiles[0].AcceptedArtifactTypes[0] != "image/png" || profilesTarget.Profiles[0].ProducedArtifactTypes[0] != "image/webp" || profilesTarget.Profiles[0].CompatibilityOperations[0] != "image.edit" || profilesTarget.Profiles[0].InputSchema["properties"].(map[string]any)["prompt"].(map[string]any)["type"] != "string" || profilesTarget.Profiles[0].OutputSchema["required"].([]any)[0] != "outputs" || profilesTarget.Profiles[0].Availability.Status != "ready" { t.Fatal("Comfy snapshot retained mutable RuntimeProfile references") }
	backing := store.NewMemoryStore(); m.SetNodeStore(backing)
	for _, tc := range []struct{id string; node *domain.Node}{
		{"disconnected", &domain.Node{ID:"disconnected",SchedulingState:domain.SchedulingEnabled,Desired:domain.Desired{SchedulingEnabled:true},Observed:domain.Observed{Connectivity:domain.ConnectivityOffline,Ready:true},Accelerators:[]domain.Accelerator{{ID:"gpu"}}}},
		{"unready", &domain.Node{ID:"unready",SchedulingState:domain.SchedulingEnabled,Desired:domain.Desired{SchedulingEnabled:true},Observed:domain.Observed{Connectivity:domain.ConnectivityConnected,Ready:false},Accelerators:[]domain.Accelerator{{ID:"gpu"}}}},
		{"unscheduled", &domain.Node{ID:"unscheduled",SchedulingState:domain.SchedulingDisabled,Desired:domain.Desired{SchedulingEnabled:true},Observed:domain.Observed{Connectivity:domain.ConnectivityConnected,Ready:true},Accelerators:[]domain.Accelerator{{ID:"gpu"}}}},
		{"missing-gpu", &domain.Node{ID:"missing-gpu",SchedulingState:domain.SchedulingEnabled,Desired:domain.Desired{SchedulingEnabled:true},Observed:domain.Observed{Connectivity:domain.ConnectivityConnected,Ready:true}}},
	} {
		if _, err := backing.UpsertNode(context.Background(), tc.node); err != nil { t.Fatal(err) }
		m.RegisterTarget(Target{ID:tc.id,Adapter:"comfy",Endpoint:server.URL,NodeID:tc.id,AcceleratorID:"gpu",Enabled:true})
	}
	got, err = m.ComfyDiscoveryTargets(context.Background(), string(domain.EgressLocalOnly))
	if err != nil || len(got) != 1 || got[0].Target.ID != "z" { t.Fatalf("ineligible node targets entered discovery: %+v err=%v", got, err) }
	t.Run("source cap refuses an oversized routable fleet", func(t *testing.T) {
		large := NewManager(quietLogger(), store.NewMemoryStore(), time.Second); defer large.Close()
		for i:=0;i<comfyMaxTargets+1;i++ { large.RegisterTarget(Target{ID:fmt.Sprintf("source-%02d",i),Adapter:"comfy",Endpoint:server.URL,Enabled:true}) }
		if sources, err := large.ComfyDiscoveryTargets(context.Background(), string(domain.EgressLocalOnly)); err == nil || sources != nil { t.Fatalf("oversized fleet was silently truncated: sources=%d err=%v",len(sources),err) }
	})
}

func TestComfyFleetDiscoveryTransportBounds(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/redirect" { http.Redirect(w, r, "/ok", http.StatusFound); return }
		if r.URL.Path == "/large" { _, _ = w.Write([]byte(strings.Repeat("x", 128))); return }
		if r.URL.Path == "/invalid-utf8" { _, _ = w.Write([]byte{0xff, '{', '}'}); return }
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	target := ComfyDiscoveryTarget{Target: Target{ID: "x", Adapter: "comfy", Endpoint: server.URL}, Generation: 1}
	if _, err := fetchComfyJSON(context.Background(), target, "redirect", 1024); err == nil { t.Fatal("redirect was followed or accepted") }
	if _, err := fetchComfyJSON(context.Background(), target, "large", 32); err == nil { t.Fatal("oversized response was accepted") }
	if _, err := fetchComfyJSON(context.Background(), target, "invalid-utf8", 32); err == nil { t.Fatal("invalid UTF-8 response was accepted") }
	if body, err := fetchComfyJSON(context.Background(), target, "ok", 32); err != nil || string(body) != `{"ok":true}` { t.Fatalf("bounded success failed: %s %v", body, err) }
	if calls.Load() != 4 { t.Fatalf("request count=%d want=4", calls.Load()) }
	var active, maximum atomic.Int32
	concurrentBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := active.Add(1)
		for old := maximum.Load(); current > old && !maximum.CompareAndSwap(old, current); old = maximum.Load() {}
		defer active.Add(-1)
		time.Sleep(10 * time.Millisecond)
		if r.URL.Path == "/object_info" { _, _ = w.Write([]byte(`{"A":{"input":{},"output":[]}}`)); return }
		_, _ = w.Write([]byte(`{"system":{},"devices":[]}`))
	}))
	defer concurrentBackend.Close()
	manager := NewManager(quietLogger(), store.NewMemoryStore(), time.Second); defer manager.Close()
	manager.RegisterAdapter(NewHTTPAdapter("comfy", "comfy", concurrentBackend.Client()))
	for i:=0;i<6;i++ { manager.RegisterTarget(Target{ID:fmt.Sprintf("parallel-%02d",i),Adapter:"comfy",Endpoint:concurrentBackend.URL,Enabled:true}) }
	if _, err := manager.ComfyFleetDiscovery(context.Background(), string(domain.EgressLocalOnly)); err != nil { t.Fatalf("bounded concurrent discovery failed: %v",err) }
	if maximum.Load() > comfyMaxConcurrent || maximum.Load() < 2 { t.Fatalf("unexpected backend concurrency %d",maximum.Load()) }
	timeoutBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) { <-r.Context().Done() }))
	defer timeoutBackend.Close()
	timeoutManager := newComfyDiscoveryTestManager(t,timeoutBackend.URL)
	timeoutCtx,cancel:=context.WithTimeout(context.Background(),25*time.Millisecond); defer cancel()
	started:=time.Now()
	if _, err := timeoutManager.ComfyFleetDiscovery(timeoutCtx,string(domain.EgressLocalOnly)); err == nil { t.Fatal("cancelled total discovery was accepted") }
	if time.Since(started)>time.Second { t.Fatal("discovery ignored the caller's finite timeout") }
	var routed atomic.Int32
	configuredClient := &http.Client{Transport: comfyRoundTripFunc(func(req *http.Request) (*http.Response,error) {
		routed.Add(1)
		if req.URL.Host != "backend.invalid" || !strings.HasPrefix(req.URL.Path,"/registered-prefix/") { t.Errorf("registered client route was not preserved: %s",req.URL) }
		body := `{"A":{"input":{},"output":[]}}`
		if strings.HasSuffix(req.URL.Path,"system_stats") { body=`{"system":{},"devices":[]}` }
		return &http.Response{StatusCode:http.StatusOK,Header:make(http.Header),Body:io.NopCloser(strings.NewReader(body)),Request:req},nil
	})}
	customManager:=NewManager(quietLogger(),store.NewMemoryStore(),time.Second); defer customManager.Close()
	customManager.RegisterAdapter(NewHTTPAdapter("comfy","comfy",configuredClient))
	customManager.RegisterTarget(Target{ID:"custom-client",Adapter:"comfy",Endpoint:"http://backend.invalid/registered-prefix",Enabled:true})
	if _,err:=customManager.ComfyFleetDiscovery(context.Background(),string(domain.EgressLocalOnly)); err!=nil || routed.Load()!=2 { t.Fatalf("configured adapter transport was not retained: requests=%d err=%v",routed.Load(),err) }
}

type comfyRoundTripFunc func(*http.Request) (*http.Response,error)
func (roundTrip comfyRoundTripFunc) RoundTrip(req *http.Request) (*http.Response,error) { return roundTrip(req) }

func TestComfyFleetGraphValidation(t *testing.T) {
	schema := map[string]json.RawMessage{
		"ImageSource": json.RawMessage(`{"input":{},"output":["IMAGE"]}`),
		"SaveImage": json.RawMessage(`{"input":{"required":{"images":["IMAGE"]}},"output":["IMAGE"]}`),
		"CheckpointLoader": json.RawMessage(`{"input":{"required":{"ckpt_name":[["checkpoint.safetensors"]]}},"output":["MODEL"]}`),
	}
	valid := domain.WorkloadRequest{Payload: json.RawMessage(`{"prompt":{"1":{"class_type":"ImageSource","inputs":{}},"2":{"class_type":"SaveImage","inputs":{"images":["1",0]}},"3":{"class_type":"CheckpointLoader","inputs":{"ckpt_name":"checkpoint.safetensors"}}}}`)}
	if err := validateComfyRequestSchema(valid, schema); err != nil { t.Fatalf("valid graph rejected: %v", err) }
	for _, payload := range []string{
		`{"prompt":{"1":{"class_type":"SaveImage","inputs":{}}}}`,
		`{"prompt":{"1":{"class_type":"CheckpointLoader","inputs":{"ckpt_name":"other.safetensors"}}}}`,
		`{"prompt":{"1":{"class_type":"ImageSource","inputs":{}},"2":{"class_type":"SaveImage","inputs":{"images":["missing",0]}}}}`,
		`{"prompt":{"1":{"class_type":"ImageSource","inputs":{}},"2":{"class_type":"SaveImage","inputs":{"images":["1",4]}}}}`,
		`{"prompt":{"1":{"class_type":"ImageSource","inputs":{}},"2":{"class_type":"SaveImage","inputs":{"images":["missing"]}}}}`,
		`{"prompt":{"1":{"class_type":"ImageSource","inputs":{}},"2":{"class_type":"SaveImage","inputs":{"images":["missing",0,1]}}}}`,
		`{"prompt":{"1":{"class_type":"ImageSource","inputs":{}},"2":{"class_type":"Wildcard","inputs":{"value":["missing",0]}}}}`,
		`{"prompt":{"client_id":{"class_type":"NotRegistered","inputs":{}},"valid":{"class_type":"ImageSource","inputs":{}}}}`,
	} {
		request := domain.WorkloadRequest{Payload: json.RawMessage(payload)}
		if err := validateComfyRequestSchema(request, schema); err == nil { t.Fatalf("invalid graph was accepted: %s", payload) }
	}
	wildcard := map[string]json.RawMessage{
		"ImageSource": json.RawMessage(`{"input":{},"output":["IMAGE"]}`),
		"Wildcard": json.RawMessage(`{"input":{"required":{"value":["*"]}},"output":[]}`),
	}
	validWildcardLink := domain.WorkloadRequest{Payload: json.RawMessage(`{"prompt":{"1":{"class_type":"ImageSource","inputs":{}},"2":{"class_type":"Wildcard","inputs":{"value":["1",0]}}}}`)}
	if validateComfyRequestSchema(validWildcardLink, wildcard) != nil { t.Fatal("well-shaped wildcard link was rejected") }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"ImageSource":{"input":{"required":{}},"output":["IMAGE"]},"SaveImage":{"input":{"required":{"images":["IMAGE"]}},"output":["IMAGE"]}}`)) }))
	defer server.Close()
	m := newComfyDiscoveryTestManager(t, server.URL)
	invalid := domain.WorkloadRequest{Payload: json.RawMessage(`{"prompt":{"bad":{"class_type":"NotRegistered","inputs":{}}}}`)}
	if _, err := m.ComfySchema(context.Background(), m.targetByID("comfy-a"), m.targetGeneration("comfy-a"), invalid); err == nil { t.Fatal("ComfySchema admitted incompatible graph") }
	validProofRequest := domain.WorkloadRequest{Payload: json.RawMessage(`{"prompt":{"one":{"class_type":"ImageSource","inputs":{}}}}`)}
	proof, err := m.ComfySchema(context.Background(), m.targetByID("comfy-a"), m.targetGeneration("comfy-a"), validProofRequest)
	if err != nil { t.Fatalf("ComfySchema rejected a compatible graph: %v", err) }
	changedGraph := validProofRequest
	changedGraph.Payload = json.RawMessage(`{"prompt":{"one":{"class_type":"ImageSource","inputs":{}},"two":{"class_type":"ImageSource","inputs":{}}}}`)
	changedProof, err := m.ComfySchema(context.Background(), m.targetByID("comfy-a"), m.targetGeneration("comfy-a"), changedGraph)
	if err != nil || comfySchemaProofMatches(proof, changedProof) { t.Fatalf("schema proof was not bound to exact graph bytes: err=%v", err) }
	if err := validateComfyRequestSchema(domain.WorkloadRequest{Payload: json.RawMessage(`{"managed_chunks":[{"prompt":{"1":{"class_type":"ImageSource","inputs":{}},"2":{"class_type":"SaveImage","inputs":{"images":["1",0]}}}}]}`)}, schema); err != nil { t.Fatalf("valid managed chunk was rejected: %v", err) }
	cycleSchema := map[string]json.RawMessage{"A": json.RawMessage(`{"input":{"required":{"in":["IMAGE"]}},"output":["IMAGE"]}`)}
	cycle := domain.WorkloadRequest{Payload: json.RawMessage(`{"prompt":{"1":{"class_type":"A","inputs":{"in":["2",0]}},"2":{"class_type":"A","inputs":{"in":["1",0]}}}}`)}
	if validateComfyRequestSchema(cycle, cycleSchema) == nil { t.Fatal("cyclic graph links were accepted") }
	left := json.RawMessage(`{"input":{"required":{"ckpt":[["a.safetensors"]]}},"output":["MODEL"]}`)
	right := json.RawMessage(`{"input":{"required":{"ckpt":[["b.safetensors"]]}},"output":["MODEL"]}`)
	merged, compatible := mergeComfySchemaEnums(left, right)
	if !compatible || !strings.Contains(string(merged), "a.safetensors") || !strings.Contains(string(merged), "b.safetensors") { t.Fatalf("compatible enum alternatives did not merge: %s", merged) }
	comboLeft := json.RawMessage(`{"input":{"optional":{"fps":["COMBO",{"default":"auto","multiselect":false,"options":["auto",8,10]}]}},"output":["VIDEO"]}`)
	comboRight := json.RawMessage(`{"input":{"optional":{"fps":["COMBO",{"default":"auto","multiselect":false,"options":["auto",12,16]}]}},"output":["VIDEO"]}`)
	comboUnion, comboCompatible := mergeComfySchemaEnums(comboLeft,comboRight)
	if !comboCompatible { t.Fatalf("compatible COMBO choices did not merge: %s",comboUnion) }
	for _, choice := range []string{`"auto"`, `8`, `10`, `12`, `16`} { if !strings.Contains(string(comboUnion),choice) { t.Fatalf("COMBO union omitted %s: %s",choice,comboUnion) } }
	incompatible := json.RawMessage(`{"input":{"optional":{"ckpt":[["b.safetensors"]]}},"output":["MODEL"]}`)
	if _, compatible := mergeComfySchemaEnums(left, incompatible); compatible { t.Fatal("required/optional schema conflict was merged") }
	for _, malformedSchema := range []json.RawMessage{
		json.RawMessage(`{"input":{}}`),
		json.RawMessage(`{"output":[]}`),
		json.RawMessage(`{"input":{"required":{"amount":["INT",{"min":"zero"}]}},"output":[]}`),
		json.RawMessage(`{"input":{"required":{}},"output":[],"private_path":"/etc/shadow"}`),
		json.RawMessage(`{"input":{"required":{}},"output":[],"description":"https://internal.invalid/token=secret"}`),
	} {
		if validateComfyClassDefinition(malformedSchema) == nil { t.Fatalf("malformed or unsafe schema was accepted: %s", malformedSchema) }
	}
	if err := validateComfyClassDefinition(json.RawMessage(`{"input":{"required":{"model":[["subdir/model.safetensors"]]}},"output":[],"category":"models/checkpoints"}`)); err != nil {
		t.Fatalf("legitimate relative model/category convention rejected: %v", err)
	}
	backendSchema := map[string]json.RawMessage{
		"CheckpointLoaderSimple": json.RawMessage(`{"input":{"required":{"ckpt_name":[["sd_xl_base_1.0.safetensors"]]}},"output":["MODEL","CLIP","VAE"]}`),
		"CLIPTextEncode": json.RawMessage(`{"input":{"required":{"text":["STRING",{"multiline":true}],"clip":["CLIP"]}},"output":["CONDITIONING"]}`),
		"EmptyLatentImage": json.RawMessage(`{"input":{"required":{"width":["INT",{"min":1}],"height":["INT",{"min":1}],"batch_size":["INT",{"min":1}]}},"output":["LATENT"]}`),
		"KSampler": json.RawMessage(`{"input":{"required":{"seed":["INT",{"min":0,"max":18446744073709551615}],"steps":["INT",{"min":1}],"cfg":["FLOAT",{"min":0}],"sampler_name":[["euler","uni_pc"]],"scheduler":[["normal","simple"]],"denoise":["FLOAT",{"min":0,"max":1}],"model":["MODEL"],"positive":["CONDITIONING"],"negative":["CONDITIONING"],"latent_image":["LATENT"]}},"output":["LATENT"]}`),
		"VAEDecode": json.RawMessage(`{"input":{"required":{"samples":["LATENT"],"vae":["VAE"]}},"output":["IMAGE"]}`),
		"UNETLoader": json.RawMessage(`{"input":{"required":{"unet_name":[["wan2.2_ti2v_5B_fp16.safetensors"]],"weight_dtype":[["default"]]}},"output":["MODEL"]}`),
		"CLIPLoader": json.RawMessage(`{"input":{"required":{"clip_name":[["umt5_xxl_fp8_e4m3fn_scaled.safetensors"]],"type":[["wan"]],"device":[["default"]]}},"output":["CLIP"]}`),
		"VAELoader": json.RawMessage(`{"input":{"required":{"vae_name":[["wan2.2_vae.safetensors"]]}},"output":["VAE"]}`),
		"ModelSamplingSD3": json.RawMessage(`{"input":{"required":{"model":["MODEL"],"shift":["FLOAT",{"min":0}]}},"output":["MODEL"]}`),
		"Wan22ImageToVideoLatent": json.RawMessage(`{"input":{"required":{"width":["INT",{"min":1}],"height":["INT",{"min":1}],"length":["INT",{"min":1}],"batch_size":["INT",{"min":1}],"vae":["VAE"]}},"output":["LATENT"]}`),
		"ImageSource": json.RawMessage(`{"input":{"required":{}},"output":["IMAGE"],"is_input_list":false,"has_intermediate_output":false,"essentials_category":"image"}`),
		"SaveImage": json.RawMessage(`{"input":{"required":{"images":["IMAGE",{"tooltip":"The images to save."}],"filename_prefix":["STRING",{"default":"output","multiline":true}]},"hidden":{"prompt":"PROMPT","extra_pnginfo":"EXTRA_PNGINFO"}},"input_order":{"required":["images","filename_prefix"],"hidden":["prompt","extra_pnginfo"]},"output":["IMAGE"],"output_node":true,"api_node":false,"dev_only":false,"output_matchtypes":["IMAGE"],"price_badge":"free"}`),
		"CreateVideo": json.RawMessage(`{"input":{"required":{"images":["IMAGE",{"tooltip":"Images used to create the video."}],"fps":["FLOAT",{"default":30.0,"min":1.0,"max":120.0,"step":1.0}]},"optional":{"bit_depth":["COMBO",{"options":["auto",8,10],"default":"auto","multiselect":false}],"color_space":["COMBO",{"options":["sRGB","HDR","HDR PQ"],"default":"sRGB","multiselect":false}]}},"output":["VIDEO"],"output_tooltips":[null],"output_matchtypes":null,"price_badge":null,"description":null,"display_name":null}`),
		"SaveVideo": json.RawMessage(`{"input":{"required":{"video":["VIDEO"],"filename_prefix":["STRING",{"default":"output"}]},"optional":{"format":["COMFY_DYNAMICCOMBO_V3",{"options":[{"key":"auto","inputs":{"required":{},"optional":{}}},{"key":"mp4","inputs":{"required":{"codec":["COMFY_DYNAMICCOMBO_V3",{"options":[{"key":"auto","inputs":{"required":{},"optional":{}}},{"key":"h264","inputs":{"required":{},"optional":{"encoding":["COMFY_DYNAMICCOMBO_V3",{"options":[{"key":"auto","inputs":{"required":{},"optional":{}}},{"key":"re-encode","inputs":{"required":{"crf":["FLOAT",{"default":23.0,"min":0.0,"max":51.0,"step":1.0}]},"optional":{}}}]}]}}},{"key":"av1","inputs":{"required":{},"optional":{}}}]}]},"optional":{}}},{"key":"mkv","inputs":{"required":{},"optional":{}}},{"key":"webm","inputs":{"required":{},"optional":{}}}] }]},"hidden":{"prompt":["PROMPT"],"extra_pnginfo":["EXTRA_PNGINFO"]}},"input_order":{"required":["video","filename_prefix"],"optional":["format"],"hidden":["prompt","extra_pnginfo"]},"output":["VIDEO"],"output_node":true}`),
		"LoadImageOutput": json.RawMessage(`{"input":{"required":{"image":["COMBO",{"image_folder":"input","image_upload":true,"remote":{"route":"images","refresh_button":true,"control_after_refresh":"first"}}]}},"output":["IMAGE"]}`),
		"ImageCropV2": json.RawMessage(`{"input":{"required":{"crop_region":["BOUNDING_BOX",{"component":"BoundingBox","socketless":true,"default":{"x":0,"y":0,"width":512,"height":512}}]}},"output":["IMAGE"]}`),
		"LTXVEmptyLatentAudio": json.RawMessage(`{"input":{"required":{"frame_rate":["FLOAT,INT",{"default":25.0,"display":"number","max":1000.0,"min":1.0,"step":0.01,"tooltip":"Number of frames per second.","widgetType":"FLOAT"}] }},"output":["LATENT"]}`),
		"Preview3D": json.RawMessage(`{"input":{"required":{"model_file":["STRING,FILE_3D_GLB,FILE_3D_GLB_COMPRESSED",{"widgetType":"file","file_upload":true,"accept":["model/gltf-binary"]}]}},"output":[]}`),
		"File3DSource": json.RawMessage(`{"input":{"required":{}},"output":["FILE_3D_GLB"]}`),
		"IntegerSource": json.RawMessage(`{"input":{"required":{}},"output":["INT"]}`),
		"MultiselectFixture": json.RawMessage(`{"input":{"required":{"flags":["COMBO",{"options":["alpha","beta"],"multiselect":true}] }},"output":[]}`),
		"MapDynamicFixture": json.RawMessage(`{"input":{"required":{"format":["COMFY_DYNAMICCOMBO_V3",{"options":{"auto":{"inputs":{"required":{},"optional":{}}},"mp4":{"inputs":{"required":{"codec":[["h264","av1"]]},"optional":{}}}}}] }},"output":[]}`),
		"StringEnumFixture": json.RawMessage(`{"input":{"required":{"mode":[["STRING","other"]]}},"output":[]}`),
		"NumericEnumFixture": json.RawMessage(`{"input":{"required":{"mode":[["FLOAT","INT"]]}},"output":[]}`),
		"HiddenLabels": json.RawMessage(`{"input":{"hidden":{"api_key":"API_KEY_COMFY_ORG","auth_token":"AUTH_TOKEN_COMFY_ORG","usage_source":"COMFY_USAGE_SOURCE"}},"input_order":{"hidden":["api_key","auth_token","usage_source"]},"output":[]}`),
		"SourceVideo": json.RawMessage(`{"input":{"required":{}},"output":["VIDEO"]}`),
	}
	for name, class := range backendSchema { if err := validateComfyClassDefinition(class); err != nil { t.Fatalf("representative backend class %s rejected: %v", name, err) } }
	for _, registered := range []string{"../../configs/comfy-bootstrap/image-sdxl-smoke.json","../../configs/comfy-bootstrap/video-wan22-5b-smoke.json"} {
		template, err := os.ReadFile(registered); if err != nil { t.Fatalf("read registered smoke graph %s: %v",registered,err) }
		payload := append([]byte(`{"prompt":`),template...); payload=append(payload,'}')
		if err := validateComfyRequestSchema(domain.WorkloadRequest{Payload:payload},backendSchema); err != nil { t.Fatalf("registered smoke graph %s rejected by one-candidate schema: %v",registered,err) }
	}
	imageGraph := domain.WorkloadRequest{Payload: json.RawMessage(`{"prompt":{"1":{"class_type":"ImageSource","inputs":{}},"2":{"class_type":"SaveImage","inputs":{"images":["1",0],"filename_prefix":"smoke"}}}}`)}
	if err := validateComfyRequestSchema(imageGraph, backendSchema); err != nil { t.Fatalf("registered SDXL graph shape rejected: %v", err) }
	videoGraph := domain.WorkloadRequest{Payload: json.RawMessage(`{"prompt":{"1":{"class_type":"ImageSource","inputs":{}},"2":{"class_type":"CreateVideo","inputs":{"images":["1",0],"fps":16,"bit_depth":"auto","color_space":"sRGB"}},"3":{"class_type":"SaveVideo","inputs":{"video":["2",0],"filename_prefix":"smoke","format":"mp4","codec":"h264","encoding":"re-encode","crf":23}}}}`)}
	if err := validateComfyRequestSchema(videoGraph, backendSchema); err != nil { t.Fatalf("registered Wan video graph shape rejected: %v", err) }
	videoOptionalEncoding := domain.WorkloadRequest{Payload:json.RawMessage(`{"prompt":{"1":{"class_type":"SourceVideo","inputs":{}},"2":{"class_type":"SaveVideo","inputs":{"video":["1",0],"filename_prefix":"smoke","format":"mp4","codec":"h264"}}}}`)}
	if err := validateComfyRequestSchema(videoOptionalEncoding,backendSchema); err != nil { t.Fatalf("valid optional-encoding SaveVideo graph rejected: %v",err) }
	for _, reordered := range []string{
		`{"prompt":{"1":{"class_type":"ImageSource","inputs":{}},"2":{"class_type":"CreateVideo","inputs":{"images":["1",0],"fps":16,"bit_depth":"auto","color_space":"sRGB"}},"3":{"class_type":"SaveVideo","inputs":{"crf":23,"encoding":"re-encode","codec":"h264","format":"mp4","filename_prefix":"smoke","video":["2",0]}}}}`,
		`{"prompt":{"1":{"class_type":"ImageSource","inputs":{}},"2":{"class_type":"CreateVideo","inputs":{"images":["1",0],"fps":16,"bit_depth":"auto","color_space":"sRGB"}},"3":{"class_type":"SaveVideo","inputs":{"video":["2",0],"format":"mp4","codec":"h264","encoding":"re-encode","crf":23,"filename_prefix":"smoke"}}}}`,
	} { if err := validateComfyRequestSchema(domain.WorkloadRequest{Payload:json.RawMessage(reordered)}, backendSchema); err != nil { t.Fatalf("input-order-dependent selected dynamic schema rejected: %v",err) } }
	for _, invalid := range []string{
		`{"prompt":{"1":{"class_type":"ImageSource","inputs":{}},"2":{"class_type":"CreateVideo","inputs":{"images":["1",0],"fps":16}},"3":{"class_type":"SaveVideo","inputs":{"video":["2",0],"filename_prefix":"smoke","format":"mp4"}}}}`,
		`{"prompt":{"1":{"class_type":"ImageSource","inputs":{}},"2":{"class_type":"CreateVideo","inputs":{"images":["1",0],"fps":16}},"3":{"class_type":"SaveVideo","inputs":{"video":["2",0],"filename_prefix":"smoke","format":"unknown","codec":"h264"}}}}`,
		`{"prompt":{"1":{"class_type":"SourceVideo","inputs":{}},"2":{"class_type":"SaveVideo","inputs":{"video":["1",0],"filename_prefix":"smoke","format":"mp4","codec":"h264","encoding":"re-encode"}}}}`,
		`{"prompt":{"1":{"class_type":"SourceVideo","inputs":{}},"2":{"class_type":"SaveVideo","inputs":{"video":["1",0],"filename_prefix":"smoke","format":"mp4","codec":"auto","encoding":"re-encode","crf":23}}}}`,
	} { if validateComfyRequestSchema(domain.WorkloadRequest{Payload:json.RawMessage(invalid)}, backendSchema) == nil { t.Fatalf("conditional dynamic input violation accepted: %s", invalid) } }
	for _, tc := range []struct{payload string; want bool}{
		{`{"prompt":{"1":{"class_type":"MapDynamicFixture","inputs":{"format":"mp4","codec":"h264"}}}}`,true},
		{`{"prompt":{"1":{"class_type":"MapDynamicFixture","inputs":{"format":"mp4"}}}}`,false},
		{`{"prompt":{"1":{"class_type":"MapDynamicFixture","inputs":{"format":"unknown","codec":"h264"}}}}`,false},
		{`{"prompt":{"1":{"class_type":"MapDynamicFixture","inputs":{"format":"auto","codec":"h264"}}}}`,false},
	} { err:=validateComfyRequestSchema(domain.WorkloadRequest{Payload:json.RawMessage(tc.payload)},backendSchema); if (err==nil)!=tc.want { t.Fatalf("map-form dynamic selection acceptance=%t want %t error=%v payload=%s",err==nil,tc.want,err,tc.payload) } }
	if err := validateComfyRequestSchema(domain.WorkloadRequest{Payload:json.RawMessage(`{"prompt":{"1":{"class_type":"MultiselectFixture","inputs":{"flags":["alpha","beta"]}}}}`)},backendSchema); err != nil { t.Fatalf("valid COMBO multiselect literal rejected as a link: %v",err) }
	for _, invalid := range []string{`["alpha","missing"]`,`["missing",0]`,`["alpha",0]`} { if comfyLiteralSupported(json.RawMessage(`["COMBO",{"options":["alpha","beta"],"multiselect":true}]`),json.RawMessage(invalid)) { t.Fatalf("invalid multiselect value accepted: %s",invalid) } }
	if validateComfyRequestSchema(domain.WorkloadRequest{Payload:json.RawMessage(`{"prompt":{"1":{"class_type":"HiddenLabels","inputs":{"api_key":"not-forwarded"}}}}`)},backendSchema) == nil { t.Fatal("caller-supplied hidden credential input was accepted") }
	if !comfyInputAccepts(json.RawMessage(`["FLOAT,INT"]`),"INT") { t.Fatal("comma-separated union connection omitted supported primitive member") }
	if comfyInputAccepts(json.RawMessage(`["FLOAT,INT"]`),"IMAGE") { t.Fatal("union connection accepted unrelated output") }
	if !comfyInputAccepts(json.RawMessage(`["STRING,FILE_3D_GLB,FILE_3D_GLB_COMPRESSED",{"widgetType":"file"}]`),"FILE_3D_GLB") { t.Fatal("comma-separated custom connection union rejected") }
	if !comfyLiteralSupported(json.RawMessage(`["FLOAT,INT",{"default":24}]`),json.RawMessage(`24`)) { t.Fatal("comma-separated primitive literal union rejected") }
	if comfyLiteralSupported(json.RawMessage(`["MODEL,CUSTOM_SOCKET"]`),json.RawMessage(`"anything"`)) { t.Fatal("unsupported custom connection union accepted a literal") }
	for _, graph := range []string{
		`{"prompt":{"1":{"class_type":"File3DSource","inputs":{}},"2":{"class_type":"Preview3D","inputs":{"model_file":["1",0]}}}}`,
		`{"prompt":{"1":{"class_type":"IntegerSource","inputs":{}},"2":{"class_type":"LTXVEmptyLatentAudio","inputs":{"frame_rate":["1",0]}}}}`,
	} { if err:=validateComfyRequestSchema(domain.WorkloadRequest{Payload:json.RawMessage(graph)},backendSchema); err!=nil { t.Fatalf("supported type-union link rejected: %v graph=%s",err,graph) } }
	if validateComfyClassDefinition(json.RawMessage(`{"input":{"required":{"mixed":["STRING,FLOAT",{"min":0.0}] }},"output":[]}`))==nil { t.Fatal("ambiguous numeric bounds on a mixed nonnumeric union were accepted") }
	frameRateSpec:=json.RawMessage(`["FLOAT,INT",{"default":25.0,"display":"number","max":1000.0,"min":1.0,"step":0.01,"tooltip":"Number of frames per second.","widgetType":"FLOAT"}]`)
	for _, value := range []string{`25`,`1`,`1000`,`1.005`} { if !comfyLiteralSupported(frameRateSpec,json.RawMessage(value)) { t.Fatalf("in-range LTXV frame-rate literal rejected: %s",value) } }
	for _, value := range []string{`0.99`,`1000.01`,`"fast"`} { if comfyLiteralSupported(frameRateSpec,json.RawMessage(value)) { t.Fatalf("out-of-range or nonnumeric LTXV frame-rate literal accepted: %s",value) } }
	for _, tc := range []struct{class,payload string; want bool}{
		{"MapDynamicFixture",`{"prompt":{"1":{"class_type":"MapDynamicFixture","inputs":{"format":"mp4","codec":"h264"}}}}`,true},
		{"MapDynamicFixture",`{"prompt":{"1":{"class_type":"MapDynamicFixture","inputs":{"format":"mp4"}}}}`,false},
		{"MapDynamicFixture",`{"prompt":{"1":{"class_type":"MapDynamicFixture","inputs":{"format":"auto","codec":"h264"}}}}`,false},
		{"StringEnumFixture",`{"prompt":{"1":{"class_type":"StringEnumFixture","inputs":{"mode":"STRING"}}}}`,true},
		{"StringEnumFixture",`{"prompt":{"1":{"class_type":"StringEnumFixture","inputs":{"mode":"arbitrary"}}}}`,false},
		{"NumericEnumFixture",`{"prompt":{"1":{"class_type":"NumericEnumFixture","inputs":{"mode":"INT"}}}}`,true},
		{"NumericEnumFixture",`{"prompt":{"1":{"class_type":"NumericEnumFixture","inputs":{"mode":24}}}}`,false},
	} { err:=validateComfyRequestSchema(domain.WorkloadRequest{Payload:json.RawMessage(tc.payload)},backendSchema); if (err==nil)!=tc.want { t.Fatalf("schema fixture %s acceptance=%t want %t error=%v",tc.class,err==nil,tc.want,err) } }
	if err := validateComfyClassDefinition(json.RawMessage(`{"input":{"required":{"seed":["INT",{"min":0,"max":18446744073709551615}]}},"output":[]}`)); err != nil { t.Fatalf("uint64 sampler seed schema rejected: %v", err) }
	if !comfyLiteralSupported(json.RawMessage(`["INT",{"min":0,"max":18446744073709551615}]`), json.RawMessage(`18446744073709551615`)) { t.Fatal("uint64 maximum sampler seed rejected") }
	if comfyLiteralSupported(json.RawMessage(`["INT",{"min":0,"max":18446744073709551615}]`), json.RawMessage(`18446744073709551616`)) { t.Fatal("out-of-range sampler seed accepted") }
	t.Run("in-process Comfy mock does not require live HTTP schema", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		m := NewManager(quietLogger(),store.NewMemoryStore(),time.Second)
		defer m.Close()
		m.RegisterAdapter(&comfyNamedMockAdapter{MockAdapter:NewMockAdapter()})
		m.RegisterTarget(Target{ID:"mock-comfy",Adapter:"comfy",AcceleratorID:"mock-gpu",Enabled:true})
		m.Start(ctx)
		row,_,err:=m.Submit(ctx,domain.WorkloadRequest{OwnerID:"mock-test",Adapter:"comfy",Payload:json.RawMessage(`{"anything":true}`)})
		if err != nil { t.Fatal(err) }
		waitComfyAdmission(t,m,row.Request.ID)
	})
}

type comfyNamedMockAdapter struct { *MockAdapter }
func (*comfyNamedMockAdapter) Name() string { return "comfy" }

func TestComfyFleetGraphSingleCandidate(t *testing.T) {
	graph := domain.WorkloadRequest{Payload: json.RawMessage(`{"prompt":{"a":{"class_type":"A","inputs":{}},"b":{"class_type":"B","inputs":{}}}}`)}
	first := map[string]json.RawMessage{"A": json.RawMessage(`{"input":{},"output":[]}`)}
	second := map[string]json.RawMessage{"B": json.RawMessage(`{"input":{},"output":[]}`)}
	union := map[string]json.RawMessage{"A": first["A"], "B": second["B"]}
	if validateComfyRequestSchema(graph, first) == nil || validateComfyRequestSchema(graph, second) == nil { t.Fatal("split graph incorrectly fit one candidate") }
	if validateComfyRequestSchema(graph, union) != nil { t.Fatal("test union itself should describe both classes") }
}

func TestComfyFleetGraphBestFit(t *testing.T) {
	// Exercise the real admission and HTTPAdapter.Start path: a smaller
	// sufficient context envelope wins even when its target ID sorts later.
	preferred := newAdmissionComfyBackend(t, `{"A":{"input":{},"output":[]}}`)
	fallback := newAdmissionComfyBackend(t, `{"A":{"input":{},"output":[]}}`)
	m := newStartedComfyAdmissionManager(t,
		Target{ID: "z-small", Adapter: "comfy", Endpoint: preferred.URL, RuntimeProtocol: "raw_comfy_v1", ContextLimit: 128, Slots: 1, Enabled: true},
		Target{ID: "a-large", Adapter: "comfy", Endpoint: fallback.URL, RuntimeProtocol: "raw_comfy_v1", ContextLimit: 256, Slots: 1, Enabled: true},
	)
	row := submitComfyAdmission(t, m, 100)
	finished := waitComfyAdmission(t, m, row.Request.ID)
	if finished.Plan == nil || finished.Plan.TargetID != "z-small" {
		t.Fatalf("best-fit admission selected target %v; want smaller sufficient z-small", finished.Plan)
	}
	if preferred.promptPosts.Load() != 1 || fallback.promptPosts.Load() != 0 {
		t.Fatalf("best-fit executed unexpected backends: preferred=%d fallback=%d", preferred.promptPosts.Load(), fallback.promptPosts.Load())
	}
}

func TestComfyFleetGraphAdmissionSpillsBusyInvalidAndOffline(t *testing.T) {
	t.Run("busy first choice", func(t *testing.T) {
		entered := make(chan struct{}, 1)
		release := make(chan struct{})
		var releaseOnce sync.Once
		releaseBusy := func() { releaseOnce.Do(func() { close(release) }) }
		busy := newAdmissionComfyBackendWithPrompt(t, `{"A":{"input":{},"output":[]}}`, func() {
			entered <- struct{}{}
			<-release
		})
		available := newAdmissionComfyBackend(t, `{"A":{"input":{},"output":[]}}`)
		m := newStartedComfyAdmissionManager(t,
			Target{ID: "a-first", Adapter: "comfy", Endpoint: busy.URL, RuntimeProtocol: "raw_comfy_v1", ContextLimit: 128, Slots: 1, Enabled: true},
			Target{ID: "b-second", Adapter: "comfy", Endpoint: available.URL, RuntimeProtocol: "raw_comfy_v1", ContextLimit: 256, Slots: 1, Enabled: true},
		)
		t.Cleanup(releaseBusy)
		first := submitComfyAdmission(t, m, 100)
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			releaseBusy()
			t.Fatal("first workload never occupied preferred backend")
		}
		second := submitComfyAdmission(t, m, 100)
		finishedSecond := waitComfyAdmission(t, m, second.Request.ID)
		if finishedSecond.Plan == nil || finishedSecond.Plan.TargetID != "b-second" {
			releaseBusy()
			t.Fatalf("busy preferred target did not spill to compatible target: %+v", finishedSecond.Plan)
		}
		if busy.promptPosts.Load() != 1 || available.promptPosts.Load() != 1 {
			releaseBusy()
			t.Fatalf("busy spill POST counts: first=%d second=%d", busy.promptPosts.Load(), available.promptPosts.Load())
		}
		releaseBusy()
		waitComfyAdmission(t, m, first.Request.ID)
	})

	for _, test := range []struct {
		name   string
		schema string
		status int
	}{
		{name: "invalid schema", schema: `{"Other":{"input":{},"output":[]}}`, status: http.StatusOK},
		{name: "offline schema endpoint", schema: ``, status: http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			first := newAdmissionComfyBackendWithStatus(t, test.schema, test.status)
			compatible := newAdmissionComfyBackend(t, `{"A":{"input":{},"output":[]}}`)
			m := newStartedComfyAdmissionManager(t,
				Target{ID: "a-first", Adapter: "comfy", Endpoint: first.URL, RuntimeProtocol: "raw_comfy_v1", ContextLimit: 128, Slots: 1, Enabled: true},
				Target{ID: "b-second", Adapter: "comfy", Endpoint: compatible.URL, RuntimeProtocol: "raw_comfy_v1", ContextLimit: 256, Slots: 1, Enabled: true},
			)
			row := submitComfyAdmission(t, m, 100)
			finished := waitComfyAdmission(t, m, row.Request.ID)
			if finished.Plan == nil || finished.Plan.TargetID != "b-second" {
				t.Fatalf("%s preferred candidate did not spill: %+v", test.name, finished.Plan)
			}
			if first.promptPosts.Load() != 0 || compatible.promptPosts.Load() != 1 {
				t.Fatalf("%s spill POST counts: incompatible/offline=%d compatible=%d", test.name, first.promptPosts.Load(), compatible.promptPosts.Load())
			}
		})
	}
}

func TestComfyFleetGraphAdmissionRejectsCrossMachineGraphWithoutPost(t *testing.T) {
	first := newAdmissionComfyBackend(t, `{"A":{"input":{},"output":[]}}`)
	second := newAdmissionComfyBackend(t, `{"B":{"input":{},"output":[]}}`)
	m := newStartedComfyAdmissionManager(t,
		Target{ID: "worker-a", Adapter: "comfy", Endpoint: first.URL, RuntimeProtocol: "raw_comfy_v1", Enabled: true},
		Target{ID: "worker-b", Adapter: "comfy", Endpoint: second.URL, RuntimeProtocol: "raw_comfy_v1", Enabled: true},
	)
	row, _, err := m.Submit(context.Background(), domain.WorkloadRequest{OwnerID: "discovery-test", Plane: domain.PlaneComfy, Adapter: "comfy", Payload: json.RawMessage(`{"prompt":{"a":{"class_type":"A","inputs":{}},"b":{"class_type":"B","inputs":{}}}}`), Recoverable: true})
	if err != nil { t.Fatal(err) }
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && first.promptPosts.Load() == 0 && second.promptPosts.Load() == 0 && (first.objectInfoGets.Load() == 0 || second.objectInfoGets.Load() == 0) {
		time.Sleep(10 * time.Millisecond)
	}
	if first.promptPosts.Load() != 0 || second.promptPosts.Load() != 0 {
		t.Fatalf("unsatisfiable graph was POSTed: worker-a=%d worker-b=%d", first.promptPosts.Load(), second.promptPosts.Load())
	}
	if first.objectInfoGets.Load() == 0 || second.objectInfoGets.Load() == 0 {
		t.Fatalf("admission did not inspect both graph candidates: first=%d second=%d", first.objectInfoGets.Load(), second.objectInfoGets.Load())
	}
	time.Sleep(75 * time.Millisecond) // allow the full admission pass to settle
	current, err := m.store.GetWorkload(context.Background(), row.Request.ID)
	if err != nil { t.Fatal(err) }
	if current.Plan != nil || (current.Status != domain.WorkloadWaiting && current.Status != domain.WorkloadQueued) {
		t.Fatalf("cross-machine graph unexpectedly acquired a plan: status=%s plan=%+v", current.Status, current.Plan)
	}
	if first.promptPosts.Load() != 0 || second.promptPosts.Load() != 0 {
		t.Fatalf("unsatisfiable graph was POSTed: worker-a=%d worker-b=%d", first.promptPosts.Load(), second.promptPosts.Load())
	}
}

type admissionComfyBackend struct {
	URL           string
	objectInfoGets atomic.Int32
	promptPosts   atomic.Int32
}

func newAdmissionComfyBackend(t *testing.T, schema string) *admissionComfyBackend {
	return newAdmissionComfyBackendWithStatus(t, schema, http.StatusOK)
}

func newAdmissionComfyBackendWithPrompt(t *testing.T, schema string, onPrompt func()) *admissionComfyBackend {
	return newAdmissionComfyBackendServer(t, schema, http.StatusOK, onPrompt)
}

func newAdmissionComfyBackendWithStatus(t *testing.T, schema string, status int) *admissionComfyBackend {
	return newAdmissionComfyBackendServer(t, schema, status, nil)
}

func newAdmissionComfyBackendServer(t *testing.T, schema string, status int, onPrompt func()) *admissionComfyBackend {
	t.Helper()
	backend := &admissionComfyBackend{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/object_info":
			backend.objectInfoGets.Add(1)
			w.WriteHeader(status)
			if status == http.StatusOK { _, _ = w.Write([]byte(schema)) }
		case "/prompt":
			backend.promptPosts.Add(1)
			if onPrompt != nil { onPrompt() }
			_ = json.NewEncoder(w).Encode(map[string]string{"prompt_id": "backend-prompt"})
		case "/history/backend-prompt":
			_ = json.NewEncoder(w).Encode(map[string]any{"backend-prompt": map[string]any{"status": map[string]any{"completed": true, "status_str": "success"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	backend.URL = server.URL
	t.Cleanup(server.Close)
	return backend
}

func newStartedComfyAdmissionManager(t *testing.T, targets ...Target) *Manager {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	m := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	m.RegisterAdapter(NewHTTPAdapter("comfy", "comfy", http.DefaultClient))
	for _, target := range targets { m.RegisterTarget(target) }
	m.Start(ctx)
	t.Cleanup(func() { cancel(); m.Close() })
	return m
}

func submitComfyAdmission(t *testing.T, m *Manager, contextTokens int) *domain.Workload {
	t.Helper()
	row, _, err := m.Submit(context.Background(), domain.WorkloadRequest{OwnerID: "discovery-test", Plane: domain.PlaneComfy, Adapter: "comfy", Bounds: domain.WorkloadBounds{ContextTokens: contextTokens}, Payload: json.RawMessage(`{"prompt":{"a":{"class_type":"A","inputs":{}}}}`), Recoverable: true})
	if err != nil { t.Fatal(err) }
	return row
}

func waitComfyAdmission(t *testing.T, m *Manager, id string) *domain.Workload {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	row, err := m.Wait(ctx, id)
	if err != nil { t.Fatalf("workload %s did not finish: %v", id, err) }
	if row.Status != domain.WorkloadSucceeded { t.Fatalf("workload %s finished %s: %+v", id, row.Status, row.Decision) }
	return row
}

func TestComfyFleetGraphAdmissionGenerationFence(t *testing.T) {
	entered, release := make(chan struct{}, 1), make(chan struct{})
	var firstRead sync.Once
	var unblockOnce sync.Once
	unblock := func() { unblockOnce.Do(func() { close(release) }) }
	var originalReads, originalReadsAfterGeneration, changedEndpointReads, posts atomic.Int32
	var generationChanged atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/object_info":
			originalReads.Add(1)
			if generationChanged.Load() { originalReadsAfterGeneration.Add(1) }
			firstRead.Do(func() {
				entered <- struct{}{}
				select { case <-release: case <-r.Context().Done(): return }
			})
			_, _ = w.Write([]byte(`{"A":{"input":{"required":{}},"output":[]}}`))
		case "/changed/object_info":
			changedEndpointReads.Add(1)
			_, _ = w.Write([]byte(`{"A":{"input":{"required":{}},"output":[]}}`))
		case "/prompt":
			posts.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]string{"prompt_id":"unexpected"})
		default: http.NotFound(w, r)
		}
	}))
	defer server.Close()
	defer unblock()
	ctx, cancel := context.WithCancel(context.Background())
	m := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	m.RegisterAdapter(NewHTTPAdapter("comfy", "comfy", server.Client()))
	m.RegisterTarget(Target{ID:"comfy-a",Adapter:"comfy",Endpoint:server.URL,RuntimeProtocol:"raw_comfy_v1",Enabled:true})
	t.Cleanup(func() { cancel(); m.Close() })
	originalGeneration := m.targetGeneration("comfy-a")
	type submitResult struct { row *domain.Workload; err error }
	submitted := make(chan submitResult, 1)
	go func() {
		row, _, err := m.Submit(ctx, domain.WorkloadRequest{OwnerID:"discovery-test",Plane:domain.PlaneComfy,Adapter:"comfy",Bounds:domain.WorkloadBounds{ContextTokens:0},Payload:json.RawMessage(`{"prompt":{"a":{"class_type":"A","inputs":{}}}}`),Recoverable:true})
		submitted <- submitResult{row:row,err:err}
	}()
	select { case <-entered: case <-time.After(3*time.Second): t.Fatal("Manager admission did not fetch the candidate schema") }
	m.RegisterTarget(Target{ID:"comfy-a",Adapter:"comfy",Endpoint:server.URL+"/changed",RuntimeProtocol:"raw_comfy_v1",Enabled:true})
	changedGeneration := m.targetGeneration("comfy-a")
	generationChanged.Store(true)
	unblock()
	var result submitResult
	select { case result = <-submitted: case <-time.After(4*time.Second): t.Fatal("asynchronous Submit did not finish after the held first schema read was released") }
	if result.err != nil || result.row == nil { t.Fatalf("Submit failed after generation fence: row=%+v err=%v",result.row,result.err) }
	if changedGeneration <= originalGeneration { t.Fatalf("target generation did not advance during the held original read: before=%d after=%d",originalGeneration,changedGeneration) }
	current, err := m.store.GetWorkload(context.Background(),result.row.Request.ID)
	if err != nil { t.Fatal(err) }
	if current.Plan != nil || current.Status == domain.WorkloadRunning || posts.Load() != 0 { t.Fatalf("stale admission crossed generation fence: status=%s plan=%+v POSTs=%d",current.Status,current.Plan,posts.Load()) }
	m.mu.RLock(); _, reserved := m.reservations[result.row.Request.ID]; m.mu.RUnlock()
	if reserved { t.Fatal("stale generation left an admission reservation") }
	if originalReads.Load() != 1 || originalReadsAfterGeneration.Load() != 0 || changedEndpointReads.Load() != 0 {
		t.Fatalf("unexpected schema read facts around generation change: original=%d original_after_change=%d changed_endpoint=%d",originalReads.Load(),originalReadsAfterGeneration.Load(),changedEndpointReads.Load())
	}
}

func TestComfyFleetGraphPreStartSchemaFence(t *testing.T) {
	var changed atomic.Bool
	var posts atomic.Int32
	activeEntered, releaseActive := make(chan struct{}), make(chan struct{})
	var activeOnce sync.Once
	backing := store.NewMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	node := &domain.Node{ID:"node",Name:"fixture",SchedulingState:domain.SchedulingEnabled,Desired:domain.Desired{SchedulingEnabled:true},Observed:domain.Observed{Connectivity:domain.ConnectivityConnected,Ready:true,LastSeenAt:time.Now().UTC()},Accelerators:[]domain.Accelerator{{ID:"node-gpu0",NodeID:"node",VRAMTotalMB:24000,VRAMFreeMB:24000}}}
	if _, err := backing.UpsertNode(ctx,node); err != nil { t.Fatal(err) }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/object_info":
			if changed.Load() { _, _ = w.Write([]byte(`{"A":{"input":{"required":{}},"output":["IMAGE"]}}`)); return }
			_, _ = w.Write([]byte(`{"A":{"input":{"required":{}},"output":["MODEL"]}}`))
		case "/prompt":
			posts.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]string{"prompt_id":"unexpected"})
		case "/history/unexpected":
			// Let a bypassed stale-schema mutant settle so the original POST assertion owns the failure.
			_ = json.NewEncoder(w).Encode(map[string]any{"unexpected": map[string]any{"status": map[string]any{"status_str": "error", "completed": true}}})
		default: http.NotFound(w,r)
		}
	}))
	defer server.Close()
	m := NewManager(quietLogger(),backing,time.Second)
	defer m.Close()
	m.SetNodeStore(backing)
	m.SetNodeControl(func(context.Context,string,string,map[string]any,string)(map[string]any,error){ return map[string]any{},nil })
	m.SetManagedGPUPerformance("node",[]int{0})
	m.SetGPUPerformanceControl(func(ctx context.Context,_ string,_ string,args map[string]any,_ string)(map[string]any,error) {
		if args["profile"] == "active" {
			activeOnce.Do(func(){ close(activeEntered) })
			select { case <-releaseActive: case <-ctx.Done(): return nil,ctx.Err() }
		}
		return map[string]any{"managed":true,"accelerator_id":"node-gpu0"},nil
	})
	m.RegisterAdapter(NewHTTPAdapter("comfy","comfy",server.Client()))
	m.RegisterTarget(Target{ID:"comfy-node-route",NodeID:"node",Adapter:"comfy",Endpoint:server.URL,RuntimeProtocol:"raw_comfy_v1",AcceleratorID:"node-gpu0",Enabled:true})
	m.Start(ctx)
	row,_,err:=m.Submit(ctx,domain.WorkloadRequest{OwnerID:"fence-test",Plane:domain.PlaneComfy,Adapter:"comfy",Payload:json.RawMessage(`{"prompt":{"a":{"class_type":"A","inputs":{}}}}`),Recoverable:true})
	if err != nil { t.Fatal(err) }
	select { case <-activeEntered: case <-time.After(3*time.Second): close(releaseActive); t.Fatal("Manager execution never reached the blocked GPU/profile wait") }
	changed.Store(true)
	close(releaseActive)
	waitCtx,waitCancel:=context.WithTimeout(context.Background(),4*time.Second); defer waitCancel()
	finished,waitErr:=m.Wait(waitCtx,row.Request.ID)
	if waitErr != nil { t.Fatal(waitErr) }
	if finished.Status != domain.WorkloadFailed { t.Fatalf("stale schema did not fail before Start: status=%s decision=%+v",finished.Status,finished.Decision) }
	if posts.Load()!=0 { t.Fatalf("schema changed without advertisement but backend received %d prompt POSTs",posts.Load()) }
	m.mu.RLock(); _,reserved:=m.reservations[row.Request.ID]; m.mu.RUnlock()
	if reserved { t.Fatal("pre-start schema rejection leaked its reservation") }
}

func TestComfyFleetGraphNoLocksAcrossFetch(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var first sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path=="/object_info" {
			first.Do(func(){ close(started); <-release })
			_,_ = w.Write([]byte(`{"A":{"input":{"required":{}},"output":[]}}`))
			return
		}
		if r.URL.Path=="/prompt" { _=json.NewEncoder(w).Encode(map[string]string{"prompt_id":"backend-prompt"}); return }
		if r.URL.Path=="/history/backend-prompt" { _=json.NewEncoder(w).Encode(map[string]any{"backend-prompt":map[string]any{"status":map[string]any{"completed":true,"status_str":"success"}}}); return }
		http.NotFound(w,r)
	}))
	defer server.Close()
	m := newStartedComfyAdmissionManager(t,Target{ID:"comfy-a",Adapter:"comfy",Endpoint:server.URL,RuntimeProtocol:"raw_comfy_v1",Enabled:true})
	row:=submitComfyAdmission(t,m,0)
	<-started
	registered := make(chan struct{})
	go func() { m.RegisterTarget(Target{ID:"side-route",Adapter:"llamacpp",Endpoint:server.URL,Enabled:true}); close(registered) }()
	select { case <-registered: case <-time.After(time.Second): close(release); t.Fatal("target registration blocked behind schema fetch") }
	close(release)
	waitComfyAdmission(t,m,row.Request.ID)
}
