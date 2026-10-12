// Package workflowtpl turns a named ComfyUI workflow plus a few typed settings
// into the API graph the managed Comfy route runs. Callers send
//
//	{"workflow": "image-qwen21-photoreal", "params": {"prompt": "..."}}
//
// instead of a whole node graph. Each template file pins one graph, the
// runtime profile it runs under, and the parameters a caller may set, each
// bound to exact node inputs with limits and defaults. Everything a caller
// cannot set stays as the template author tuned it.
package workflowtpl

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Param types.
const (
	TypeString  = "string"
	TypeInteger = "integer"
	TypeNumber  = "number"
	TypeBoolean = "boolean"
	TypeEnum    = "enum"
	TypeSeed    = "seed"  // integer; random when omitted
	TypeImage   = "image" // artifact id of an uploaded or produced image
	TypeVideo   = "video" // artifact id of an uploaded or produced video
)

// maxSeed keeps seeds exactly representable as JSON numbers.
const maxSeed = int64(1)<<53 - 1

// Binding writes a parameter's value into one node input. Format, for string
// parameters only, wraps the value: "l3n0v0, {value}"; "{tokens:style}"
// inserts the Tokens entry of enum parameter "style" for its chosen value.
// Map, for enum parameters only, writes Map[value] instead of the value (e.g.
// a style name to a LoRA file).
type Binding struct {
	Node   string         `json:"node"`
	Input  string         `json:"input"`
	Format string         `json:"format,omitempty"`
	Map    map[string]any `json:"map,omitempty"`
}

// Bypass removes Node from the graph when an enum parameter takes one of the
// When values, rewiring every consumer of the node's output N to the link in
// its input Outputs[N] (e.g. a LoRA loader's MODEL output to its "model"
// input), so "none" loads nothing instead of a zero-strength LoRA.
type Bypass struct {
	Node    string            `json:"node"`
	When    []string          `json:"when"`
	Outputs map[string]string `json:"outputs"`
}

type Param struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Description string   `json:"description,omitempty"`
	Required    bool     `json:"required,omitempty"`
	Default     any      `json:"default,omitempty"`
	Min         *float64 `json:"min,omitempty"`
	Max         *float64 `json:"max,omitempty"`
	MultipleOf  int64    `json:"multiple_of,omitempty"`
	MaxLength   int      `json:"max_length,omitempty"`
	Values      []string `json:"values,omitempty"`
	// Tokens are prompt fragments per enum value, inserted by "{tokens:name}"
	// in a string binding's Format (e.g. a LoRA's trigger word).
	Tokens map[string]string `json:"tokens,omitempty"`
	Bypass []Bypass          `json:"bypass,omitempty"`
	Bind   []Binding         `json:"bind"`
}

var tokenRefPattern = regexp.MustCompile(`\{tokens:([a-z][a-z0-9_]*)\}`)

func formatTokenRefs(format string) []string {
	var refs []string
	for _, match := range tokenRefPattern.FindAllStringSubmatch(format, -1) {
		refs = append(refs, match[1])
	}
	return refs
}

func (t *Template) param(name string) *Param {
	for i := range t.Params {
		if t.Params[i].Name == name {
			return &t.Params[i]
		}
	}
	return nil
}

func (p *Param) bypasses(node, value string) bool {
	for _, bypass := range p.Bypass {
		if bypass.Node == node && containsValue(bypass.When, value) {
			return true
		}
	}
	return false
}

func containsValue(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

// Template is one workflow file.
type Template struct {
	ID          string `json:"id"`
	Version     int    `json:"version"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	// Operation and Profile ("profile-id@version") select how the compiled
	// graph is admitted, exactly as a hand-written request would.
	Operation string   `json:"operation"`
	Profile   string   `json:"profile"`
	Outputs   []string `json:"outputs,omitempty"`
	// TypicalSeconds is a rough warm runtime on the current hardware, shown
	// in discovery so callers can pick between fast and high-quality variants.
	TypicalSeconds int                        `json:"typical_seconds,omitempty"`
	Params         []Param                    `json:"params"`
	Graph          map[string]json.RawMessage `json:"graph"`
}

// Ref is "id@version".
func (t *Template) Ref() string { return fmt.Sprintf("%s@%d", t.ID, t.Version) }

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,63}$`)
var namePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

type node struct {
	ClassType string         `json:"class_type"`
	Inputs    map[string]any `json:"inputs"`
}

// Validate checks the template is self-consistent: every binding names an
// existing node and literal input, and every default satisfies its limits.
func (t *Template) Validate() error {
	if !idPattern.MatchString(t.ID) || t.Version < 1 {
		return fmt.Errorf("template id %q / version %d is invalid", t.ID, t.Version)
	}
	if t.Title == "" || t.Operation == "" || !strings.Contains(t.Profile, "@") {
		return fmt.Errorf("template %s requires title, operation and profile (id@version)", t.ID)
	}
	if len(t.Graph) == 0 {
		return fmt.Errorf("template %s has no graph", t.ID)
	}
	nodes, err := decodeGraph(t.Graph)
	if err != nil {
		return fmt.Errorf("template %s: %w", t.ID, err)
	}
	seen := map[string]bool{}
	bound := map[string]string{}
	for i := range t.Params {
		p := &t.Params[i]
		if !namePattern.MatchString(p.Name) || seen[p.Name] {
			return fmt.Errorf("template %s: parameter name %q is invalid or repeated", t.ID, p.Name)
		}
		seen[p.Name] = true
		switch p.Type {
		case TypeString, TypeInteger, TypeNumber, TypeBoolean, TypeSeed, TypeImage, TypeVideo:
		case TypeEnum:
			if len(p.Values) == 0 {
				return fmt.Errorf("template %s: enum %s lists no values", t.ID, p.Name)
			}
		default:
			return fmt.Errorf("template %s: parameter %s has unknown type %q", t.ID, p.Name, p.Type)
		}
		if len(p.Bind) == 0 {
			return fmt.Errorf("template %s: parameter %s binds no node input", t.ID, p.Name)
		}
		for _, b := range p.Bind {
			n, ok := nodes[b.Node]
			if !ok {
				return fmt.Errorf("template %s: parameter %s binds missing node %q", t.ID, p.Name, b.Node)
			}
			current, ok := n.Inputs[b.Input]
			if !ok {
				return fmt.Errorf("template %s: parameter %s binds missing input %s.%s", t.ID, p.Name, b.Node, b.Input)
			}
			if _, link := current.([]any); link {
				return fmt.Errorf("template %s: parameter %s binds linked input %s.%s", t.ID, p.Name, b.Node, b.Input)
			}
			key := b.Node + "." + b.Input
			if other := bound[key]; other != "" {
				return fmt.Errorf("template %s: input %s is bound by both %s and %s", t.ID, key, other, p.Name)
			}
			bound[key] = p.Name
			if b.Format != "" && (p.Type != TypeString || !strings.Contains(b.Format, "{value}")) {
				return fmt.Errorf("template %s: parameter %s format needs a string parameter and {value}", t.ID, p.Name)
			}
			if b.Map != nil {
				if p.Type != TypeEnum {
					return fmt.Errorf("template %s: parameter %s map needs an enum parameter", t.ID, p.Name)
				}
				for _, value := range p.Values {
					if _, mapped := b.Map[value]; !mapped && !p.bypasses(b.Node, value) {
						return fmt.Errorf("template %s: parameter %s map lacks value %q", t.ID, p.Name, value)
					}
				}
			}
		}
		if (len(p.Tokens) > 0 || len(p.Bypass) > 0) && p.Type != TypeEnum {
			return fmt.Errorf("template %s: parameter %s tokens/bypass need an enum parameter", t.ID, p.Name)
		}
		for _, bypass := range p.Bypass {
			n, ok := nodes[bypass.Node]
			if !ok || len(bypass.When) == 0 || len(bypass.Outputs) == 0 {
				return fmt.Errorf("template %s: parameter %s bypass is incomplete", t.ID, p.Name)
			}
			for _, value := range bypass.When {
				if !containsValue(p.Values, value) {
					return fmt.Errorf("template %s: parameter %s bypass names unknown value %q", t.ID, p.Name, value)
				}
			}
			for _, input := range bypass.Outputs {
				if link, isLink := n.Inputs[input].([]any); !isLink || len(link) != 2 {
					return fmt.Errorf("template %s: parameter %s bypass input %s.%s is not a link", t.ID, p.Name, bypass.Node, input)
				}
			}
		}
		if p.Required && p.Default != nil {
			return fmt.Errorf("template %s: required parameter %s may not have a default", t.ID, p.Name)
		}
		if (p.Type == TypeImage || p.Type == TypeVideo) && p.Default != nil {
			return fmt.Errorf("template %s: media parameter %s may not have a default", t.ID, p.Name)
		}
		if !p.Required && p.Default == nil && p.Type != TypeSeed {
			return fmt.Errorf("template %s: optional parameter %s needs a default", t.ID, p.Name)
		}
		if p.Default != nil {
			if _, err := p.coerce(p.Default); err != nil {
				return fmt.Errorf("template %s: default for %s: %w", t.ID, p.Name, err)
			}
		}
	}
	for _, p := range t.Params {
		for _, b := range p.Bind {
			for _, ref := range formatTokenRefs(b.Format) {
				target := t.param(ref)
				if target == nil || target.Type != TypeEnum || len(target.Tokens) == 0 {
					return fmt.Errorf("template %s: parameter %s format references {tokens:%s}, which is not an enum with tokens", t.ID, p.Name, ref)
				}
			}
		}
	}
	return nil
}

func decodeGraph(graph map[string]json.RawMessage) (map[string]node, error) {
	nodes := make(map[string]node, len(graph))
	for id, raw := range graph {
		var n node
		if err := json.Unmarshal(raw, &n); err != nil || n.ClassType == "" || n.Inputs == nil {
			return nil, fmt.Errorf("graph node %q is not a ComfyUI API node", id)
		}
		nodes[id] = n
	}
	return nodes, nil
}

// coerce validates one value against the parameter and returns the value to
// write into the graph.
func (p *Param) coerce(v any) (any, error) {
	switch p.Type {
	case TypeString:
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("must be a string")
		}
		if p.Required && strings.TrimSpace(s) == "" {
			return nil, fmt.Errorf("may not be empty")
		}
		limit := p.MaxLength
		if limit == 0 {
			limit = 4000
		}
		if utf8.RuneCountInString(s) > limit {
			return nil, fmt.Errorf("is longer than %d characters", limit)
		}
		return s, nil
	case TypeInteger, TypeSeed:
		n, ok := wholeNumber(v)
		if !ok {
			return nil, fmt.Errorf("must be a whole number")
		}
		if p.Type == TypeSeed && (n < 0 || n > maxSeed) {
			return nil, fmt.Errorf("must be between 0 and %d", maxSeed)
		}
		if err := p.checkRange(float64(n)); err != nil {
			return nil, err
		}
		if p.MultipleOf > 0 && n%p.MultipleOf != 0 {
			return nil, fmt.Errorf("must be a multiple of %d", p.MultipleOf)
		}
		return n, nil
	case TypeNumber:
		f, ok := v.(float64)
		if !ok {
			if n, isInt := v.(int); isInt {
				f, ok = float64(n), true
			}
		}
		if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, fmt.Errorf("must be a number")
		}
		if err := p.checkRange(f); err != nil {
			return nil, err
		}
		return f, nil
	case TypeBoolean:
		b, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("must be true or false")
		}
		return b, nil
	case TypeEnum:
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("must be one of %s", strings.Join(p.Values, ", "))
		}
		for _, allowed := range p.Values {
			if s == allowed {
				return s, nil
			}
		}
		return nil, fmt.Errorf("must be one of %s", strings.Join(p.Values, ", "))
	case TypeImage, TypeVideo:
		s, ok := v.(string)
		s = strings.TrimPrefix(strings.TrimSpace(s), "artifact://")
		if !ok || s == "" || strings.ContainsAny(s, `/\`) {
			return nil, fmt.Errorf("must be an artifact id")
		}
		return s, nil
	}
	return nil, fmt.Errorf("unknown type %q", p.Type)
}

func (p *Param) checkRange(f float64) error {
	if p.Min != nil && f < *p.Min {
		return fmt.Errorf("must be at least %v", *p.Min)
	}
	if p.Max != nil && f > *p.Max {
		return fmt.Errorf("must be at most %v", *p.Max)
	}
	return nil
}

func wholeNumber(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		if n == math.Trunc(n) && math.Abs(n) <= float64(maxSeed) {
			return int64(n), true
		}
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

// ParamError reports every invalid or unknown parameter at once.
type ParamError struct {
	Workflow string
	Problems map[string]string
}

func (e *ParamError) Error() string {
	names := make([]string, 0, len(e.Problems))
	for name := range e.Problems {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+" "+e.Problems[name])
	}
	return fmt.Sprintf("workflow %s: invalid params: %s", e.Workflow, strings.Join(parts, "; "))
}

// Compiled is a ready-to-submit graph plus the artifacts it reads.
type Compiled struct {
	Graph        map[string]any
	ArtifactRefs []string
	Params       map[string]any // effective values, defaults and seeds filled in
}

// Compile validates params and writes them into a copy of the graph.
func (t *Template) Compile(params map[string]any) (*Compiled, error) {
	problems := map[string]string{}
	known := map[string]bool{}
	for _, p := range t.Params {
		known[p.Name] = true
	}
	for name := range params {
		if !known[name] {
			problems[name] = "is not a parameter of this workflow"
		}
	}
	var graph map[string]any
	raw, _ := json.Marshal(t.Graph)
	if err := json.Unmarshal(raw, &graph); err != nil {
		return nil, err
	}
	out := &Compiled{Graph: graph, Params: map[string]any{}}
	for i := range t.Params {
		p := &t.Params[i]
		v, supplied := params[p.Name]
		if !supplied || v == nil {
			switch {
			case p.Required:
				problems[p.Name] = "is required"
				continue
			case p.Default != nil:
				v = p.Default
			case p.Type == TypeSeed:
				v = randomSeed()
			}
		}
		value, err := p.coerce(v)
		if err != nil {
			problems[p.Name] = err.Error()
			continue
		}
		out.Params[p.Name] = value
		if p.Type == TypeImage || p.Type == TypeVideo {
			out.ArtifactRefs = append(out.ArtifactRefs, value.(string))
		}
	}
	if len(problems) > 0 {
		return nil, &ParamError{Workflow: t.Ref(), Problems: problems}
	}
	// Write values only after every parameter is known: a Format may insert
	// another enum parameter's tokens.
	bypassed := map[string]map[string]string{}
	for i := range t.Params {
		p := &t.Params[i]
		value := out.Params[p.Name]
		if chosen, isEnum := value.(string); isEnum && p.Type == TypeEnum {
			for _, bypass := range p.Bypass {
				if containsValue(bypass.When, chosen) {
					bypassed[bypass.Node] = bypass.Outputs
				}
			}
		}
		for _, b := range p.Bind {
			written := value
			if b.Map != nil {
				written = b.Map[value.(string)]
			}
			if b.Format != "" {
				text := strings.ReplaceAll(b.Format, "{value}", value.(string))
				written = tokenRefPattern.ReplaceAllStringFunc(text, func(ref string) string {
					name := tokenRefPattern.FindStringSubmatch(ref)[1]
					chosen, _ := out.Params[name].(string)
					return t.param(name).Tokens[chosen]
				})
			}
			graph[b.Node].(map[string]any)["inputs"].(map[string]any)[b.Input] = written
		}
	}
	for removedID, outputs := range bypassed {
		removed := graph[removedID].(map[string]any)["inputs"].(map[string]any)
		delete(graph, removedID)
		for _, other := range graph {
			inputs := other.(map[string]any)["inputs"].(map[string]any)
			for name, input := range inputs {
				if link, isLink := input.([]any); isLink && len(link) == 2 && link[0] == removedID {
					inputs[name] = removed[outputs[fmt.Sprint(link[1])]]
				}
			}
		}
	}
	return out, nil
}

func randomSeed() int64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return int64(binary.BigEndian.Uint64(b[:]) & uint64(maxSeed))
}

// Registry holds every loaded template by id; the newest version wins for a
// bare id, and "id@version" selects an exact one.
type Registry struct {
	byRef  map[string]*Template
	latest map[string]*Template
}

// LoadDir reads every *.json template in dir.
func LoadDir(dir string) (*Registry, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	r := &Registry{byRef: map[string]*Template{}, latest: map[string]*Template{}}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		t := &Template{}
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(t); err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
		}
		if err := r.Add(t); err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
		}
	}
	return r, nil
}

// NewRegistry builds a registry from in-memory templates.
func NewRegistry(templates ...*Template) (*Registry, error) {
	r := &Registry{byRef: map[string]*Template{}, latest: map[string]*Template{}}
	for _, t := range templates {
		if err := r.Add(t); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (r *Registry) Add(t *Template) error {
	if err := t.Validate(); err != nil {
		return err
	}
	if r.byRef[t.Ref()] != nil {
		return fmt.Errorf("duplicate workflow %s", t.Ref())
	}
	r.byRef[t.Ref()] = t
	if cur := r.latest[t.ID]; cur == nil || t.Version > cur.Version {
		r.latest[t.ID] = t
	}
	return nil
}

var ErrUnknownWorkflow = errors.New("unknown workflow")

// Get resolves "id" (newest version) or "id@version".
func (r *Registry) Get(ref string) (*Template, error) {
	if r != nil {
		if t := r.byRef[ref]; t != nil {
			return t, nil
		}
		if t := r.latest[ref]; t != nil {
			return t, nil
		}
	}
	return nil, fmt.Errorf("%w %q", ErrUnknownWorkflow, ref)
}

// All returns every template version sorted by id then version.
func (r *Registry) All() []*Template {
	if r == nil {
		return nil
	}
	out := make([]*Template, 0, len(r.byRef))
	for _, t := range r.byRef {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		return out[i].Version < out[j].Version
	})
	return out
}
