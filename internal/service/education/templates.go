package education

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
	"text/template"

	"github.com/kennguy3n/sn360-es/internal/dto"
)

// TemplateLibrary stores and renders SimulationTemplate definitions.
// Templates are loaded once at construction and indexed by attack type
// and difficulty so list operations are O(1) lookup + O(n_filtered)
// iteration.
type TemplateLibrary struct {
	mu        sync.RWMutex
	byID      map[string]dto.SimulationTemplate
	byAttack  map[dto.AttackType]map[dto.DifficultyLevel][]string
	templates map[string]*template.Template // subject+body parsed
}

// NewTemplateLibrary constructs an empty library. Use Register to
// add templates programmatically, or LoadDefaultTemplates to seed
// from the embedded catalog.
func NewTemplateLibrary() *TemplateLibrary {
	return &TemplateLibrary{
		byID:      map[string]dto.SimulationTemplate{},
		byAttack:  map[dto.AttackType]map[dto.DifficultyLevel][]string{},
		templates: map[string]*template.Template{},
	}
}

// Register adds (or replaces) a template. Returns an error if the
// template is malformed.
func (l *TemplateLibrary) Register(t dto.SimulationTemplate) error {
	if err := validateTemplate(t); err != nil {
		return err
	}
	subjectTmpl, err := template.New(t.TemplateID + ".subject").Parse(t.SubjectTemplate)
	if err != nil {
		return fmt.Errorf("templates: %s subject: %w", t.TemplateID, err)
	}
	bodyTmpl, err := template.New(t.TemplateID + ".body").Parse(t.BodyTemplate)
	if err != nil {
		return fmt.Errorf("templates: %s body: %w", t.TemplateID, err)
	}
	senderTmpl, err := template.New(t.TemplateID + ".sender").Parse(t.SenderDisplayTemplate)
	if err != nil {
		return fmt.Errorf("templates: %s sender: %w", t.TemplateID, err)
	}
	domainTmpl, err := template.New(t.TemplateID + ".domain").Parse(t.SenderDomainTemplate)
	if err != nil {
		return fmt.Errorf("templates: %s domain: %w", t.TemplateID, err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.byID[t.TemplateID] = t
	if _, ok := l.byAttack[t.AttackType]; !ok {
		l.byAttack[t.AttackType] = map[dto.DifficultyLevel][]string{}
	}
	// Avoid duplicate index entries on re-register. We allocate a
	// fresh slice rather than reslicing `existing` (with
	// `existing[:0]`) so the underlying array of any retained
	// reference is not mutated by subsequent appends.
	existing := l.byAttack[t.AttackType][t.Difficulty]
	dedup := make([]string, 0, len(existing)+1)
	for _, id := range existing {
		if id != t.TemplateID {
			dedup = append(dedup, id)
		}
	}
	dedup = append(dedup, t.TemplateID)
	sort.Strings(dedup)
	l.byAttack[t.AttackType][t.Difficulty] = dedup
	l.templates[t.TemplateID+".subject"] = subjectTmpl
	l.templates[t.TemplateID+".body"] = bodyTmpl
	l.templates[t.TemplateID+".sender"] = senderTmpl
	l.templates[t.TemplateID+".domain"] = domainTmpl
	return nil
}

// List returns templates that match the filter. Either attackType or
// difficulty can be zero-value to widen the filter on that axis.
func (l *TemplateLibrary) List(attackType dto.AttackType, difficulty dto.DifficultyLevel) []dto.SimulationTemplate {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var out []dto.SimulationTemplate
	for _, t := range l.byID {
		if attackType != "" && t.AttackType != attackType {
			continue
		}
		if difficulty != "" && t.Difficulty != difficulty {
			continue
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TemplateID < out[j].TemplateID })
	return out
}

// Get returns the template for an ID, or false if not registered.
func (l *TemplateLibrary) Get(templateID string) (dto.SimulationTemplate, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	t, ok := l.byID[templateID]
	return t, ok
}

// Render produces a RenderedSimulation for the requested template,
// substituting params into the subject / body / sender / domain.
// Unknown params are ignored; missing params render as the empty
// string. ContainsHazard is always true — these are simulations, not
// production mail.
func (l *TemplateLibrary) Render(templateID string, params map[string]string) (dto.RenderedSimulation, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	t, ok := l.byID[templateID]
	if !ok {
		return dto.RenderedSimulation{}, fmt.Errorf("templates: unknown template %q", templateID)
	}
	subject, err := renderOne(l.templates[templateID+".subject"], params)
	if err != nil {
		return dto.RenderedSimulation{}, err
	}
	body, err := renderOne(l.templates[templateID+".body"], params)
	if err != nil {
		return dto.RenderedSimulation{}, err
	}
	sender, err := renderOne(l.templates[templateID+".sender"], params)
	if err != nil {
		return dto.RenderedSimulation{}, err
	}
	domain, err := renderOne(l.templates[templateID+".domain"], params)
	if err != nil {
		return dto.RenderedSimulation{}, err
	}
	out := dto.RenderedSimulation{
		TemplateID:     t.TemplateID,
		Subject:        subject,
		Body:           body,
		SenderDisplay:  sender,
		SenderDomain:   domain,
		LandingPage:    t.LandingPageType,
		Parameters:     copyParams(params),
		ContainsHazard: true,
	}
	return out, nil
}

func renderOne(t *template.Template, params map[string]string) (string, error) {
	if t == nil {
		return "", nil
	}
	var b strings.Builder
	if err := t.Execute(&b, paramsMap(params)); err != nil {
		return "", fmt.Errorf("templates: render %s: %w", t.Name(), err)
	}
	return b.String(), nil
}

type paramsMap map[string]string

// AttackTypes returns every attack type currently registered, sorted.
func (l *TemplateLibrary) AttackTypes() []dto.AttackType {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]dto.AttackType, 0, len(l.byAttack))
	for k := range l.byAttack {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func validateTemplate(t dto.SimulationTemplate) error {
	switch {
	case t.TemplateID == "":
		return errors.New("templates: template_id is required")
	case !t.AttackType.Valid():
		return fmt.Errorf("templates: invalid attack_type %q", t.AttackType)
	case !t.Difficulty.Valid():
		return fmt.Errorf("templates: invalid difficulty %q", t.Difficulty)
	case t.SubjectTemplate == "":
		return errors.New("templates: subject_template is required")
	case t.BodyTemplate == "":
		return errors.New("templates: body_template is required")
	case t.SenderDisplayTemplate == "":
		return errors.New("templates: sender_display_template is required")
	case t.SenderDomainTemplate == "":
		return errors.New("templates: sender_domain_template is required")
	case t.LandingPageType == "":
		return errors.New("templates: landing_page_type is required")
	}
	return nil
}

func copyParams(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// --- Embedded default catalog ---------------------------------------

//go:embed templates/*.json
var embeddedTemplates embed.FS

// LoadDefaultTemplates returns a library seeded with the embedded
// default templates (at least one Easy/Medium/Hard per attack type).
func LoadDefaultTemplates() (*TemplateLibrary, error) {
	return loadTemplatesFromFS(embeddedTemplates, "templates")
}

func loadTemplatesFromFS(fsys fs.FS, root string) (*TemplateLibrary, error) {
	entries, err := fs.ReadDir(fsys, root)
	if err != nil {
		return nil, fmt.Errorf("templates: read dir %s: %w", root, err)
	}
	lib := NewTemplateLibrary()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		blob, err := fs.ReadFile(fsys, path.Join(root, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("templates: read %s: %w", e.Name(), err)
		}
		var batch []dto.SimulationTemplate
		if err := json.Unmarshal(blob, &batch); err != nil {
			return nil, fmt.Errorf("templates: parse %s: %w", e.Name(), err)
		}
		for _, t := range batch {
			if err := lib.Register(t); err != nil {
				return nil, fmt.Errorf("templates: %s: %w", e.Name(), err)
			}
		}
	}
	return lib, nil
}
