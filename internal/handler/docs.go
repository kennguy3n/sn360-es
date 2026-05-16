package handler

import (
	"embed"
	"io/fs"
	"net/http"
)

// SwaggerUIVersion is pinned at compile time so production builds are
// reproducible. Browsers fetch the assets directly from a CDN — we do
// not bundle them — but the version is fixed.
const SwaggerUIVersion = "5.17.14"

// openapiFS embeds the OpenAPI document so the binary is self-contained
// (no external file lookups at runtime).
//
//go:embed openapi.yaml
var openapiFS embed.FS

// DocsHandler serves Swagger UI (HTML shell + CDN assets) and the
// underlying OpenAPI document. Wire it under `/docs` and
// `/openapi.yaml` from the main server.
type DocsHandler struct {
	spec []byte
}

// NewDocsHandler reads the embedded openapi.yaml. The file MUST exist —
// the embed directive enforces this at compile time, but we surface a
// runtime check too so initialization failures are obvious in tests.
func NewDocsHandler() (*DocsHandler, error) {
	data, err := fs.ReadFile(openapiFS, "openapi.yaml")
	if err != nil {
		return nil, err
	}
	return &DocsHandler{spec: data}, nil
}

// ServeSwaggerUI handles GET /docs. It returns a minimal HTML page
// that loads Swagger UI from a public CDN and points it at the local
// /openapi.yaml endpoint.
func (h *DocsHandler) ServeSwaggerUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write([]byte(swaggerHTML(SwaggerUIVersion)))
}

// ServeOpenAPI handles GET /openapi.yaml.
func (h *DocsHandler) ServeOpenAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(h.spec)
}

// Spec returns the raw OpenAPI document. Useful for tests.
func (h *DocsHandler) Spec() []byte { return h.spec }

// swaggerHTML returns a minimal Swagger UI shell.
func swaggerHTML(version string) string {
	return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SN360-ES API</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@` + version + `/swagger-ui.css" />
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@` + version + `/swagger-ui-bundle.js" crossorigin></script>
  <script>
    window.addEventListener("load", () => {
      window.ui = SwaggerUIBundle({
        url: "/openapi.yaml",
        dom_id: "#swagger-ui",
        deepLinking: true,
        layout: "BaseLayout"
      });
    });
  </script>
</body>
</html>`
}
