package localapp

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
)

type Detection struct {
	Name   string `json:"name"`
	Engine string `json:"engine,omitempty"`
	File   string `json:"file,omitempty"`
}
type ScanDetails struct {
	Detections []Detection     `json:"detections"`
	Response   json.RawMessage `json:"response"`
}

func extractDetections(raw []byte) []Detection {
	var root map[string]any
	out := []Detection{}
	seen := map[string]bool{}
	if json.Unmarshal(raw, &root) != nil {
		return out
	}
	var visit func(any, string, bool)
	visit = func(value any, engine string, inMalware bool) {
		switch v := value.(type) {
		case []any:
			for _, item := range v {
				visit(item, engine, inMalware)
			}
		case map[string]any:
			name, _ := v["malwareName"].(string)
			if name == "" && inMalware {
				name, _ = v["name"].(string)
			}
			if e, ok := v["engine"].(string); ok {
				engine = e
			}
			file, _ := v["fileName"].(string)
			if name != "" {
				key := engine + "\x00" + name + "\x00" + file
				if !seen[key] {
					out = append(out, Detection{Name: name, Engine: engine, File: file})
					seen[key] = true
				}
			}
			for k, item := range v {
				if k == "malware" || k == "foundMalwares" {
					visit(item, engine, true)
				}
			}
		}
	}
	visit(root, "", false)
	if engines, ok := root["result"].(map[string]any); ok {
		for engine, result := range engines {
			visit(result, engine, false)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Engine+out[i].Name+out[i].File < out[j].Engine+out[j].Name+out[j].File
	})
	return out
}
func (a *App) recordScanDetails(id string, raw []byte, secret string) error {
	cleaned := string(raw)
	if secret != "" {
		cleaned = strings.ReplaceAll(cleaned, secret, "[redacted]")
	}
	if !json.Valid([]byte(cleaned)) {
		b, _ := json.Marshal(map[string]string{"error": "Scanner response was not valid JSON"})
		cleaned = string(b)
	}
	details := ScanDetails{Detections: extractDetections([]byte(cleaned)), Response: json.RawMessage(cleaned)}
	sealed, e := a.Seal(details)
	if e != nil {
		return e
	}
	_, e = a.DB.Exec("INSERT INTO scan_details(job_id,payload) VALUES(?,?) ON CONFLICT(job_id) DO UPDATE SET payload=excluded.payload", id, sealed)
	return e
}
func (a *App) scanDetails(w http.ResponseWriter, r *http.Request) {
	var b []byte
	if a.DB.QueryRow("SELECT payload FROM scan_details WHERE job_id=?", r.PathValue("id")).Scan(&b) != nil {
		problem(w, 404, "Scanner response was not recorded for this job. Historical jobs require rescanning.")
		return
	}
	var result ScanDetails
	if a.Unseal(b, &result) != nil {
		problem(w, 500, "Could not read scanner response.")
		return
	}
	respond(w, 200, result)
}
