package localapp

import "strings"

// Names allow known oversized archives to be held before capture. The worker
// also inspects captured signatures so a renamed archive cannot bypass the cap.
func compressedFileName(name string) bool {
	name = strings.ToLower(name)
	for _, ext := range []string{".zip", ".zipx", ".gz", ".gzip", ".tgz", ".tar", ".7z", ".rar", ".bz2", ".tbz", ".tbz2", ".xz", ".txz", ".zst", ".tzst", ".cab", ".iso", ".lz", ".lzma", ".lz4", ".z", ".docx", ".docm", ".xlsx", ".xlsm", ".xlsb", ".pptx", ".pptm", ".jar", ".war", ".ear", ".apk", ".ipa", ".odt", ".ods", ".odp", ".epub"} {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}
