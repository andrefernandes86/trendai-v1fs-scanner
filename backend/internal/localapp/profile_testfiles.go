package localapp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
)

type generatedTestFile struct {
	Digest string `json:"digest"`
}

func testFileID(m Mount, key string) string {
	sum := sha256.Sum256([]byte(m.BaseURL() + "/" + key))
	return hex.EncodeToString(sum[:])
}
func (a *App) profileTestFile(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Kind string `json:"kind"`
	}
	if !decode(w, r, &input) {
		return
	}
	if input.Kind != "safe" && input.Kind != "eicar" {
		problem(w, 400, "Select safe or eicar.")
		return
	}
	var p Profile
	if a.Get("profiles", r.PathValue("id"), &p) != nil {
		problem(w, 404, "Profile not found.")
		return
	}
	var m Mount
	if a.Get("mounts", p.SourceMount, &m) != nil {
		problem(w, 400, "Source connection not found.")
		return
	}
	content, name := "Vision One File Security safe test file.\n", "safe.txt"
	if input.Kind == "eicar" {
		content, name = eicarContent, "eicar.com.txt"
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		problem(w, 500, "Cannot generate test ID.")
		return
	}
	key := strings.Trim(p.Prefix, "/")
	if key != "" {
		key += "/"
	}
	key += "v1fs-tests/" + hex.EncodeToString(nonce[:]) + "/" + name
	fullKey := m.Prefix + key
	sum := sha256.Sum256([]byte(content))
	digest := hex.EncodeToString(sum[:])
	f, err := os.CreateTemp(a.DataDir, "profile-test-*")
	if err != nil {
		problem(w, 500, "Cannot stage test file.")
		return
	}
	defer os.Remove(f.Name())
	_, err = f.WriteString(content)
	f.Close()
	if err != nil {
		problem(w, 500, "Cannot stage test file.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	// Persist ownership before publishing, so only generated inputs can be removed after routing.
	if err = a.Save("testfiles", testFileID(m, fullKey), generatedTestFile{Digest: digest}); err != nil {
		problem(w, 500, "Cannot record test file.")
		return
	}
	if m.Type() == "blob" {
		var cErr error
		c, cErr := m.ContainerClient()
		err = cErr
		if err == nil {
			var file *os.File
			file, err = os.Open(f.Name())
			if err == nil {
				_, err = c.NewBlockBlobClient(fullKey).UploadFile(ctx, file, &blockblob.UploadFileOptions{Metadata: map[string]*string{"v1fs_complete": to.Ptr("true")}, AccessConditions: &blob.AccessConditions{ModifiedAccessConditions: &blob.ModifiedAccessConditions{IfNoneMatch: to.Ptr(azcore.ETag("*"))}}})
				file.Close()
			}
		}
	} else {
		err = routeShare(ctx, m, fullKey, f.Name(), digest, hex.EncodeToString(nonce[:]), int64(len(content)))
		if err == nil {
			fs, e := remoteOpen(ctx, m)
			err = e
			if err == nil {
				err = fs.UploadExclusive(fullKey+".complete", strings.NewReader("complete\n"), 9)
				fs.Close()
			}
		}
	}
	if err != nil {
		problem(w, 502, "Test upload failed. Check source write permissions and connectivity.")
		return
	}
	a.Audit("profile.test_file", p.ID, "Created "+input.Kind+" test input: "+key)
	respond(w, 201, map[string]any{"key": key, "source": m.BaseURL() + "/" + fullKey, "automatic": p.Enabled, "request": map[string]any{"kind": input.Kind, "profileId": p.ID, "bytes": len(content)}, "response": map[string]any{"uploaded": true, "completionMarker": true, "sha256": digest}, "message": "Test file uploaded to the profile source. Automatic monitoring will scan and route it after upload stability checks. With automatic monitoring disabled, scan it from Storage explorer."})
}

// Cleanup is restricted to app-generated test files with the exact scanned digest.
func (a *App) cleanupTestFile(ctx context.Context, s Snapshot, digest string) {
	key := s.Source.Prefix + s.Key
	var owned generatedTestFile
	if a.Get("testfiles", testFileID(s.Source, key), &owned) != nil || owned.Digest != digest {
		return
	}
	var err error
	if s.Source.Type() == "blob" {
		c, e := s.Source.ContainerClient()
		err = e
		if err == nil {
			_, err = c.NewBlobClient(key).Delete(ctx, &blob.DeleteOptions{AccessConditions: &blob.AccessConditions{ModifiedAccessConditions: &blob.ModifiedAccessConditions{IfMatch: to.Ptr(azcore.ETag(s.ETag))}}})
		}
	} else {
		fs, e := remoteOpen(ctx, s.Source)
		err = e
		if err == nil {
			// Verify current content and identity again before removing this generated input.
			info, e := fs.Stat(key)
			err = e
			if err == nil && infoTag(info) == s.ETag {
				err = verifyRemote(fs, key, digest, s.Size)
				if err == nil {
					err = fs.Remove(key)
					if err == nil {
						_ = fs.Remove(key + ".complete")
					}
				}
			}
			fs.Close()
		}
	}
	if err != nil {
		a.Audit("profile.test_cleanup_failed", s.Profile.ID, "Destination verified; generated source could not be removed.")
	}
}
