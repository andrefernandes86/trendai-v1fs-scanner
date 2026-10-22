package localapp

import (
	"strings"
	"testing"
)

// History reconciliation must search by source key rather than scan all jobs
// in the profile for every unmatched inventory entry.
func TestInventoryIdentityLookupUsesKeyIndex(t *testing.T) {
	a := testApp(t)
	rows, err := a.DB.Query(`EXPLAIN QUERY PLAN SELECT j.id FROM jobs j WHERE j.profile_id=? AND j.key=? AND trim(j.etag,'"')=trim(?,'"') ORDER BY j.created_at DESC LIMIT 1`, "profile", "file.csv", "etag")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	indexed := false
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(detail, "USE TEMP B-TREE") {
			t.Fatalf("history lookup sorts profile history: %s", detail)
		}
		if strings.Contains(detail, "profile_id=? AND key=?") {
			indexed = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !indexed {
		t.Fatal("inventory identity lookup does not search by profile and key")
	}
}
