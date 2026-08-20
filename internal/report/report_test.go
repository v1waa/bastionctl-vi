package report

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSummaryAndJSONSchema(t *testing.T) {
	r := New("1.2.3", "server", "audit", "localhost")
	r.Add(Result{Control: "one", Status: Pass, Message: "ok"})
	r.Add(Result{Control: "two", Status: Fail, Message: "bad"})
	var output bytes.Buffer
	if err := WriteJSON(&output, r); err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Schema != Schema || decoded.Summary.Pass != 1 || decoded.Summary.Fail != 1 || !decoded.HasFailures() {
		t.Fatalf("unexpected report: %+v", decoded)
	}
}
