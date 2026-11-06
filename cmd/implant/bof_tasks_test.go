package main

import (
	"context"
	"encoding/base64"
	"runtime"
	"testing"
)

func TestInlineExecuteValidation(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString([]byte("not-a-real-coff"))
	cases := []string{
		`not-json`,
		`{}`,
		`{"coff":"!!not-base64!!"}`,
	}
	if runtime.GOOS != "windows" {
		cases = append(cases, `{"coff":"`+valid+`"}`)
	}
	for _, args := range cases {
		if _, err := handleInlineExecute(context.Background(), args); err == nil {
			t.Errorf("handleInlineExecute(%q) unexpectedly succeeded", args)
		}
	}
}
