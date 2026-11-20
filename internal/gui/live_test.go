package gui

import (
	"testing"

	"eyeofmx/internal/model"
)

func TestLiveMatchesDefaultFilter(t *testing.T) {
	e := model.ActivityEvent{Category: "BOOT", Severity: "INFO", Message: "EyeOFmX live monitor started"}
	key := liveFilterKey("", "All categories")
	if !liveMatches(e, key) {
		t.Fatal("default filter hid a BOOT event — live feed would appear empty")
	}
}

func TestLiveMatchesCategoryAndText(t *testing.T) {
	e := model.ActivityEvent{Category: "NETWORK", Message: "Listening socket opened", Detail: "local=127.0.0.1:8080"}
	if liveMatches(e, liveFilterKey("", "PROCESS")) {
		t.Error("wrong category passed the filter")
	}
	if !liveMatches(e, liveFilterKey("8080", "All categories")) {
		t.Error("search text did not match detail")
	}
	if liveMatches(e, liveFilterKey("shadow", "All categories")) {
		t.Error("unrelated search text passed the filter")
	}
}
