package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type environmentSupportEvent struct {
	UTC  string `json:"utc"`
	Kind string `json:"kind"`
	Code string `json:"code"`
}

type environmentSupportOptions struct {
	SettingsCached bool
	Settings       *EnvironmentSettings
}

// Support exports are intentionally constructed from selected fields rather
// than serializing receipts, settings, inventories or workbench addresses.
func environmentSupportReport(ctx context.Context, root string, inventory func(context.Context) (EnvironmentInventory, error), options ...environmentSupportOptions) (map[string]any, error) {
	root, e := environmentRoot(root, false)
	if e != nil || !validEnvironmentOwner(root) {
		return nil, errors.New("OWNED_ENVIRONMENT_REQUIRED_FOR_SUPPORT")
	}
	report := map[string]any{
		"schema": "hongai.environment-support.v1", "version": environmentVersion,
		"generatedUtc": time.Now().UTC().Format(time.RFC3339), "platform": runtime.GOOS, "architecture": runtime.GOARCH,
		"scope": "PREPARATION_DIAGNOSTICS_ONLY_NO_ACCOUNT_OR_CHAT_READ", "hostNetworkModified": false,
		"containsCredentials": false, "containsRawIPOrPaths": false, "fullEnvironmentAccepted": false,
	}
	var receipt EnvironmentReceipt
	if decodeFile(filepath.Join(root, "environment-receipt.json"), &receipt) == nil && receipt.Schema == "hongai.environment-install.v1" && samePath(receipt.Root, root) && ownedEnvironmentRuntime(root, receipt.Runtime) {
		b, readError := readRuntimeBytes(receipt.Runtime)
		report["installedRuntimeMatchesReceipt"] = readError == nil && digest(b) == receipt.RuntimeSHA
	} else {
		report["installedRuntimeMatchesReceipt"] = false
	}
	settingsPresent := false
	if i, statError := os.Lstat(filepath.Join(root, "environment-settings.sealed")); statError == nil && i.Mode().IsRegular() {
		settingsPresent = true
	}
	var settings EnvironmentSettings
	settingsError := errors.New("NO_READABLE_SETTINGS")
	if len(options) > 0 && options[0].SettingsCached {
		report["settingsScope"] = "CURRENT_WORKBENCH_CACHE_NO_KEYCHAIN_REOPEN"
		if options[0].Settings != nil {
			settings, settingsError = *options[0].Settings, nil
		}
	} else {
		report["settingsScope"] = "CURRENT_USER_PROTECTED_STORAGE"
		settings, settingsError = loadEnvironmentSettings(root)
	}
	report["settingsPresent"] = settingsPresent
	report["settingsReadable"] = settingsError == nil
	report["stageOneConfirmed"] = settingsError == nil && settings.HostAssessmentConfirmed
	inv, inventoryError := inventory(ctx)
	report["inventoryStatus"] = environmentSupportCode(safeEnvironmentCode(inventoryError))
	if inventoryError == nil {
		report["officialClientInstalled"] = inv.Client.Installed
		report["officialSignatureVerified"] = inv.Client.Verified
		// A version is not free-form diagnostic text; only numeric dotted forms
		// are exported. Installation paths and per-user identifiers never are.
		if environmentVersionStringSafe(inv.Client.Version) {
			report["officialClientVersion"] = inv.Client.Version
		}
		report["profileCandidateExists"] = inv.Client.ProfileExists
		report["timeZoneMatchesOrder"] = settingsError == nil && inv.TimeZone == settings.TimeZone
	}
	events, eventStatus := environmentSupportEvents(root)
	report["events"] = events
	report["eventStatus"] = eventStatus
	report["eventScope"] = "CURRENT_LOG_TAIL_UP_TO_64_KIB_LAST_40_VALID_RECORDS_NOT_A_FULL_HISTORY_ATTESTATION"
	return report, nil
}

func environmentVersionStringSafe(v string) bool {
	if len(v) == 0 || len(v) > 64 {
		return false
	}
	for _, c := range v {
		if c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	parts := strings.Split(v, ".")
	if len(parts) < 3 || len(parts) > 4 {
		return false
	}
	for _, part := range parts {
		if len(part) < 1 || len(part) > 5 {
			return false
		}
	}
	if ip, e := netip.ParseAddr(v); e == nil && ip.IsValid() {
		return false
	}
	return true
}

func environmentSupportCode(code string) string {
	switch code {
	case "SUCCESS", "REQUESTED", "SAVE_REQUESTED", "SAVED_NO_HOST_CHANGE", "STARTED_LOOPBACK_ONLY", "STOPPED_NETWORK_AND_CLIENT_UNCHANGED",
		"INVENTORY_COMPLETED_NO_ACCOUNT_READ", "THREE_TRACE_SAMPLES_MATCH", "PROXY_OR_TRACE_UNAVAILABLE", "FINAL_EXIT_MISMATCH",
		"HEALTH_NOT_ACCEPTED_NO_LAUNCH", "VERIFIED_ENTRY_ACTIVATION_REQUESTED", "OFFICIAL_ACTIVATION_REQUESTED_ACCOUNT_TEST_PENDING",
		"PROXY_HEALTH_NOT_ACCEPTED_NO_CLIENT_LAUNCH", "WORKBENCH_OPERATION_CANCELLED", "VERIFIED_OFFICIAL_CLIENT_REQUIRED",
		"TIME_ZONE_DIFFERENCE_REQUIRES_REVIEW_NO_SETTINGS_CHANGED", "COMPLETE_STAGE_ONE_ASSESSMENT_FIRST", "APPROVED_CONFIGURATION_REQUIRED",
		"WINDOWS_OFFICIAL_CLIENT_INVENTORY_FAILED", "WINDOWS_INVENTORY_RESPONSE_INVALID", "OFFICIAL_APP_VERSION_UNREADABLE",
		"OFFICIAL_APP_SIGNATURE_OR_IDENTITY_NOT_VERIFIED", "OFFICIAL_APP_EXECUTABLE_METADATA_INVALID", "OFFICIAL_APPMODEL_ACTIVATION_FAILED",
		"OFFICIAL_APP_ACTIVATION_FAILED", "INVENTORY_NOT_READY_REFRESH_FIRST", "EXISTING_SETTINGS_UNREADABLE_RESTORE_OR_REVIEW_REQUIRED":
		return code
	default:
		return "UNLISTED_STATUS_REDACTED"
	}
}

func environmentSupportKind(kind string) string {
	switch kind {
	case "WORKBENCH", "SETTINGS", "INVENTORY", "PROBE", "LAUNCH", "DAILY_LAUNCH":
		return kind
	default:
		return "UNLISTED_OPERATION_REDACTED"
	}
}

func environmentSupportEvents(root string) ([]environmentSupportEvent, string) {
	events := []environmentSupportEvent{}
	p := filepath.Join(root, "environment-events.jsonl")
	info, e := os.Lstat(p)
	if os.IsNotExist(e) {
		return events, "NO_OPERATION_EVENTS"
	}
	if e != nil || !info.Mode().IsRegular() {
		return events, "EVENT_PATH_UNAVAILABLE_NO_RAW_DETAILS"
	}
	f, e := os.Open(p)
	if e != nil {
		return events, "EVENT_READ_UNAVAILABLE_NO_RAW_DETAILS"
	}
	defer f.Close()
	start := info.Size() - 64*1024
	if start < 0 {
		start = 0
	}
	if _, e = f.Seek(start, io.SeekStart); e != nil {
		return events, "EVENT_READ_UNAVAILABLE_NO_RAW_DETAILS"
	}
	b, e := io.ReadAll(io.LimitReader(f, 64*1024))
	if e != nil {
		return events, "EVENT_READ_UNAVAILABLE_NO_RAW_DETAILS"
	}
	if start > 0 {
		if first := bytes.IndexByte(b, '\n'); first >= 0 {
			b = b[first+1:]
		} else {
			return events, "NO_COMPLETE_EVENT_IN_BOUNDED_TAIL"
		}
	}
	status := "SELECTED_EVENT_CODES_ONLY"
	for _, line := range bytes.Split(bytes.TrimSpace(b), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var record struct {
			Event json.RawMessage `json:"event"`
			Hash  string          `json:"hash"`
		}
		var event environmentSupportEvent
		if json.Unmarshal(line, &record) != nil || len(record.Hash) != 64 || digest(record.Event) != record.Hash || json.Unmarshal(record.Event, &event) != nil || !environmentEventCodeValid(event.Kind, 80) || !environmentEventCodeValid(event.Code, 100) {
			status = "INVALID_EVENT_RECORDS_OMITTED"
			continue
		}
		parsed, timeError := time.Parse(time.RFC3339Nano, event.UTC)
		if timeError != nil {
			status = "INVALID_EVENT_RECORDS_OMITTED"
			continue
		}
		event.UTC = parsed.UTC().Format(time.RFC3339Nano)
		event.Kind = environmentSupportKind(event.Kind)
		event.Code = environmentSupportCode(event.Code)
		events = append(events, event)
		if len(events) > 40 {
			events = events[len(events)-40:]
		}
	}
	return events, status
}
