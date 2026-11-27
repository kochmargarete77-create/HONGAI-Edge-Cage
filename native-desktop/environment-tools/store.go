package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

type Binding struct {
	Version int               `json:"version"`
	Program string            `json:"program"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env,omitempty"`
	Policy  Policy            `json:"policy"`
}
type Request struct {
	ConfigFile  string   `json:"configFile"`
	DataRoot    string   `json:"dataRoot"`
	PolicyFile  string   `json:"policyFile"`
	ServerNames []string `json:"serverNames"`
}
type Receipt struct {
	Version         int    `json:"version"`
	ConfigFile      string `json:"configFile"`
	BeforeSHA       string `json:"beforeSha256"`
	AfterSHA        string `json:"afterSha256"`
	PolicySHA       string `json:"policySha256"`
	Stage           string `json:"stage"`
	WrappedServers  int    `json:"wrappedServers"`
	ConfigCommitted bool   `json:"configCommitted"`
	RuntimeFile     string `json:"runtimeFile"`
	RuntimeSHA      string `json:"runtimeSha256"`
}

func copyRuntime(source, target string) (string, error) {
	source, e := realPath(source, false)
	if e != nil {
		return "", errors.New("CURRENT_RUNTIME_SOURCE_UNAVAILABLE")
	}
	in, e := os.Open(source)
	if e != nil {
		return "", errors.New("CURRENT_RUNTIME_UNREADABLE")
	}
	defer in.Close()
	info, e := in.Stat()
	if e != nil || info.Size() < 1 || info.Size() > 32*1024*1024 {
		return "", errors.New("RUNTIME_SIZE_OUTSIDE_LIMIT")
	}
	out, e := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if e != nil {
		return "", errors.New("RUNTIME_COPY_CREATE_FAILED")
	}
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(out, h), io.LimitReader(in, 32*1024*1024+1))
	syncErr := out.Sync()
	closeErr := out.Close()
	if e != nil || syncErr != nil || closeErr != nil || n != info.Size() {
		return "", errors.New("RUNTIME_COPY_INCOMPLETE")
	}
	end, e := in.Stat()
	if e != nil || end.Size() != info.Size() || !end.ModTime().Equal(info.ModTime()) {
		return "", errors.New("RUNTIME_SOURCE_CHANGED")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func assertCustomerIdentity() error {
	if runtime.GOOS == "darwin" && os.Geteuid() == 0 {
		return errors.New("RUN_AS_CUSTOMER_USER_NOT_ROOT")
	}
	if runtime.GOOS == "windows" {
		u, e := user.Current()
		if e != nil {
			return errors.New("CURRENT_USER_IDENTITY_UNAVAILABLE")
		}
		if u.Uid == "S-1-5-18" || u.Uid == "S-1-5-19" || u.Uid == "S-1-5-20" {
			return errors.New("RUN_AS_CUSTOMER_USER_NOT_SYSTEM_SERVICE")
		}
	}
	return nil
}

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func randomName() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic("SECURE_RANDOM_FAILED")
	}
	return hex.EncodeToString(b)
}
func realPath(p string, directory bool) (string, error) {
	if !filepath.IsAbs(p) {
		return "", errors.New("ABSOLUTE_LOCAL_PATH_REQUIRED")
	}
	abs := filepath.Clean(p)
	resolved, e := filepath.EvalSymlinks(abs)
	if e != nil {
		return "", errors.New("PATH_UNAVAILABLE")
	}
	equal := abs == resolved
	if runtime.GOOS == "windows" {
		equal = strings.EqualFold(abs, resolved)
	}
	if !equal {
		return "", errors.New("LINK_PATH_REQUIRES_REVIEW")
	}
	info, e := os.Lstat(abs)
	if e != nil || info.IsDir() != directory || (!directory && !info.Mode().IsRegular()) {
		return "", errors.New("PATH_TYPE_MISMATCH")
	}
	return abs, nil
}
func readSmall(p string) ([]byte, error) {
	p, e := realPath(p, false)
	if e != nil {
		return nil, e
	}
	f, e := os.Open(p)
	if e != nil {
		return nil, errors.New("LOCAL_FILE_UNREADABLE")
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || info.Size() > maximumFrame {
		return nil, errors.New("LOCAL_FILE_TOO_LARGE")
	}
	b := make([]byte, info.Size())
	if _, e = ioReadFull(f, b); e != nil {
		return nil, errors.New("LOCAL_FILE_CHANGED")
	}
	return b, nil
}
func parseObject(b []byte) (map[string]any, error) {
	if len(b) >= 3 && string(b[:3]) == "\xef\xbb\xbf" {
		b = b[3:]
	}
	v, e := strictJSON(b)
	if e != nil {
		return nil, errors.New("LOCAL_JSON_INVALID_CONTENT_NOT_LOGGED")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("JSON_OBJECT_REQUIRED")
	}
	return m, nil
}
func decodeFile(p string, v any) error {
	b, e := readSmall(p)
	if e != nil {
		return e
	}
	if _, e = parseObject(b); e != nil {
		return e
	}
	if len(b) >= 3 && string(b[:3]) == "\xef\xbb\xbf" {
		b = b[3:]
	}
	if json.Unmarshal(b, v) != nil {
		return errors.New("LOCAL_TYPED_JSON_INVALID")
	}
	return nil
}
func writeNew(p string, b []byte) error {
	f, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return errors.New("OWNED_FILE_CREATE_FAILED")
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return errors.New("OWNED_FILE_WRITE_FAILED")
	}
	return nil
}
func atomicReplace(p string, b []byte) error {
	parent, e := realPath(filepath.Dir(p), true)
	if e != nil {
		return e
	}
	tmp := filepath.Join(parent, ".hongai-"+randomName()+".pending")
	if e = writeNew(tmp, b); e != nil {
		return e
	}
	defer os.Remove(tmp)
	return replaceFile(tmp, p)
}
func ensureRoot(p string) (string, error) {
	if !filepath.IsAbs(p) || filepath.Clean(p) == filepath.VolumeName(p)+string(os.PathSeparator) {
		return "", errors.New("SPECIFIC_DATA_DIRECTORY_REQUIRED")
	}
	if _, e := os.Lstat(p); os.IsNotExist(e) {
		if _, e = realPath(filepath.Dir(p), true); e != nil {
			return "", e
		}
		if e = os.Mkdir(p, 0700); e != nil {
			return "", errors.New("DATA_DIRECTORY_CREATE_FAILED")
		}
	}
	return realPath(p, true)
}
func commandBinding(node map[string]any, policy Policy) (Binding, error) {
	command, ok := node["command"].(string)
	if !ok || command == "" {
		return Binding{}, errors.New("SELECTED_SERVER_IS_NOT_LOCAL_STDIO")
	}
	program, e := exec.LookPath(command)
	if e != nil {
		return Binding{}, errors.New("UPSTREAM_EXECUTABLE_MISSING")
	}
	program, e = filepath.Abs(program)
	if e != nil {
		return Binding{}, e
	}
	args := []string{}
	if raw, ok := node["args"]; ok {
		list, ok := raw.([]any)
		if !ok {
			return Binding{}, errors.New("UPSTREAM_ARGUMENTS_INVALID")
		}
		for _, v := range list {
			s, ok := v.(string)
			if !ok {
				return Binding{}, errors.New("UPSTREAM_ARGUMENTS_INVALID")
			}
			args = append(args, s)
		}
	}
	if runtime.GOOS == "windows" && (strings.EqualFold(filepath.Ext(program), ".cmd") || strings.EqualFold(filepath.Ext(program), ".bat")) {
		base := strings.ToLower(filepath.Base(program))
		entry := ""
		if base == "npx.cmd" {
			entry = "npx-cli.js"
		}
		if base == "npm.cmd" {
			entry = "npm-cli.js"
		}
		nodeExe := filepath.Join(filepath.Dir(program), "node.exe")
		script := filepath.Join(filepath.Dir(program), "node_modules", "npm", "bin", entry)
		if entry == "" {
			return Binding{}, errors.New("WINDOWS_COMMAND_SHIM_NOT_SUPPORTED")
		}
		if _, e = realPath(nodeExe, false); e != nil {
			return Binding{}, errors.New("NATIVE_NODE_SHIM_TARGET_MISSING")
		}
		if _, e = realPath(script, false); e != nil {
			return Binding{}, errors.New("NATIVE_NPM_SHIM_TARGET_MISSING")
		}
		program = nodeExe
		args = append([]string{script}, args...)
	}
	if _, e = realPath(program, false); e != nil {
		return Binding{}, e
	}
	env := map[string]string{}
	if raw, ok := node["env"]; ok {
		m, ok := raw.(map[string]any)
		if !ok {
			return Binding{}, errors.New("UPSTREAM_ENVIRONMENT_INVALID")
		}
		for k, v := range m {
			s, ok := v.(string)
			if !ok || k == "" || strings.ContainsAny(k, "=\x00") || strings.ContainsRune(s, 0) {
				return Binding{}, errors.New("UPSTREAM_ENVIRONMENT_INVALID")
			}
			env[k] = s
		}
		if runtime.GOOS == "windows" {
			seen := map[string]bool{}
			for key := range env {
				folded := strings.ToUpper(key)
				if seen[folded] {
					return Binding{}, errors.New("UPSTREAM_ENVIRONMENT_CASE_COLLISION")
				}
				seen[folded] = true
			}
		}
	}
	return Binding{Version: 1, Program: program, Args: args, Env: env, Policy: policy}, nil
}

func install(request Request, self string) (map[string]any, error) {
	if e := assertCustomerIdentity(); e != nil {
		return nil, e
	}
	if len(request.ServerNames) == 0 || len(request.ServerNames) > 64 {
		return nil, errors.New("EXPLICIT_SERVER_SELECTION_REQUIRED")
	}
	configPath, e := realPath(request.ConfigFile, false)
	if e != nil {
		return nil, e
	}
	root, e := ensureRoot(request.DataRoot)
	if e != nil {
		return nil, e
	}
	if configPath == filepath.Join(root, "installation.json") {
		return nil, errors.New("CONFIG_OVERLAPS_INTERNAL_STATE")
	}
	lock := filepath.Join(root, "installation.lock")
	if e = writeNew(lock, []byte("HONGAI_INSTALL_OWNER\n")); e != nil {
		return nil, errors.New("INSTALLATION_BUSY_OR_INCOMPLETE_REVIEW_LOCK")
	}
	defer os.Remove(lock)
	before, e := readSmall(configPath)
	if e != nil {
		return nil, e
	}
	var policy Policy
	if e = decodeFile(request.PolicyFile, &policy); e != nil {
		return nil, e
	}
	if _, e = newFilter(policy); e != nil {
		return nil, e
	}
	policyJSON, _ := json.Marshal(policy)
	receiptPath := filepath.Join(root, "installation.json")
	pending := filepath.Join(root, "installation.pending.json")
	if _, e = os.Stat(receiptPath); e == nil {
		var r Receipt
		if e = decodeFile(receiptPath, &r); e != nil {
			return nil, e
		}
		if r.ConfigFile == configPath && r.AfterSHA == digest(before) && r.PolicySHA == digest(policyJSON) {
			return map[string]any{"phase": "ALREADY_INSTALLED", "wrappedServers": r.WrappedServers, "loginStateChanged": false, "hostNetworkChanged": false}, nil
		}
		return nil, errors.New("EXISTING_INSTALLATION_OR_POLICY_CHANGED_REVIEW_NO_OVERWRITE")
	}
	if _, e = os.Stat(pending); e == nil {
		var r Receipt
		if e = decodeFile(pending, &r); e != nil {
			return nil, e
		}
		if r.ConfigFile == configPath && r.AfterSHA == digest(before) && r.PolicySHA == digest(policyJSON) {
			r.ConfigCommitted = true
			b, _ := json.MarshalIndent(r, "", "  ")
			if e = atomicReplace(receiptPath, b); e != nil {
				return nil, e
			}
			os.Remove(pending)
			return map[string]any{"phase": "INSTALLED_RECEIPT_RECOVERED", "wrappedServers": r.WrappedServers, "loginStateChanged": false, "hostNetworkChanged": false}, nil
		}
		return nil, errors.New("PREPARED_INSTALLATION_REQUIRES_REVIEW_NO_AUTOMATIC_RESET")
	}
	config, e := parseObject(before)
	if e != nil {
		return nil, e
	}
	servers, ok := config["mcpServers"].(map[string]any)
	if !ok {
		return nil, errors.New("EXISTING_MCP_SERVERS_REQUIRED_NO_INVENTED_TOOLS")
	}
	bindings := map[string]Binding{}
	selected := map[string]bool{}
	for _, name := range request.ServerNames {
		if selected[name] {
			return nil, errors.New("DUPLICATE_SERVER_SELECTION")
		}
		selected[name] = true
		node, ok := servers[name].(map[string]any)
		if !ok {
			return nil, errors.New("SELECTED_SERVER_NOT_FOUND")
		}
		b, e := commandBinding(node, policy)
		if e != nil {
			return nil, e
		}
		if samePath(b.Program, self) {
			return nil, errors.New("RECURSIVE_WRAPPER_REJECTED")
		}
		bindings[name] = b
	}
	stage := filepath.Join(root, "revision-"+randomName())
	if e = os.Mkdir(stage, 0700); e != nil {
		return nil, e
	}
	runtimeName := "hongai-tools"
	if runtime.GOOS == "windows" {
		runtimeName += ".exe"
	}
	installedRuntime := filepath.Join(stage, runtimeName)
	runtimeSHA, e := copyRuntime(self, installedRuntime)
	if e != nil {
		return nil, e
	}
	backup, e := platformSeal(before, root)
	if e != nil {
		return nil, e
	}
	if e = writeNew(filepath.Join(stage, "original-config.protected"), backup); e != nil {
		return nil, e
	}
	for name, binding := range bindings {
		plain, _ := json.Marshal(binding)
		sealed, e := platformSeal(plain, root)
		if e != nil {
			return nil, e
		}
		bindingFile := filepath.Join(stage, digest([]byte(name))+".binding")
		if e = writeNew(bindingFile, sealed); e != nil {
			return nil, e
		}
		node := servers[name].(map[string]any)
		node["command"] = installedRuntime
		node["args"] = []string{"bridge", "--binding", bindingFile, "--data-root", root}
		delete(node, "env")
	}
	after, e := json.MarshalIndent(config, "", "  ")
	if e != nil {
		return nil, e
	}
	r := Receipt{Version: 1, ConfigFile: configPath, BeforeSHA: digest(before), AfterSHA: digest(after), PolicySHA: digest(policyJSON), Stage: stage, WrappedServers: len(bindings), ConfigCommitted: false, RuntimeFile: installedRuntime, RuntimeSHA: runtimeSHA}
	journal, _ := json.MarshalIndent(r, "", "  ")
	if e = writeNew(pending, journal); e != nil {
		return nil, e
	}
	check, e := readSmall(configPath)
	if e != nil || digest(check) != r.BeforeSHA {
		return nil, errors.New("CONFIG_CHANGED_DURING_PREPARATION_NOT_REPLACED")
	}
	if e = atomicReplace(configPath, after); e != nil {
		return nil, e
	}
	r.ConfigCommitted = true
	journal, _ = json.MarshalIndent(r, "", "  ")
	if e = atomicReplace(receiptPath, journal); e != nil {
		return nil, errors.New("CONFIG_COMMITTED_RECEIPT_PENDING_RETRY_SAME_REQUEST")
	}
	os.Remove(pending)
	return map[string]any{"phase": "INSTALLED", "wrappedServers": len(bindings), "backupEncrypted": true, "loginStateChanged": false, "hostNetworkChanged": false, "fullEnvironmentSimulation": false}, nil
}
func samePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
	}
	return filepath.Clean(a) == filepath.Clean(b)
}
func restore(root string) (map[string]any, error) {
	if e := assertCustomerIdentity(); e != nil {
		return nil, e
	}
	root, e := realPath(root, true)
	if e != nil {
		return nil, e
	}
	lock := filepath.Join(root, "installation.lock")
	if e = writeNew(lock, []byte("HONGAI_RESTORE_OWNER\n")); e != nil {
		return nil, errors.New("INSTALLATION_BUSY_OR_INCOMPLETE_REVIEW_LOCK")
	}
	defer os.Remove(lock)
	var r Receipt
	if e = decodeFile(filepath.Join(root, "installation.json"), &r); e != nil {
		return nil, e
	}
	if r.Version != 1 || !strings.HasPrefix(r.Stage, root+string(os.PathSeparator)) || !strings.HasPrefix(filepath.Base(r.Stage), "revision-") {
		return nil, errors.New("OWNED_RECEIPT_INVALID")
	}
	current, e := readSmall(r.ConfigFile)
	if e != nil || digest(current) != r.AfterSHA {
		return nil, errors.New("CONFIG_CHANGED_SINCE_INSTALL_DO_NOT_OVERWRITE")
	}
	sealed, e := readSmall(filepath.Join(r.Stage, "original-config.protected"))
	if e != nil {
		return nil, e
	}
	before, e := platformOpen(sealed, root)
	if e != nil {
		return nil, e
	}
	if digest(before) != r.BeforeSHA {
		return nil, errors.New("BACKUP_INTEGRITY_FAILED")
	}
	if e = atomicReplace(r.ConfigFile, before); e != nil {
		return nil, e
	}
	if e = replaceFile(filepath.Join(root, "installation.json"), filepath.Join(root, "restored-"+randomName()+".json")); e != nil {
		return nil, errors.New("CONFIG_RESTORED_RECEIPT_ARCHIVE_FAILED")
	}
	return map[string]any{"phase": "RESTORED", "originalConfigBytesRestored": true, "recoveryDataDeleted": false, "loginStateChanged": false, "hostNetworkChanged": false}, nil
}
