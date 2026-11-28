"""Offline, metadata-only feedback reports; no collection or network activity."""
import argparse
import hashlib
import html
import json
import math
import os
from pathlib import Path
import re
import secrets
import sys

from analyse_observation import SafeError, _path, read_bounded, summarize_bytes
from activity_events import link_events, parse_activity_events, _utc as event_utc
from compare_observations import compare_summaries, _json_copy, SafeError as ComparisonError
from collect_readonly_macos import blocked_macos_path

MAX_LOGS = 8
MAX_REPORT_BYTES = 2 * 1024 * 1024
REPORT_SCHEMA = "hongai.passive-feedback-report.v1"
PROVENANCE_LABELS = {
    "SYNTHETIC_FIXED_FIXTURE": "合成样例 · 非客户实测",
    "COLLECTOR_DECLARED_PASSIVE_NOT_ATTESTED": "客户侧被动记录 · 来源为采集器声明",
    "UNSPECIFIED_SOURCE_NOT_OBSERVATION_PROOF": "来源未完整标记 · 不能认定为客户实测",
}
DIAGNOSTICS = {
    "HEADER_FOOTER_UTC_ORDER_INVALID": "开始与结束记录的 UTC 顺序相悖",
    "SAMPLE_OUTSIDE_DECLARED_UTC_WINDOW": "采样时间落在声明窗口之外",
    "SAMPLE_AFTER_DECLARED_ELAPSED_WINDOW": "结束耗时早于已有采样",
    "NO_SAMPLES_REVIEW": "没有可分析的采样",
    "TCP_CATEGORY_TOTAL_DISAGREES": "连接类别计数与总数不一致",
    "MONOTONIC_TIMELINE_REVERSED": "相对时间出现逆序",
    "FOOTER_SAMPLE_COUNT_DISAGREES": "结束记录与样本数量不一致",
    "EMPTY_PROCESS_STATE_HAS_NONZERO_COUNT": "空进程状态含有非零计数",
    "EMPTY_TCP_STATE_HAS_NONZERO_COUNT": "空连接状态含有非零计数",
    "PROXY_NAME_ROLE_NOT_VISIBLE_WHILE_APP_ROLE_VISIBLE": "应用名称角色可见，代理名称角色未见；需核查",
    "OBSERVATION_GAP": "存在采样空窗",
    "UTC_AND_ELAPSED_TIMELINES_DIFFER": "UTC 与相对时间有差异；可能有校时或采样延迟",
    "APP_NAME_ROLE_COUNT_CHANGED": "应用名称角色的进程数量发生变化",
}
EVENT_LABELS = {"chat":"聊天", "download":"下载", "tool_use":"工具操作", "app_opened":"打开应用", "app_closed":"关闭应用", "visible_error":"可见错误"}
EVENT_SOURCES = {"customer_reported":"客户报告", "visible_ui":"界面观察"}
EVENT_RESULTS = {"completed":"已完成", "failed":"失败", "unknown":"未知"}
ALIGNMENTS = {"ALIGNED_BOTH_CLOCKS":"双时间信息相符", "ALIGNED_UTC_ONLY":"仅 UTC 对齐", "NOT_ALIGNED":"未对齐"}
FLAGS = {"sourcePathsIncluded","rawPayloadsIncluded","reportAuthenticatesSource","accountRiskOrBanCauseInferred","hardwareSimulationVerified","officialClientReadCoverageCompleted","environmentScoreIssued","fullEnvironmentAccepted","customerReady"}
ACTIVITY_CODES = {"OBSERVATION_SEQUENCE_INCOMPLETE_OR_INCONSISTENT","OBSERVATION_PROTOCOL_ISSUES_REQUIRE_REVIEW","NO_SAMPLES_FOR_EVENT_ALIGNMENT","OBSERVATION_UTC_ORDER_INVALID","OBSERVATION_ELAPSED_NOT_STRICTLY_INCREASING","OBSERVATION_ELAPSED_WINDOW_INVALID","OBSERVATION_CLOCK_AXES_DISAGREE","EVENT_PRECEDES_FIRST_OBSERVED_SAMPLE_NO_ALIGNMENT","EVENT_UTC_OUTSIDE_WINDOW","UTC_WINDOW_NOT_ESTABLISHED","EVENT_ELAPSED_OUTSIDE_WINDOW","ELAPSED_WINDOW_NOT_ESTABLISHED","EVENT_CLOCK_AXES_DISAGREE_OR_UNOBSERVED"}


def _fields(value, allowed, required=None):
    if type(value) is not dict or set(value)-set(allowed) or not set(allowed if required is None else required)<=set(value):
        raise SafeError("REPORT_FIELDS_INVALID")


def _finite(value, minimum=0, maximum=1900):
    if type(value) not in (int,float) or not math.isfinite(value) or not minimum<=value<=maximum:
        raise SafeError("REPORT_NUMBER_INVALID")


def _validate_bundle(original):
    bundle = _json_copy(original)
    _fields(bundle, {"schema","scope","primaryAnalysis","additionalAnalyses","comparison","activityAlignment","inputDigests","eventAnnotationsProvided","eventInputDigest"}|FLAGS)
    if bundle["schema"]!=REPORT_SCHEMA or bundle["scope"]!="OFFLINE_PASSIVE_DIAGNOSTIC_FEEDBACK_ONLY":
        raise SafeError("REPORT_SCHEMA_INVALID")
    if any(bundle[flag] is not False for flag in FLAGS):
        raise SafeError("REPORT_SCOPE_CLAIM_INVALID")
    if type(bundle["additionalAnalyses"]) is not list or len(bundle["additionalAnalyses"])>=MAX_LOGS:
        raise SafeError("REPORT_LOG_LIMIT_OR_TYPE")
    analyses = [bundle["primaryAnalysis"],*bundle["additionalAnalyses"]]
    if type(bundle["comparison"]) is not dict:
        raise SafeError("REPORT_COMPARISON_MISMATCH")
    comparison=compare_summaries(analyses,comparison_scope=bundle["comparison"].get("comparisonScope"))
    if comparison!=bundle["comparison"]:
        raise SafeError("REPORT_COMPARISON_MISMATCH")
    meanings={"NO_SAMPLES_REVIEW":"NO_ACTIVITY_CONCLUSION_POSSIBLE","PROXY_NAME_ROLE_NOT_VISIBLE_WHILE_APP_ROLE_VISIBLE":"REVIEW_ONLY_NOT_ROUTE_OR_LEAK_PROOF","OBSERVATION_GAP":"MISSING_WINDOW_NOT_NO_ACTIVITY","UTC_AND_ELAPSED_TIMELINES_DIFFER":"CLOCK_ADJUSTMENT_OR_CAPTURE_DELAY_REQUIRES_REVIEW","APP_NAME_ROLE_COUNT_CHANGED":"NOT_LOGIN_STATE_OR_DEVICE_ID_CHANGE_PROOF"}
    for analysis in analyses:
        for record in [*analysis["protocolIssues"],*analysis["reviewHints"]]:
            if record["code"] not in DIAGNOSTICS or ("meaning" in record and record["meaning"]!=meanings.get(record["code"])):
                raise SafeError("REPORT_DIAGNOSTIC_CODE_UNKNOWN")
    digests=bundle["inputDigests"]
    if type(digests) is not list or len(digests)!=len(analyses):
        raise SafeError("REPORT_DIGESTS_INVALID")
    for digest,analysis in zip(digests,analyses):
        _fields(digest,{"sessionId","sha256","bytes"})
        if digest["sessionId"]!=analysis["sessionId"] or type(digest["sha256"]) is not str or not re.fullmatch(r"[a-f0-9]{64}",digest["sha256"]):
            raise SafeError("REPORT_DIGESTS_INVALID")
        _safe_integer(digest["bytes"],5*1024*1024)
    activity=bundle["activityAlignment"]
    if type(bundle["eventAnnotationsProvided"]) is not bool or bundle["eventAnnotationsProvided"] is not (activity is not None):
        raise SafeError("REPORT_ACTIVITY_SCOPE_INVALID")
    if activity is None:
        if bundle["eventInputDigest"] is not None:
            raise SafeError("REPORT_DIGESTS_INVALID")
        return bundle
    if type(bundle["eventInputDigest"]) is not str or not re.fullmatch(r"[a-f0-9]{64}",bundle["eventInputDigest"]):
        raise SafeError("REPORT_DIGESTS_INVALID")
    activity_flags={"rawIdentifiersOrPayloadsIncluded","eventSourcesAttested","mcpInvocationVerified","sourceLogPrivacyCertified","accountRiskOrBanCauseInferred","fullEnvironmentAccepted","customerReady"}
    _fields(activity,{"schema","sessionId","scope","annotationsStatus","eventCount","events","observationWindow","alignmentIssues"}|activity_flags)
    if activity["schema"]!="hongai.passive-activity-alignment.v1" or activity["sessionId"]!=analyses[0]["sessionId"] or activity["scope"]!="ANNOTATION_TO_PASSIVE_SAMPLING_TIME_ONLY_NOT_CAUSALITY" or any(activity[flag] is not False for flag in activity_flags):
        raise SafeError("REPORT_ACTIVITY_SCOPE_INVALID")
    events=activity["events"]
    if type(events) is not list or len(events)>200 or type(activity["eventCount"]) is not int or activity["eventCount"]!=len(events):
        raise SafeError("REPORT_EVENT_LIMIT_OR_TYPE")
    if activity["annotationsStatus"]!=("EVENT_ANNOTATIONS_PROVIDED" if events else "NO_EVENT_ANNOTATIONS_NOT_NO_ACTIVITY"):
        raise SafeError("REPORT_ACTIVITY_SCOPE_INVALID")
    for codes in [activity["alignmentIssues"],*[event.get("alignmentCodes") if type(event) is dict else None for event in events]]:
        if type(codes) is not list or len(codes)>len(ACTIVITY_CODES) or any(type(code) is not str or code not in ACTIVITY_CODES for code in codes):
            raise SafeError("REPORT_ACTIVITY_CODES_INVALID")
    base_fields={"eventIndex","utcISO","kind","source","result","code"}
    extensions={"utcWindowStatus","elapsedWindowStatus","clockAgreement","utcElapsedDifferenceSeconds","sampleWindowStatus","alignmentStatus","alignmentCodes","nearbySampleIndices","nearbySampleStatus"}
    for index,event in enumerate(events,1):
        _fields(event,base_fields|extensions|{"elapsedSeconds"},base_fields|extensions)
        if type(event["eventIndex"]) is not int or event["eventIndex"]!=index:
            raise SafeError("REPORT_EVENT_RECORD_INVALID")
        base={key:event[key] for key in {"utcISO","kind","source","result","code","elapsedSeconds"} if key in event}
        parse_activity_events(json.dumps({"schema":"hongai.passive-activity-events.v1","sessionId":activity["sessionId"],"events":[base]}).encode(),activity["sessionId"])
        for key,allowed in (("utcWindowStatus",{"WINDOW_UNAVAILABLE","IN_WINDOW","OUTSIDE_WINDOW"}),("elapsedWindowStatus",{"NOT_PROVIDED","WINDOW_UNAVAILABLE","IN_WINDOW","OUTSIDE_WINDOW"}),("clockAgreement",{"EXACT","WITHIN_DECLARED_TOLERANCE","MISMATCH","UTC_ONLY","NO_OBSERVATION_ANCHOR"}),("sampleWindowStatus",{"NO_SAMPLES","BEFORE_FIRST_SAMPLE","AT_OR_AFTER_FIRST_SAMPLE"}),("alignmentStatus",set(ALIGNMENTS)),("nearbySampleStatus",{"NOT_LINKED","NEARBY_SAMPLES_WITHIN_DECLARED_RADIUS","NO_SAMPLE_WITHIN_DECLARED_RADIUS"})):
            if type(event[key]) is not str or event[key] not in allowed:
                raise SafeError("REPORT_EVENT_RECORD_INVALID")
        nearby=event["nearbySampleIndices"]
        if type(nearby) is not list or len(nearby)>2 or any(type(value) is not int or not 1<=value<=analyses[0]["sampleCount"] for value in nearby):
            raise SafeError("REPORT_EVENT_RECORD_INVALID")
        if event["utcElapsedDifferenceSeconds"] is not None:
            _finite(event["utcElapsedDifferenceSeconds"],-1000000000000,1000000000000)
    window=activity["observationWindow"]
    _fields(window,{"utcStart","utcEnd","elapsedStartSeconds","elapsedEndSeconds","sampleCount","earliestSampleUtcISO","headerElapsedAnchor","captureStructure","captureOutcome","evidenceProvenance","clockToleranceSeconds","nearbySampleRadiusSeconds"})
    for key in ("utcStart","utcEnd","earliestSampleUtcISO"):
        if window[key] is not None:event_utc(window[key])
    for key in ("sampleCount","captureStructure","captureOutcome","evidenceProvenance"):
        if window[key]!=analyses[0][key]:raise SafeError("REPORT_WINDOW_INVALID")
    if window["headerElapsedAnchor"]!="NOT_RECORDED" or window["clockToleranceSeconds"]!=1.0 or window["elapsedStartSeconds"]!=0:
        raise SafeError("REPORT_WINDOW_INVALID")
    _finite(window["nearbySampleRadiusSeconds"],1,30)
    if window["elapsedEndSeconds"] is not None:_finite(window["elapsedEndSeconds"])
    return bundle


def build_feedback(log_bytes, *, event_bytes=None, comparison_scope="independent_sessions"):
    if type(log_bytes) is not list or not 1 <= len(log_bytes) <= MAX_LOGS or any(type(data) is not bytes for data in log_bytes):
        raise SafeError("FEEDBACK_LOG_LIMIT_OR_TYPE")
    digests = [hashlib.sha256(data).hexdigest() for data in log_bytes]
    if len(set(digests)) != len(digests):
        raise SafeError("FEEDBACK_DUPLICATE_INPUT_LOG")
    analyses = [summarize_bytes(data) for data in log_bytes]
    comparison = compare_summaries(analyses, comparison_scope=comparison_scope)
    activity = link_events(log_bytes[0], event_bytes) if event_bytes is not None else None
    return {
        "schema":REPORT_SCHEMA, "scope":"OFFLINE_PASSIVE_DIAGNOSTIC_FEEDBACK_ONLY",
        "primaryAnalysis":analyses[0], "additionalAnalyses":analyses[1:], "comparison":comparison,
        "activityAlignment":activity,
        "inputDigests":[{"sessionId":analysis["sessionId"],"sha256":digest,"bytes":len(data)} for analysis,digest,data in zip(analyses,digests,log_bytes)],
        "eventAnnotationsProvided":event_bytes is not None,
        "eventInputDigest":hashlib.sha256(event_bytes).hexdigest() if event_bytes is not None else None,
        "sourcePathsIncluded":False, "rawPayloadsIncluded":False, "reportAuthenticatesSource":False,
        "accountRiskOrBanCauseInferred":False, "hardwareSimulationVerified":False,
        "officialClientReadCoverageCompleted":False, "environmentScoreIssued":False,
        "fullEnvironmentAccepted":False, "customerReady":False,
    }


def _safe_integer(value, maximum=1000000):
    if type(value) is not int or not 0 <= value <= maximum:
        raise SafeError("REPORT_VALUE_INVALID")
    return str(value)


def _timestamp(value):
    return html.escape(value, quote=True) if type(value) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z", value) else "未提供"


def render_feedback(bundle):
    bundle = _validate_bundle(bundle)
    if type(bundle) is not dict or bundle.get("schema") != REPORT_SCHEMA:
        raise SafeError("REPORT_SCHEMA_INVALID")
    summaries = [bundle["primaryAnalysis"], *bundle["additionalAnalyses"]]
    comparison = compare_summaries(summaries, comparison_scope=bundle["comparison"]["comparisonScope"])
    if comparison != bundle["comparison"]:
        raise SafeError("REPORT_COMPARISON_MISMATCH")
    for flag in ("sourcePathsIncluded","rawPayloadsIncluded","reportAuthenticatesSource","accountRiskOrBanCauseInferred","hardwareSimulationVerified","officialClientReadCoverageCompleted","environmentScoreIssued","fullEnvironmentAccepted","customerReady"):
        if bundle.get(flag) is not False:
            raise SafeError("REPORT_SCOPE_CLAIM_INVALID")
    analysis = summaries[0]
    source_label = PROVENANCE_LABELS[analysis["evidenceProvenance"]]
    processes, tcp = analysis["coverage"]["processNameRoles"], analysis["coverage"]["tcpMetadata"]
    sample_count = _safe_integer(analysis["sampleCount"],180)
    structure = "记录结构完整" if analysis["captureStructure"] == "COMPLETE_RECORD_SEQUENCE" else "记录不完整或存在矛盾"
    outcome = {"COLLECTOR_REPORTED_WINDOW_FINISHED":"采集器报告窗口结束", "COLLECTOR_LIMIT_REACHED":"达到采集限制", "COLLECTOR_STOPPED_EARLY":"采集提前停止", "NOT_ESTABLISHED":"完成情况未建立"}[analysis["captureOutcome"]]
    issues = []
    for kind, items in (("记录问题", analysis["protocolIssues"]), ("排查线索", analysis["reviewHints"])):
        for item in items:
            at = "采样 " + _safe_integer(item["sampleIndex"],180) if "sampleIndex" in item else "当前记录"
            issues.append("<tr><td>"+kind+"</td><td>"+at+"</td><td>"+html.escape(DIAGNOSTICS.get(item["code"],"未识别的固定诊断代码"))+"</td></tr>")
    if not issues:
        issues.append('<tr><td colspan="3">当前已分析字段未提出排查线索；这不代表未观测板块已通过。</td></tr>')
    activity = bundle.get("activityAlignment")
    event_rows = []
    if activity is not None:
        if type(activity) is not dict or activity.get("schema") != "hongai.passive-activity-alignment.v1" or activity.get("sessionId") != analysis["sessionId"]:
            raise SafeError("REPORT_ACTIVITY_SCOPE_INVALID")
        events = activity.get("events")
        if type(events) is not list or len(events)>200:
            raise SafeError("REPORT_EVENT_LIMIT_OR_TYPE")
        for event in events:
            if type(event) is not dict:
                raise SafeError("REPORT_EVENT_RECORD_INVALID")
            event_rows.append("<tr><td>"+_timestamp(event.get("utcISO"))+"</td><td>"+EVENT_LABELS.get(event.get("kind"),"未知类型")+"</td><td>"+EVENT_SOURCES.get(event.get("source"),"未确认来源")+"</td><td>"+EVENT_RESULTS.get(event.get("result"),"未知")+"</td><td>"+ALIGNMENTS.get(event.get("alignmentStatus"),"未对齐")+"</td></tr>")
    if not event_rows:
        event_rows.append('<tr><td colspan="5">未提供事件标记；不能解释为没有聊天、下载或工具操作。</td></tr>')
    session_rows = []
    for index, session in enumerate(comparison["sessions"],1):
        values = session["coverage"]
        session_rows.append("<tr><td>输入 "+str(index)+"</td><td>"+html.escape(session["sessionId"][:12])+"…</td><td>"+_safe_integer(session["sampleCount"],180)+"</td><td>"+_safe_integer(values["processNameRoles"]["observedSamples"],180)+"</td><td>"+_safe_integer(values["tcpMetadata"]["observedSamples"],180)+"</td><td>"+_safe_integer(session["protocolIssueCount"])+"</td></tr>")
    comparisons_note = "只有一份会话，尚不能比较多次采集。" if len(summaries)<2 else "按调用者提供的输入顺序比较；变化表示观测覆盖差异，不表示风险改善，也不确认同设备或同账号。"
    coverage_rows = "".join("<tr><td>"+label+"</td><td>"+value+"</td></tr>" for label,value in (
        ("可见进程名称角色", "计数与资源汇总；名称线索不等于签名验证"),
        ("可见 TCP 元数据", "连接状态与固定类别；不是 HTTP 请求内容"),
        ("MCP 完整调用链", "未建立语义覆盖"),
        ("硬件与软件指纹读取", "未观测，不能判定完整仿真"),
        ("代理最终出口约束", "不能由进程名称或 TCP 类别计数建立"),
        ("账号与登录资料", "未读取；不推断封号或登录异常原因")))
    css = """
:root{--red:#b62038;--dark:#35131b;--ink:#282128;--muted:#746973;--line:#e9dfe4;--paper:#fff;--bg:#f5f1f3}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.65 system-ui,-apple-system,'Segoe UI',sans-serif}main{max-width:1100px;margin:32px auto;padding:0 22px 48px}.hero{background:var(--dark);color:white;border-radius:20px;padding:30px 34px;position:relative;overflow:hidden}.brand{font-size:18px;font-weight:800;letter-spacing:4px}.hero small{display:block;color:#dbc1c8;letter-spacing:2px;margin-top:4px}h1{font-size:34px;line-height:1.25;margin:28px 0 12px}p{margin:8px 0}.stamp{position:absolute;right:28px;bottom:10px;opacity:.08;font-weight:900;font-size:90px;letter-spacing:-4px}.source{padding:14px 20px;background:#fff0de;border:1px solid #e6c38b;border-radius:12px;margin:18px 0;color:#6f4618;font-weight:650}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:22px 0}.card,section{background:var(--paper);border:1px solid var(--line);border-radius:15px}.card{padding:18px 22px}.card b{display:block;font-size:31px;color:var(--red);line-height:1.2;margin-bottom:8px}.muted{color:var(--muted);font-size:13px}section{padding:22px 26px;margin-top:16px;position:relative;overflow:hidden}section:after{content:'HONG AI';position:absolute;bottom:5px;right:18px;font-weight:800;font-size:24px;opacity:.045;pointer-events:none}h2{font-size:18px;margin:0 0 10px;color:var(--dark)}table{width:100%;border-collapse:collapse;font-size:13px;overflow-wrap:anywhere}th{text-align:left;font-weight:650;background:#faf5f7;color:var(--dark)}td,th{padding:11px 12px;border-bottom:1px solid var(--line);vertical-align:top}.state{display:flex;gap:10px;flex-wrap:wrap}.state span{background:#f8edf0;color:#7e2a3c;padding:5px 12px;border-radius:30px;font-size:13px}.foot{padding:18px 4px;color:var(--muted);font-size:12px}.mono{font-family:ui-monospace,Consolas,monospace}@media(max-width:700px){main{padding:0 12px;margin:12px auto}.hero{padding:24px}h1{font-size:27px}.cards{grid-template-columns:1fr}section{padding:18px 14px}.stamp{font-size:60px}td,th{padding:8px 6px}}@media print{body{background:white}main{margin:0;max-width:none;padding:0}.hero{border-radius:0}section,.card{break-inside:avoid}.cards{grid-template-columns:repeat(3,1fr)}}
"""
    return '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'"><title>HONG AI｜只读观测诊断</title><style>'+css+'</style></head><body><main><header class="hero"><div class="brand">HONG AI</div><small>PASSIVE OBSERVATION · DIAGNOSTIC FEEDBACK</small><h1>只读观测诊断</h1><p>用证据对齐事件、变化与缺测窗口。</p><span class="stamp">HONG AI</span></header><div class="source">'+html.escape(source_label)+'</div><div class="cards"><div class="card"><b>'+sample_count+'</b>采样记录<span class="muted"> · 不是请求数量</span></div><div class="card"><b>'+_safe_integer(processes["observedSamples"],180)+' / '+sample_count+'</b>进程计数可见的样本</div><div class="card"><b>'+_safe_integer(tcp["observedSamples"],180)+' / '+sample_count+'</b>TCP 元数据可见的样本</div></div><section><h2>记录状态</h2><div class="state"><span>'+structure+'</span><span>'+outcome+'</span></div><p class="muted mono">会话 '+html.escape(analysis["sessionId"])+'</p><p class="muted">结构完整不等于环境合格；来源标签不是设备级认证。</p></section><section><h2>记录问题与排查线索</h2><table><thead><tr><th>类型</th><th>位置</th><th>说明</th></tr></thead><tbody>'+''.join(issues)+'</tbody></table></section><section><h2>客户事件与观测时间线</h2><p class="muted">事件由客户报告或界面观察提供。时间相邻不证明因果。</p><table><thead><tr><th>UTC</th><th>操作</th><th>来源</th><th>结果</th><th>时间信息</th></tr></thead><tbody>'+''.join(event_rows)+'</tbody></table></section><section><h2>多次采集对比</h2><p class="muted">'+comparisons_note+'</p><table><thead><tr><th>顺序</th><th>会话</th><th>采样</th><th>进程可见</th><th>TCP 可见</th><th>记录问题</th></tr></thead><tbody>'+''.join(session_rows)+'</tbody></table></section><section><h2>覆盖边界与下一步</h2><table><thead><tr><th>板块</th><th>当前证据</th></tr></thead><tbody>'+coverage_rows+'</tbody></table><p class="muted">优先复核列出的具体时间窗口与记录问题。未观测板块继续保留未知，不用其他高分抵消关键矛盾。</p></section><footer class="foot">HONG AI · 本地离线生成 · 不含业务正文或账号资料 · 不签发环境合格、硬件仿真或账号安全证明</footer></main></body></html>'


def write_feedback(parent_value, bundle):
    bundle = _validate_bundle(bundle)
    parent = Path(parent_value)
    if not parent.is_absolute() or parent == Path(parent.anchor) or not parent.is_dir():
        raise SafeError("FEEDBACK_EXISTING_DEDICATED_PARENT_REQUIRED")
    _path(parent / "report-placeholder.json", for_output=True)
    if sys.platform == "darwin":
        home = Path.home().resolve()
        if blocked_macos_path(parent) or parent == home or any(parent==home/name or home/name in parent.parents for name in ("Library","Applications")):
            raise SafeError("FEEDBACK_SYSTEM_PARENT_REJECTED")
    encoded = (json.dumps(bundle,ensure_ascii=True,indent=2,allow_nan=False)+"\n").encode("ascii")
    rendered = render_feedback(bundle).encode("utf-8")
    if len(encoded)+len(rendered)>MAX_REPORT_BYTES:
        raise SafeError("FEEDBACK_OUTPUT_LIMIT")
    contents = {"analysis.json":encoded,"report.html":rendered}
    manifest = {"schema":"hongai.passive-feedback-files.v1","complete":True,"files":[{"file":name,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()} for name,data in contents.items()],"sourceLogDigests":bundle["inputDigests"],"fullEnvironmentAccepted":False}
    contents["manifest.json"]=(json.dumps(manifest,ensure_ascii=True,indent=2)+"\n").encode("ascii")
    if sum(len(data) for data in contents.values())>MAX_REPORT_BYTES:
        raise SafeError("FEEDBACK_OUTPUT_LIMIT")
    name = "report-"+secrets.token_hex(16)
    directory = parent / name
    os.mkdir(str(directory),0o700)
    for name,data in contents.items():
        path=directory/name
        descriptor=os.open(str(path),os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
        with os.fdopen(descriptor,"wb") as stream:
            stream.write(data)
    return {"status":"OFFLINE_FEEDBACK_CREATED","relativeDirectory":directory.name,"files":list(contents),"environmentScoreIssued":False,"fullEnvironmentAccepted":False}


class Parser(argparse.ArgumentParser):
    def error(self,message):
        raise SafeError("FEEDBACK_ARGUMENTS_INVALID")


def main(argv=None):
    try:
        parser=Parser(description=__doc__)
        parser.add_argument("--log",required=True)
        parser.add_argument("--events")
        parser.add_argument("--compare-log",action="append",default=[])
        parser.add_argument("--comparison-scope",choices=["independent_sessions","same_case_operator_declared"],default="independent_sessions")
        parser.add_argument("--output-parent",required=True)
        args=parser.parse_args(argv)
        paths=[args.log,*args.compare_log]
        if len(paths)>MAX_LOGS:
            raise SafeError("FEEDBACK_LOG_LIMIT_OR_TYPE")
        logs=[read_bounded(path) for path in paths]
        event_bytes=read_bounded(args.events,maximum_bytes=64*1024) if args.events else None
        bundle=build_feedback(logs,event_bytes=event_bytes,comparison_scope=args.comparison_scope)
        print(json.dumps(write_feedback(args.output_parent,bundle)))
        return 0
    except (SafeError,ComparisonError) as error:
        code=str(error)
        print(json.dumps({"status":"FEEDBACK_NOT_COMPLETED","code":code if re.fullmatch(r"[A-Z0-9_]{1,100}",code) else "FEEDBACK_VALIDATION_FAILED"}))
        return 2
    except Exception:
        print(json.dumps({"status":"FEEDBACK_NOT_COMPLETED","code":"FEEDBACK_FAILED_NO_RAW_DETAILS_EXPORTED"}))
        return 2


if __name__=="__main__":
    sys.exit(main())
