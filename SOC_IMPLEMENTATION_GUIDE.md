# SOC Pipeline Implementation (Wazuh 4.12+)

Tài liệu này mô tả cách triển khai pipeline triage cảnh báo Wazuh theo chuẩn SOC: thu thập không bỏ sót, chuẩn hóa đầy đủ, gắn nhãn FP, tương quan, chấm điểm heuristics + LLM, và gửi cảnh báo Telegram giàu ngữ cảnh. Mọi bước đều tránh “silent drop”.

## 1) Cấu hình chính (env)
- Ngưỡng lọc hai tầng: `MIN_LEVEL`, `MAX_LEVEL`, `INCLUDE_RULE_IDS`, `INCLUDE_RULE_ID_PREFIX`, và luôn lấy `ALWAYS_REEVALUATE_LEVEL_GTE`.
- Tương quan & dedup: `LOOKBACK_MINUTES_CORRELATION`, `DEDUP_WINDOW_MINUTES`.
- Nhịp kéo chỉ số: `WAZUH_POLL_INTERVAL_SEC`.

```61:68:src/common/config.py
SOC_MIN_LEVEL = get_env_int("MIN_LEVEL", 3)  # Minimum rule level to include (for custom rules)
SOC_MAX_LEVEL = get_env_int("MAX_LEVEL", 7)  # Maximum rule level for custom rule filtering
INCLUDE_RULE_IDS = [rid.strip() for rid in get_env("INCLUDE_RULE_IDS", "100100").split(",") if rid.strip()]  # Comma-separated list of rule IDs to include
INCLUDE_RULE_ID_PREFIX = get_env("INCLUDE_RULE_ID_PREFIX", "1001")  # Optional prefix for rule IDs
ALWAYS_REEVALUATE_LEVEL_GTE = get_env_int("ALWAYS_REEVALUATE_LEVEL_GTE", 7)  # Always include and re-evaluate alerts with level >= this
LOOKBACK_MINUTES_CORRELATION = get_env_int("LOOKBACK_MINUTES_CORRELATION", 30)  # Lookback window for correlation
DEDUP_WINDOW_MINUTES = get_env_int("DEDUP_WINDOW_MINUTES", 10)  # Deduplication window in minutes
WAZUH_POLL_INTERVAL_SEC = get_env_int("WAZUH_POLL_INTERVAL_SEC", 8)
```

## 2) Luồng tổng thể
1. Collector (_wazuh_client.py_): dựng truy vấn hai tầng, cân bằng agent, xử lý lookback động, chuẩn hóa AlertNormalized.
2. Correlation & FP labeling: correlate_alert + analyze_fp_risk → gắn nhãn `correlation`, `fp_filtering` (không loại bỏ).
3. Triage: heuristic + LLM (dynamic weighting, threat-level adjustment), boost theo tag/rule, dựng alert_card.
4. Notify: kiểm tra override critical, format Telegram SOC-grade, fallback không Markdown nếu lỗi parse.

## 3) Thu thập & lọc hai tầng (collector)
- Tầng 1: level trong [MIN_LEVEL..MAX_LEVEL] và rule id khớp list/prefix.
- Tầng 2: luôn lấy level >= ALWAYS_REEVALUATE_LEVEL_GTE.
- Không còn must_not cho agent 002; sort theo thời gian và agent để tránh dồn tải.

```627:666:src/collector/wazuh_client.py
# SOC-GRADE FILTERING: Two-tier approach
# Tier 1: Include alerts with level [SOC_MIN_LEVEL..SOC_MAX_LEVEL] AND rule.id in INCLUDE_RULE_IDS or starts with INCLUDE_RULE_ID_PREFIX
# Tier 2: Always include alerts with level >= ALWAYS_REEVALUATE_LEVEL_GTE (for AI re-evaluation)
filters: List[Dict[str, Any]] = [
    {
        "bool": {
            "should": [
                {
                    "bool": {
                        "must": [
                            {"range": {"rule.level": {"gte": SOC_MIN_LEVEL, "lte": SOC_MAX_LEVEL}}},
                            {"bool": {"should": rule_id_filters if rule_id_filters else [{"match_all": {}}], "minimum_should_match": 1 if rule_id_filters else 0}}
                        ]
                    }
                },
                {"range": {"rule.level": {"gte": ALWAYS_REEVALUATE_LEVEL_GTE}}}
            ],
            "minimum_should_match": 1
        }
    }
]
```

## 4) Chuẩn hóa AlertNormalized
- Giữ nguyên @timestamp (UTC + local), event_id, index, agent/rule/decoder/manager, location.
- Trích xuất network (src/dest ip/port, proto, app_proto, direction, flow stats), http, suricata_alert, tags, full_data, raw_json.
- Mặc định None/{} nếu thiếu để tránh crash; lưu toàn bộ raw cho bằng chứng và LLM.

```520:611:src/collector/wazuh_client.py
# ---- Extract additional SOC-required fields
event_id = raw.get("_id") or raw.get("id", "")
index = raw.get("_index", "")
manager = raw.get("manager", {})
decoder = raw.get("decoder", {})
location = raw.get("location", "")
full_data = data_section.copy() if data_section else {}
tags = []
...
return {
    "@timestamp": timestamp,
    "@timestamp_local": localized_ts or "",
    "event_id": event_id,
    "index": index,
    "manager": {"name": manager_name} if manager_name else {},
    "decoder": {"name": decoder_name} if decoder_name else {},
    "location": location,
    "agent": raw.get("agent", {}),
    "rule": raw.get("rule", {}),
    "src_ip": src_ip, "src_port": src_port,
    "dest_ip": dest_ip, "dest_port": dest_port,
    "proto": proto, "app_proto": app_proto,
    "flow": {...},
    "http": http_context if http_context else None,
    "suricata_alert": suricata_alert if suricata_alert else None,
    "full_data": full_data,
    "tags": tags,
    "raw": raw,
    "raw_json": raw_json,
}
```

## 5) Correlation & FP labeling
- Correlation: nhóm theo source/destination attack, signature, rule pattern trong window; trả về `is_correlated`, `group_size`, `first_seen`, `attack_pattern`.
- FP filtering: gắn nhãn FP nhưng không loại bỏ; xét internal IP + 404, benign signature/user-agent, lặp lại, cron pattern; xuất `fp_risk`, `fp_reason`, `noise_signals`.

```145:211:src/common/correlation.py
def correlate(self, alert: Dict[str, Any]) -> Dict[str, Any]:
    # Try different correlation types (priority order)
    correlation_types = ["source_attack", "destination_attack", "signature", "rule_pattern"]
    ...
    if group_key in self.alert_groups:
        ...
        return {"is_correlated": True, "group_key": group_key, "group_size": len(group), "first_seen": first_seen, "attack_pattern": metadata.get("attack_pattern"), "correlation_type": corr_type}
    ...
    self.group_metadata[group_key] = {"first_seen": timestamp, "last_seen": timestamp, "count": 1, "attack_pattern": attack_pattern, "correlation_type": corr_type}
```

```60:148:src/common/fp_filtering.py
def analyze_fp_risk(alert: Dict[str, Any], correlation_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if src_ip and _is_internal_ip(src_ip):
        if http_context and http_context.get("status") == "404":
            fp_reasons.append("Internal IP with HTTP 404 (likely internal scan)")
    ...
    if correlation_info and correlation_info.get("is_correlated"):
        group_size = correlation_info.get("group_size", 1)
        if group_size >= 10:
            fp_reasons.append(f"High repetition: {group_size} alerts from same source (possible noise)")
    ...
    return {"fp_risk": fp_risk, "fp_reason": fp_reasons, "allowlist_hit": allowlist_hit, "noise_signals": noise_signals}
```

```46:64:src/analyzer/triage.py
if CORRELATION_ENABLE:
    correlation_info = correlate_alert(alert)
    alert["correlation"] = correlation_info
...
fp_result = analyze_fp_risk(alert, correlation_info)
alert["fp_filtering"] = fp_result
```

## 6) Triage (heuristic + LLM)
- Heuristic score + LLM triage_llm; dynamic trọng số theo confidence; điều chỉnh theo threat_level.
- Boost confidence khi LLM nhận đúng SQLi/XSS/command injection; xây `alert_card` để hiển thị.

```245:270:src/analyzer/triage.py
if llm_confidence < 0.3:
    effective_h_weight = min(HEURISTIC_WEIGHT + 0.2, 0.9)
...
fused_score = (effective_h_weight * h_score) + (effective_l_weight * llm_confidence)
threat_adjustment = THREAT_LEVEL_ADJUSTMENTS.get(threat_level, 0.0)
final_score = max(0.0, min(1.0, final_score))
```

## 7) Thông báo Telegram SOC-grade
- Override critical: rule list, critical tags, high level, Suricata severity, attack tools, correlation campaign.
- Helper `_to_int` chuyển chuỗi số → int để tránh TypeError; dùng trong evidence/flow stats.
- Validate Markdown, fallback gửi plain text nếu parse lỗi để không mất cảnh báo.

```14:49:src/orchestrator/notify.py
def _to_int(value: Any) -> Optional[int]:
    """Best-effort convert a value to int (handles numeric strings from JSON)."""
    if isinstance(value, str):
        s = value.strip()
        if re.fullmatch(r"-?\d+", s):
            return int(s)
        return int(float(s))
    return None
```

```89:158:src/orchestrator/notify.py
def should_notify_critical_attack(alert: Dict[str, Any], triage: Dict[str, Any]) -> Tuple[bool, str]:
    if rule_id in CRITICAL_ATTACK_RULES: return True, ...
    if critical_tags_found: return True, ...
    if rule_level >= 12: return True, ...
    if suricata_severity >= 3: return True, ...
    if attack_tools in user_agent: return True, ...
    if correlation.get("group_size") >= 5: return True, ...
```

```189:214:src/orchestrator/notify.py
def _validate_telegram_message(message: str) -> Tuple[bool, Optional[str]]:
    MAX_LENGTH = 4096
    if len(message) > MAX_LENGTH:
        return False, f"Message too long: {len(message)} characters (max {MAX_LENGTH})"
    asterisk_count = message.count('*')
    if asterisk_count % 2 != 0:
        return False, f"Unbalanced asterisks: {asterisk_count} (should be even for proper Markdown formatting)"
```

## 8) Lưu ý vận hành
- Agent 001/002 xử lý đồng nhất (không must_not); cân bằng qua sort và truy vấn theo agent.
- Không drop cảnh báo: mọi FP chỉ được gắn nhãn `fp_risk`, vẫn qua LLM + Telegram.
- Đảm bảo TELEGRAM_BOT_TOKEN/CHAT_ID, WAZUH API/indexer, và OPENAI_API_KEY được đặt trước khi chạy.

## 9) Cách chạy nhanh
- Chạy pipeline: `python bin/run_pipeline.py` (đảm bảo env đã set và indexer/API reachable).
- Kiểm tra định dạng Telegram offline: `python bin/test_telegram_message_formatting.py`.

