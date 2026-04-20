def detect_log_clear(events):
    alerts = []
    for event in events:
        if event.get("event_id") == 1102:
            alerts.append(f"[ЖОҒАРЫ] Оқиға журналы тазартылды: {event.get('timestamp')}")
    return alerts
