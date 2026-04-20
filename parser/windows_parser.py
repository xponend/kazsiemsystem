import re

def parse_log_line(line):
    event = {}

    # Уақыт белгісін алу
    ts = re.search(r"Time:\s*(.*)", line)
    if ts:
        event["timestamp"] = ts.group(1)

    # Оқиға ID алу
    eid = re.search(r"EventID:\s*(\d+)", line)
    if eid:
        event["event_id"] = int(eid.group(1))

    # Пайдаланушыны алу
    user = re.search(r"User:\s*(.*)", line)
    if user:
        event["user"] = user.group(1)

    # IP мекенжайын алу
    ip = re.search(r"IP:\s*(.*)", line)
    if ip:
        event["ip"] = ip.group(1)

    # Пәрменді алу
    cmd = re.search(r"Command:\s*(.*)", line)
    if cmd:
        event["command"] = cmd.group(1)

    return event
