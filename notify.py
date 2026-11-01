"""Fallback phone alert through ntfy.sh (plain HTTPS, works from cloud sessions)."""
import os
import urllib.request


def ntfy(message, priority="urgent"):
    topic = os.environ.get("NTFY_TOPIC")
    if not topic:
        raise RuntimeError("NTFY_TOPIC is not set")
    server = os.environ.get("NTFY_SERVER", "https://ntfy.sh").rstrip("/")
    req = urllib.request.Request(
        f"{server}/{topic}",
        data=message.encode("utf-8"),
        headers={"Title": "Claude", "Priority": priority, "Tags": "telephone_receiver"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        r.read()
    return f"sent ntfy alert to topic {topic}"


def alert(message, ring_seconds=30):
    """Ring over SIP; if that fails, send an ntfy push instead."""
    from sip_call import call_from_env
    try:
        return call_from_env(message, ring_seconds)
    except Exception as e:
        sip_error = e
    try:
        return f"SIP call failed ({sip_error}); {ntfy(message)}"
    except Exception as e:
        raise RuntimeError(f"SIP call failed ({sip_error}); ntfy failed ({e})")
