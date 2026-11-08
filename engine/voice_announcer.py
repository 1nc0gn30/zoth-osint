"""
Voice Announcer for Zoth-OSINT — Synthesizes tactical audio debriefs via Kokoro ONNX (:9394).
Engineered by Neal Frazier Tech (@1nc0gn30) • NullAI Platform
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from typing import Optional

logger = logging.getLogger("zoth_osint.voice")

KOKORO_URL = os.environ.get("KOKORO_URL", "http://127.0.0.1:9394/speak")
DEFAULT_VOICE = os.environ.get("KOKORO_VOICE", "af_heart")


def is_kokoro_online(timeout: float = 0.5) -> bool:
    """Check if the local Kokoro ONNX daemon is ready."""
    try:
        req = urllib.request.Request("http://127.0.0.1:9394/health", method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def synthesize_and_play(text: str, voice: str = DEFAULT_VOICE, blocking: bool = False) -> bool:
    """Synthesizes text via Kokoro ONNX and plays it on the host via PipeWire/PulseAudio."""
    if not text.strip():
        return False

    clean_text = " ".join(text.split())[:350]

    payload = json.dumps({
        "text": clean_text,
        "voice": voice,
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            KOKORO_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8.0) as resp:
            audio_bytes = resp.read()

        if not audio_bytes:
            return False

        # Find available player (pw-play, paplay, or aplay)
        player = shutil.which("pw-play") or shutil.which("paplay") or shutil.which("aplay")
        if not player:
            return False

        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tf:
            tf.write(audio_bytes)
            tf_path = tf.name

        cmd = [player, tf_path]
        if blocking:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            try:
                os.unlink(tf_path)
            except OSError:
                pass
        else:
            # Play in background and cleanup file afterwards
            clean_cmd = f"{player} '{tf_path}' && rm -f '{tf_path}'"
            subprocess.Popen(clean_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        return True

    except Exception as err:
        logger.debug("Voice synthesis skipped: %s", err)
        return False


def announce_scan_result(target: str, target_type: str, finding_count: int, risk_score: Optional[int] = None) -> bool:
    """Compose and announce an executive audio brief of scan completion."""
    risk_phrase = f"with risk score {risk_score} out of 100." if risk_score is not None else "scan complete."
    summary = (
        f"Reconnaissance complete for target {target}, classified as {target_type}. "
        f"Identified {finding_count} tactical findings, {risk_phrase}"
    )
    return synthesize_and_play(summary)
