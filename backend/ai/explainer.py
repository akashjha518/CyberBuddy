import requests


OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
MODEL = "gemma3:4b"


def generate_explanation(analysis: dict) -> str | None:
    """
    Ask Gemma to explain an existing CyberBuddy analysis.

    The deterministic CyberBuddy analysis remains authoritative.
    Gemma only explains the supplied evidence.
    """

    prompt = f"""
You are CyberBuddy, a cybersecurity assistant for non-technical users.

Explain the following security analysis in simple, clear language.

IMPORTANT RULES:
- Do NOT change the provided risk level.
- Do NOT invent indicators.
- Do NOT claim something is definitely malicious unless the supplied evidence supports it.
- Explain why the detected indicators matter.
- Give practical and safe next steps.
- Never ask the user for passwords, OTPs, PINs, API keys, or other secrets.
- Keep the explanation concise.

CyberBuddy analysis:

Risk: {analysis.get("risk")}
Risk Score: {analysis.get("score")}
Possible Attack: {analysis.get("possible_attack")}
URLs: {analysis.get("urls")}
Indicators: {analysis.get("indicators")}
Recommended Actions: {analysis.get("recommended_actions")}
"""

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are a careful cybersecurity explanation "
                            "assistant. Only explain the evidence provided "
                            "by CyberBuddy."
                        ),
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ],
                "stream": False,
                "options": {
                    "temperature": 0.2,
                },
            },
            timeout=60,
        )

        response.raise_for_status()

        data = response.json()

        message = data.get("message", {})
        content = message.get("content")

        if not content:
            return None

        return content.strip()

    except requests.RequestException:
        return None
    except (ValueError, TypeError, AttributeError):
        return None