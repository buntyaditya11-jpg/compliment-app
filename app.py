import hashlib
import hmac
import os
import random
import time

from flask import Flask, jsonify, request

app = Flask(__name__)

# Slack > Basic Information > App Credentials > Signing Secret
SIGNING_SECRET = os.environ.get("SLACK_SIGNING_SECRET", "")

COMPLIMENTS = [
    "You make hard problems look easy.",
    "Your code reviews make everyone better.",
    "You have a great eye for detail.",
    "Your ideas keep this team moving forward.",
    "You're the kind of teammate everyone is glad to have.",
    "You explain things so clearly.",
    "Your curiosity is contagious.",
    "You turn chaos into a plan.",
]


def verify_slack_request(req) -> bool:
    """Check that the request really came from Slack."""
    timestamp = req.headers.get("X-Slack-Request-Timestamp", "")
    signature = req.headers.get("X-Slack-Signature", "")
    if not timestamp or not signature:
        return False
    # Reject replays older than 5 minutes
    if abs(time.time() - int(timestamp)) > 60 * 5:
        return False
    base = f"v0:{timestamp}:{req.get_data(as_text=True)}"
    expected = "v0=" + hmac.new(
        SIGNING_SECRET.encode(), base.encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


@app.route("/", methods=["GET"])
def health():
    return "Compliment app is running", 200


@app.route("/slack/compliment", methods=["POST"])
def compliment():
    if not verify_slack_request(request):
        return "Invalid signature", 401

    user_id = request.form.get("user_id", "someone")
    return jsonify(
        {
            "response_type": "in_channel",  # visible to the whole channel
            "text": f"<@{user_id}> says: {random.choice(COMPLIMENTS)}",
        }
    )


if __name__ == "__main__":
    app.run(port=int(os.environ.get("PORT", 3000)))
