import json
import os
import sys
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

# Ensure root directory is on Python path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from phishing_checker import inspect_url, calculate_risk, risk_label


class handler(BaseHTTPRequestHandler):
    """Vercel Python Serverless HTTP Request Handler."""

    def _set_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(200)
        self._set_cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        # API query parameter: /api?url=...
        if "url" in params:
            target_url = params["url"][0]
            findings = inspect_url(target_url)
            score = calculate_risk(findings)
            category = risk_label(score)

            response_data = {
                "url": target_url,
                "findings": findings,
                "score": score,
                "category": category,
            }

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode("utf-8"))
            return

        # Serve static HTML if requested directly
        html_path = os.path.join(ROOT_DIR, "public", "index.html")
        if not os.path.exists(html_path):
            html_path = os.path.join(ROOT_DIR, "index.html")

        if os.path.exists(html_path):
            with open(html_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(content)
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(
            json.dumps({"status": "EWB Phishing Checker API ready"}).encode("utf-8")
        )

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        try:
            body = json.loads(post_data.decode("utf-8")) if post_data else {}
            target_url = body.get("url", "")
        except Exception:
            target_url = ""

        findings = inspect_url(target_url)
        score = calculate_risk(findings)
        category = risk_label(score)

        response_data = {
            "url": target_url,
            "findings": findings,
            "score": score,
            "category": category,
        }

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(response_data).encode("utf-8"))
