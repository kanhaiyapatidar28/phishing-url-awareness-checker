"""
Vercel entrypoint compatibility wrapper for EWB Phishing URL Awareness Checker.
Directs Vercel's Python runtime to the serverless handler in api/index.py.
"""

from api.index import handler

app = handler
