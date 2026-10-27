# Phishing URL Awareness Checker

A beginner-friendly, defensive cybersecurity mini-project that checks visible URL patterns. It does **not** open URLs, contact websites, or prove that a link is safe.

## Requirements
- Python 3.10+ recommended (standard library only)
- VS Code (optional)

## Run in VS Code
1. Open this project folder in VS Code.
2. Choose **Terminal → New Terminal**.
3. Confirm the terminal path ends in `phishing-url-awareness`.
4. Run:
   - Windows: `python phishing_checker.py`
   - macOS/Linux: `python3 phishing_checker.py`
5. Enter a sample URL when prompted.

Try:
`http://192.0.2.10/account`

Then try:
`https://www.example.com/login`

## Run all five sample tests
From the project root:

Windows:
```powershell
python -c "from phishing_checker import inspect_url; samples=['https://www.example.com/login','http://192.0.2.10/account','http://example.com@sample.invalid/login','https://a.b.c.d.e.example.invalid/path','https://xn--example.invalid/']; [print(f'{i}. {u}\\n   ' + ' | '.join(inspect_url(u))) for i,u in enumerate(samples,1)]"
```

macOS/Linux:
```bash
python3 -c "from phishing_checker import inspect_url; samples=['https://www.example.com/login','http://192.0.2.10/account','http://example.com@sample.invalid/login','https://a.b.c.d.e.example.invalid/path','https://xn--example.invalid/']; [print(f'{i}. {u}\\n   ' + ' | '.join(inspect_url(u))) for i,u in enumerate(samples,1)]"
```

Record your own Python version, operating system, and date in `tests/test_samples.md`. The actual-result examples are the expected results from this implementation; rerun the tests on your computer before submitting.

## Project files
- `phishing_checker.py` — URL text checks and command-line program
- `tests/test_samples.md` — five-sample test log
- `requirements.txt` — confirms no extra packages are required
