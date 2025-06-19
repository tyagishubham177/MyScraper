# Fuzzing

This folder contains fuzzing targets for the project.

Currently it includes Python fuzzers for key modules in the `scripts/` package:

- `fuzz_notifications.py` exercises the email formatting utilities in `scripts/notifications.py`.
- `fuzz_config.py` reloads configuration with randomized environment variables.
- `fuzz_check_stock.py` targets helper functions in `scripts/check_stock.py`.
- `fuzz_scraper.py` simulates the Playwright scraper in `scripts/scraper.py`.

These fuzzers require **Python 3.11** because the latest `atheris` release does not compile on Python 3.12 yet. To run them locally:

```bash
pip install atheris
python fuzz/fuzz_notifications.py -runs=100
python fuzz/fuzz_check_stock.py -runs=100
python fuzz/fuzz_config.py -runs=100
python fuzz/fuzz_scraper.py -runs=100
```

The accompanying GitHub Actions workflow `fuzz.yml` executes these fuzzers on every pull request.
