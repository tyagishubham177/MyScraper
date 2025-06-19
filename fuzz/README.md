# Fuzzing

This folder contains fuzzing targets for the project.

The fuzzers are built using [Atheris](https://github.com/google/atheris) and
currently require **Python 3.11** because the latest release does not compile on
Python 3.12 yet.

Available fuzzers:

- `fuzz_notifications.py` – exercises the email formatting utilities in
  `scripts/notifications.py`.
- `fuzz_check_stock.py` – fuzzes helper functions like `within_time_window` and
  `filter_active_subs` from `scripts/check_stock.py`.
- `fuzz_config.py` – reloads the configuration module with random environment
  variables.
- `fuzz_scraper.py` – feeds randomized input to the internal scraping logic
  without launching a real browser.

To run a fuzzer locally:

```bash
pip install atheris
python fuzz/<fuzzer_name>.py -runs=100
```

The accompanying GitHub Actions workflow `fuzz.yml` executes all fuzzers on every
pull request.
