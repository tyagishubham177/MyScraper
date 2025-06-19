# Fuzzing

This folder contains fuzzing targets for the project.

Currently it includes a Python fuzzer for the email formatting utilities in `scripts/notifications.py` built using [Atheris](https://github.com/google/atheris).

This fuzzer currently requires **Python 3.11** because the latest
`atheris` release does not compile on Python 3.12 yet. To run the
fuzzer locally:

```bash
pip install atheris
python fuzz/fuzz_notifications.py -runs=100
```

The accompanying GitHub Actions workflow `fuzz.yml` executes this fuzzer on every pull request.
