# Fuzzing

This folder contains fuzzing targets for the project.

Currently it includes a Python fuzzer for the email formatting utilities in `scripts/notifications.py` built using [Atheris](https://github.com/google/atheris).

To run the fuzzer locally:

```bash
pip install atheris
python fuzz/fuzz_notifications.py -runs=100
```

The accompanying GitHub Actions workflow `fuzz.yml` executes this fuzzer on every pull request.
