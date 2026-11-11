# How to Contribute

Thanks for your interest in contributing to `Byte Fault Fuzzer`! Here are a few
general guidelines on contributing and reporting bugs that we ask you to review.
Following these guidelines helps to communicate that you respect the time of the
contributors managing and developing this open source project. In return, they
should reciprocate that respect in addressing your issue, assessing changes, and
helping you finalize your pull requests. In that spirit of mutual respect, we
may endeavor to review incoming issues and pull requests, and may
close any lingering issues or pull requests after inactivity.

Please note that all of your interactions in the project are subject to our
[Code of Conduct](CODE_OF_CONDUCT.md). This includes creation of issues or pull
requests, commenting on issues or pull requests, and extends to all interactions
in any real-time space e.g., Slack, Discord, etc.

## Reporting Issues

Before reporting a new issue, please ensure that the issue was not already
reported or fixed by searching through our [issues
list](https://github.com/cisco-talos/byte-fault-fuzzer/issues).

When creating a new issue, please be sure to include a **title and clear
description**, as much relevant information as possible, and, if possible, a
test case.

**If you discover a security bug, please do not report it in a public GitHub
issue or pull request. Instead, please see security procedures in
[SECURITY.md](SECURITY.md).**

## Sending Pull Requests

Before sending a new pull request, take a look at existing pull requests and
issues to see if the proposed change or fix has been discussed in the past, or
if the change was already implemented but not yet released.

We expect new pull requests to include tests for any affected behavior, and, as
we follow semantic versioning, we may reserve breaking changes until the next
major version release.

## Testing

Use Python 3.13 or newer and install `pytest`; install `rich` for complete
rendering and offline scenario coverage. Runtime Rich support is optional,
but not every Rich-dependent test automatically skips when it is absent.
Run these selections in separate processes from the project root:

```text
python -B -m pytest -q -p no:cacheprovider tests/unit tests/regression
python -B -m pytest -q -p no:cacheprovider tests/scenarios/offline
python -B -m pytest -q -p no:cacheprovider tests/scenarios/loopback
```

Offline scenarios deny real network and subprocess activity; loopback scenarios
allow only fixture-owned local endpoints and cannot share their process with
the offline guard. During development, select the tests affected by a change.
Native Windows terminal qualification uses the separate
[ConPTY driver](tests/scenarios/windows/conpty_driver.py), not ordinary pytest
discovery. See [usage](docs/USAGE.md) for feature-specific system prerequisites
and the Windows core-retrieval testing exclusion.

## Other Ways to Contribute

We welcome anyone that wants to contribute to `Byte Fault Fuzzer` to triage and
reply to open issues to help troubleshoot and fix existing bugs. Here is what
you can do:

- Help ensure that existing issues follows the recommendations from the
  _[Reporting Issues](#reporting-issues)_ section, providing feedback to the
  issue's author on what might be missing.
- Review and update the existing content of our
  [documentation](docs/USAGE.md) with up-to-date instructions and code samples.
- Review existing pull requests, and testing patches against real existing
  applications that use `Byte Fault Fuzzer`.
- Write a test, or add a missing test case to an existing test.

Thanks again for your interest on contributing to `Byte Fault Fuzzer`!
