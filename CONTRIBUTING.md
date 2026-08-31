# Contributing to jCustos

## Before your first pull request: sign the CLA

jCustos is open core. The Community Edition in this repository is free software
under the EUPL 1.2; a separate Enterprise Edition funds the work. That model
only holds if the project may license contributions under both — so every
contribution needs the [Contributor Licence Agreement](CLA.md).

The grant is **non-exclusive**: you keep all rights in your own work. In return
the project commits to keeping your contribution permanently available under a
free licence. Obvious fixes (typos, formatting, a handful of lines without
creative choice) need no signature.

To sign, add this line to your pull request:

> I have read the jCustos CLA v1.0 and agree to it. Name, e-mail, date.

Contributing on behalf of an employer? Use `CLA-CORPORATE.md`.

## Working on the code

```bash
./mvnw clean install          # full reactor, 52 modules
./mvnw test -pl jCustos-core  # a single module
```

Two conventions worth knowing before you start:

- **No mocking frameworks.** Tests run against real implementations; the build
  enforces this and fails on Mockito, EasyMock or PowerMock. Where a real
  implementation is awkward, the fixtures in `jCustos-test` usually help.
- **The edition boundary is a test.** `CommunityDoesNotReferenceEnterpriseTest`
  fails if community code references the enterprise edition. Nothing here may
  depend on it.

Source, comments, log and exception messages are American English. User-facing
strings follow the project's i18n resources.

## Reporting security issues

Please do not open a public issue for a vulnerability. Mail
sven.ruppert@gmail.com directly.
