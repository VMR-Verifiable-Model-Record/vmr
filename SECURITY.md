# Security policy

## Scope

This covers the code in this repository: the record format library, the
offline verifier, the policy-pack evaluator, the engine-free record
builder, the `vmr` CLI, and the specifications and schemas under `specs/`.
It does not cover any proprietary component distributed separately (an
enforcement or runtime product, a hosted service, or a policy pack
maintained under contract).

Of particular interest: any input that a parser here (a record, a trust
store, a policy pack, a public key file, or a manifest) can be made to
crash, hang, or misreport on — since every one of these reads untrusted
bytes.

## Reporting a vulnerability

Please report security vulnerabilities through GitHub's private
vulnerability reporting for this repository (the Security tab, "Report a
vulnerability"), not through a public issue, a discussion, or Discord.

Do not email a report: this project does not use an email address for
security reports.

## What to expect

We read every report. We do not promise a specific response time here; if
one is published, it will be added to this file.
