# Security policy

Chromifer is pre-release research and engineering software. Do not use it as a security boundary for a production browser.

Report vulnerabilities privately through GitHub's security advisory interface. Include the affected commit, a minimal reproduction, and the expected security property.

The project treats the following as security-sensitive:

- process and site-isolation policy;
- ownership crossing FFI boundaries;
- IPC message validation;
- sandbox broker interfaces;
- compatibility checks whose bypass could approve an unsafe migration.
