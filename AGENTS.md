# Engineering guidelines

- **Progmatic Engineering (Pragmatic Engineering):** favor practical, testable solutions over theoretical machinery.
- **KISS:** use the simplest correct implementation, avoid unnecessary abstractions.
- **DRY:** share stable logic when useful, but keep independent experiments understandable and runnable on their own.
- **Labs live under `./labs/`:** each experiment has its own directory, README, scripts and test fixtures as needed. Never put lab code at repository root.
- **Minimal CI:** only fast syntax checks and deterministic unprivileged unit tests. Do not run root, network namespaces, live network, or expensive integration tests in GitHub Actions.
- **Main only:** make changes directly to `main`; do not create feature branches or pull requests for this repository.
- Keep all networking exercises isolated in namespaces. Never modify the host's default route, DNS, or firewall from a lab.
- Document setup, teardown, assumptions, observed results, and limitations; do not claim internet reachability from local namespace tests.
