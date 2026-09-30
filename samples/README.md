# Sample output (SYNTHETIC)

These files were produced by the offline demo:

```bash
python pivot.py --demo -o samples
```

Everything in them is **synthetic**: the seed `example-demo.test` and every
related name use reserved (`.test`, `.invalid`) or clearly fictional domains,
all IP addresses are in documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24, 2001:db8::/32), and "DemoCDN", "Demo Cloud Hosting" and
"Demo Registrar" do not exist. Nothing here describes real infrastructure.

The timestamp is pinned (2026-09-30T00:00:00+00:00), so the output is
reproducible. CI regenerates it and fails if it differs from these files. If
you change a rating rule or a fixture on purpose, regenerate with the command
above and commit the result.
