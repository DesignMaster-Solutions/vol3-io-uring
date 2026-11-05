# Submission package: Volatility Plugin Contest 2026

Status: READY, NOT SENT. Sending the e-mail and signing the Individual Contributor License
Agreement (ICLA) are for the author (Alan De Bortolo) to do.

Rules: https://volatilityfoundation.org/volatility-plugin-contest/ (deadline 31 December 2026;
earlier submissions are preferred when entries are similar).

## Checklist before sending

- [ ] ICLA signed and attached (requested from the Volatility Foundation)
- [ ] `git pull` and `python -m pytest tests` green on both samples (and `tests/mutants/run_mutants.sh` all KILLED)
- [ ] Release v0.1.0 assets downloadable and sha256 equal to the README table
- [ ] Send `email.txt` to contest@volatilityfoundation.org (the info@ account in Spark adds its own signature: send with `--no-signature` or drop the closing lines of the txt)
- [ ] Decide on an AI-assistance note (the ICLA states copyright ownership; other deliveries say "Built with AI coding assistance; I reviewed and tested it.")

## What goes in (contest requirements -> where)

| Requirement | Where |
|---|---|
| Source code | https://github.com/DesignMaster-Solutions/vol3-io-uring (`plugins/linux/io_uring.py`) and the zip of the v0.1.0 tag |
| Memory sample | Release v0.1.0: `io-uring-6.1.0-54-cloud-amd64.elf.zst`, `io-uring-6.12.115.deb13.1-cloud-amd64.elf.zst` (GitHub turns `+` into `.` in asset names) (+ ISF `.json.xz`), rebuildable with `sample/build_sample.sh` |
| How to use | README.md ("Install and run") and docs/usage.md (real output) |
| Write-up (why it is useful) | docs/writeup.md |
| Signed ICLA | attachment (author) |
