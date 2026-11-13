# Lexblum — approved content distribution

Public storage for **explicitly approved and licensed** Lexblum content packages, separate from the private Android application source.

The repository is initialized, but **no content package has been published or approved through this repository yet**.

Release assets, once reviewed and independently signed, are expected to use `catalog.envelope` (optional graphics), `oga-catalog.envelope` (Oga_PL), `sdc-catalog.envelope` (Lexblum_SDC), and immutable SHA-256-named object files.

Technical fixtures, LAB world data, screenshots used as inspiration and provisional Oga scenes must not be published as official content. The Android consumer separately validates Ed25519 signatures, content hashes, compatibility and transactional installation.

The existing content delivery Worker stays unconfigured until an approved, complete, signed release is available.
