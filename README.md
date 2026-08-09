# Distributed Network Security Monitoring & Mathematical Threat Modeling

A bare-metal Network Security Monitoring (NSM) testbed and mathematical threat detection framework implemented in Fortran 90 to isolate sub-threshold, distributed data exfiltration signals from complex background noise without relying on traditional signature matching.

## Architecture & Detection Pipeline

- **Bare-Metal Telemetry Cluster:** Segregated 7-node Raspberry Pi 5 / AMD Ryzen compute environment with dedicated NFS storage fabric and L3 Gigabit VLAN segmentation[cite: 1].
- **Parametric Baseline Synthesis:** Fortran 90 baseline engine incorporating Gaussian-smoothed daily profiles, $1/f$ pink noise temporal drift, Box-Muller Gaussian jitter, and Poisson/Log-Normal human workflow models[cite: 1].
- **Layered Mathematical Threat Detection:**
  - *Localized Attack-Likelihood Model:* Hyperbolic tangent ($\tanh$) anomaly mappings across time, magnitude, persistence, and directionality metrics[cite: 1].
  - *Lagged Cross-Correlation Engine:* Evaluates multi-sensor temporal lag matrices and triple-node coordination consistency ($F_{\text{coord}}$) to uncover structured exfiltration (including non-uniform Fibonacci delays)[cite: 1].
  - *Morlet Wavelet-Coherence Operator:* Scale-collapsed continuous wavelet transforms ($C_{\text{all}}(t)$) that isolate adversarial "liquid-skeleton" exfiltration signatures[cite: 1].
- **Telemetry Replay & Traffic Control:** Replays synthetic baseline and threat traffic via persistent TCP streams (`nc`) rate-shaped through Linux Hierarchical Token Bucket (`tc`/HTB) traffic control[cite: 1].

## Repository Structure

- `src/fortran/replay_detection/`: Fortran 90 telemetry replay engines, baseline models, and configuration files[cite: 1]
- `src/fortran/synthetic_detection/`: Fortran 90 mathematical detection routines and threat configuration scripts[cite: 1]
- `docs/`: Technical research paper PDF and mathematical validation plots[cite: 1]

## Hardware & Environment Setup

- **Compute Fabric:** 4x Raspberry Pi 5 sensor nodes (8 GB LPDDR5), 1x RP5 collector node, 1x RP5 traffic injector, 1x RP5 dedicated NFS storage node, 1x AMD Ryzen 7 7700X management host[cite: 1].
- **Network & OS:** PiOS (Linux kernel 6.12), Ubuntu 25.10, L3 Managed Gigabit Switch, Fortran 90 (`gfortran`)[cite: 1].

## Experimental Validation Results

- **Fibonacci-Lag Exfiltration:** Successfully detected distributed exfiltration across LOW localized likelihood scores ($P_{\text{sys}} = 0.4185$) with $F_{\text{coord}} = 1.000$ coordination alarms[cite: 1].
- **Mixed-Signal Exfiltration:** Identified coordinated timing across geometrically mismatched waveforms (parabolic, exponential, sinusoidal, stochastic) where point-in-time detectors showed NO indication ($P_{\text{sys}} = 0.2379$)[cite: 1].
- **Wavelet-Coherence Validation:** Extracted persistent multi-scale coherence ($C_{\text{all}} = 0.940$) from adversarial liquid-skeleton signatures that completely bypassed localized and fixed-lag correlation detectors[cite: 1].
