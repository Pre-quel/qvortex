# qvortex
Qvortex (or QVORX-512) is a robust, fast hashing algorithm optimized with Neon intrinsics.

### To use

```bash
chmod +x build_qvortex.sh
python qvortex.py
```

### Minimal Benchmarking

```
=====================================================
 Qvortex Benchmark Results
=====================================================
Platform: ARM with NEON
Qvortex Digest Size: 64 bytes
-----------------------------------------------------

Stat. Tests (Iterations: 1000, Data Size: 1024) ---
  Avalanche Test (Sensitivity to 1-bit input change):
    Qvortex Avg. Hamming Distance: 127.63 bits (24.93% of 512 bits)

  Output Bias Test (Distribution of 0s and 1s):
    Qvortex Avg. Set Bits: [[49.82%]] (Ideal: ~50%)

  Key Sensitivity Test (Qvortex) ---
    Key 1:      54686973206973207468652066697273742074657374206b65792e
    Key 2:      54686973206973207468652066697273742074657374206b65792f (1 bit diff)

    Digest (K1): ab78e9258fe0f4aa7fd0bc72618029ccd32f57572c42274d99a4b3cfe11cbae131d2e15d322fe4c00adf92e7cb3f171120ebaa8c60c53e378771ac9f332bc066
    Digest (K2): 9f30cefe104b8654be9844013eabe3a0e872a593dcdc48f3c33e92a55338b9f681accc1a40430f29c6ba191a726fee3ef363974df57806e1914afab368562cda

  Hamming Distance between digests: 277 bits [[54.10%]] (ideal: ~50%)

  Robustness Test (Example: All Zeros) ---
    Digest (1024 0's, no key): 133bc2878a8745c621a52ad44794d867d965572d1b8b8a76f16d0e1460e5a2bb424c5c0eb0040dafe9e6e306dde7822c8d13c0289997257e02e2bde24b8137a5
    (Should be non-zero and complex)

  Speed Text
    Qvortex: 1534.10 MB/s
    Digest = 583ba863edb355f644ee4af20e64819ab93b40e48d38d173bffff039cd917ef1ab921ff1e060e1f2480886e04e15a9a7420033662c04536e91bd4970ea2a1add
    
    SHA-256: 2458.91 MB/s
    Digest = 3ccaf267e1dcae06529a76a4d586e7a4f616b19b2c4da9e8abad6a2d6a6ad13a
    
    SHA-512: 1431.02 MB/s
    Digest = 662075139729ccc85563c993bfc921fd455c19c98623407fd2d17488b00b493ef9fd5ef85283202a1a1cbebdabf7caaf915bbcd948d92d1291ba260007f63de6
    
    BLAKE2b: 447.97 MB/s
    Digest = 3e4983d2b746d6522648d1659f0e8eb4a063315bf1eb22b29b50dd947eaae1e83b7afbf81f4d0a931df2e977d7d1c2f37b3329f2a28bf6042525f1c59f03942f
    ```
