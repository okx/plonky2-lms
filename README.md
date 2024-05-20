# LMS Hash-based Signature in Plonky2
LMS Signature Verification in Plonky2.

Fork from: https://github.com/Fraunhofer-AISEC/hbs-lms-rust

Compared to ECDSA, LMS:
- ✅ Verification in Plonky2 is fast
- ✅ Quantum-resistant
- ❌ Stateful, need to keep track of the used key pairs.
- ❌ Key generation and signing are slow.
- ❌ Signature size is large

## Limitations
DISCLAIMER: This is an unaudited prototype. DO NOT USE THIS IN PRODUCTION.
- Only support fixed LMS and LM-OTS parameters.
- Not support HSS (multi-tree variant of LMS).
- Not compatible with the reference implementation found here: [hash-sigs](https://github.com/cisco/hash-sigs).

## Benchmark
- Key generation, signing, and verification using SHA-256 and Poseidon in native Rust.
- Verification using Poseidon in Plonky2.

`cargo bench`

Result on MacBook M1Pro:
```
test tests::hasher_poseidon256_256    ... bench:       4,118 ns/iter (+/- 191)
test tests::hasher_sha256_256         ... bench:         750 ns/iter (+/- 18)
test tests::keygen_h5w2               ... bench:   6,249,095 ns/iter (+/- 274,502)
test tests::keygen_h5w2_h5w2          ... bench:   6,251,766 ns/iter (+/- 303,264)
test tests::keygen_with_aux_h5w2      ... bench:   6,260,225 ns/iter (+/- 130,199)
test tests::keygen_with_aux_h5w2_h5w2 ... bench:   6,254,754 ns/iter (+/- 132,943)
test tests::sign_h5w2                 ... bench:   6,195,979 ns/iter (+/- 99,432)
test tests::sign_h5w2_h5w2            ... bench:  18,625,629 ns/iter (+/- 416,090)
test tests::sign_with_aux_h10w2       ... bench:     275,868 ns/iter (+/- 29,399)
test tests::sign_with_aux_h15w2       ... bench:   3,336,850 ns/iter (+/- 33,665)
test tests::sign_with_aux_h5w2        ... bench:     157,445 ns/iter (+/- 2,248)
test tests::sign_with_aux_h5w2_h5w2   ... bench:  12,581,987 ns/iter (+/- 277,378)
test tests::verify                    ... bench:      95,502 ns/iter (+/- 1,650)
test tests::verify_reference          ... bench:     106,256 ns/iter (+/- 1,586)

test result: ok. 0 passed; 0 failed; 0 ignored; 14 measured; 0 filtered out; finished in 28.13s

     Running benches/signature.rs (target/release/deps/signature-10699a4b6742a2d5)
keygen_Sha256_256/H10W1 time:   [187.62 ms 188.11 ms 188.66 ms]
keygen_Sha256_256/H10W2 time:   [201.68 ms 202.44 ms 203.27 ms]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high mild
keygen_Sha256_256/H10W4 time:   [420.81 ms 421.75 ms 422.79 ms]
Benchmarking keygen_Sha256_256/H10W8: Warming up for 3.0000 s
Warning: Unable to complete 10 samples in 5.0s. You may wish to increase target time to 34.7s.
keygen_Sha256_256/H10W8 time:   [3.4556 s 3.4613 s 3.4685 s]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high severe

Benchmarking keygen_Poseidon256_256/H10W1: Warming up for 3.0000 s
Warning: Unable to complete 10 samples in 5.0s. You may wish to increase target time to 15.2s.
keygen_Poseidon256_256/H10W1
                        time:   [1.5115 s 1.5170 s 1.5225 s]
Benchmarking keygen_Poseidon256_256/H10W2: Warming up for 3.0000 s
Warning: Unable to complete 10 samples in 5.0s. You may wish to increase target time to 14.3s.
keygen_Poseidon256_256/H10W2
                        time:   [1.4346 s 1.4404 s 1.4462 s]
Benchmarking keygen_Poseidon256_256/H10W4: Warming up for 3.0000 s
Warning: Unable to complete 10 samples in 5.0s. You may wish to increase target time to 27.7s.
keygen_Poseidon256_256/H10W4
                        time:   [2.7472 s 2.7534 s 2.7617 s]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high severe
Benchmarking keygen_Poseidon256_256/H10W8: Warming up for 3.0000 s
Warning: Unable to complete 10 samples in 5.0s. You may wish to increase target time to 219.7s.
keygen_Poseidon256_256/H10W8
                        time:   [22.133 s 22.177 s 22.227 s]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high mild

sign_Sha256_256/H10W1   time:   [188.06 ms 189.70 ms 192.31 ms]
Found 2 outliers among 10 measurements (20.00%)
  2 (20.00%) high severe
sign_Sha256_256/H10W2   time:   [202.40 ms 204.06 ms 206.70 ms]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high severe
sign_Sha256_256/H10W4   time:   [420.97 ms 425.16 ms 432.24 ms]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high severe
Benchmarking sign_Sha256_256/H10W8: Warming up for 3.0000 s
Warning: Unable to complete 10 samples in 5.0s. You may wish to increase target time to 34.4s.
sign_Sha256_256/H10W8   time:   [3.4566 s 3.4687 s 3.4807 s]

Benchmarking sign_Poseidon256_256/H10W1: Warming up for 3.0000 s
Warning: Unable to complete 10 samples in 5.0s. You may wish to increase target time to 15.3s.
sign_Poseidon256_256/H10W1
                        time:   [1.5095 s 1.5145 s 1.5197 s]
Benchmarking sign_Poseidon256_256/H10W2: Warming up for 3.0000 s
Warning: Unable to complete 10 samples in 5.0s. You may wish to increase target time to 14.5s.
sign_Poseidon256_256/H10W2
                        time:   [1.4475 s 1.4582 s 1.4691 s]
Benchmarking sign_Poseidon256_256/H10W4: Warming up for 3.0000 s
Warning: Unable to complete 10 samples in 5.0s. You may wish to increase target time to 27.8s.
sign_Poseidon256_256/H10W4
                        time:   [2.7333 s 2.7406 s 2.7494 s]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high mild
Benchmarking sign_Poseidon256_256/H10W8: Warming up for 3.0000 s
Warning: Unable to complete 10 samples in 5.0s. You may wish to increase target time to 220.2s.
sign_Poseidon256_256/H10W8
                        time:   [22.040 s 22.151 s 22.272 s]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high mild

verify_Sha256_256/H10W1 time:   [96.179 µs 97.614 µs 99.252 µs]
verify_Sha256_256/H10W2 time:   [102.80 µs 105.43 µs 107.50 µs]
verify_Sha256_256/H10W4 time:   [198.24 µs 204.42 µs 212.72 µs]
verify_Sha256_256/H10W8 time:   [1.6346 ms 1.7087 ms 1.7838 ms]

verify_Poseidon256_256/H10W1
                        time:   [505.89 µs 524.66 µs 536.00 µs]
verify_Poseidon256_256/H10W2
                        time:   [598.88 µs 620.68 µs 639.02 µs]
verify_Poseidon256_256/H10W4
                        time:   [1.2799 ms 1.3584 ms 1.4488 ms]
verify_Poseidon256_256/H10W8
                        time:   [10.020 ms 10.801 ms 11.930 ms]

zk_verify_poseidon256_256/h10w1
                        time:   [179.69 ms 183.72 ms 188.14 ms]
```

## Naming conventions wrt to the IETF RFC
The naming in the RFC is done by using a single character.
To allow for a better understanding of the implementation, we have decided to use more descriptive designations.
The following table shows the mapping between the RFC and the library naming including a short description.

| RFC Naming | Library Naming       | Meaning                                                   |
|------------|----------------------|-----------------------------------------------------------|
| I          | lms_tree_identifier  | 16-byte random value to identify a single LMS tree        |
| q          | lms_leaf_identifier  | 4-byte value to identify all leafs in a single LMS tree   |
| C          | signature_randomizer | 32-byte random value added to every signature             |
| Q          | message_hash         | Output of hashed message together with I, q, D_MESG and C |
| y          | signature_data       | The actual data of the signature                          |
| p          | hash_chain_count     | The number of hash chains for a certain W parameter       |
| ls         | checksum_left_shift  | How many bits the checksum is shifted into the coef-value |
| n          | hash_function_output_size | Number of bytes that the lm_ots hash functions generates         |
| m          | hash_function_output_size | Number of bytes that the lms hash functions generates         |

## Licensing
This work is licensed under terms of the Apache-2.0 license (see [LICENSE file](LICENSE)).

### Contribution
Any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be licensed as above, without any additional terms or conditions.
