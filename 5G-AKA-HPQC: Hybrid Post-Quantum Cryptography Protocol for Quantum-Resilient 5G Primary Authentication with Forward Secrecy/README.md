# 5G-AKA-HPQC ProVerif Models

This directory provides the ProVerif models associated with the paper **“5G-AKA-HPQC: Hybrid Postquantum Cryptography Protocol for Quantum-Resilient 5G Primary Authentication With Forward Secrecy.”** This note clarifies how the four component-compromise scenarios are modeled and how their results should be interpreted. It does not change the protocol, security requirements, or formal-analysis methodology presented in the paper.

## 1. Verification scope

The paper defines seven security requirements through queries Q0–Q6 and additionally evaluates the HPQC construction under four cryptographic-component conditions. The four scenario files are boundary tests of the hybrid construction. They must not be read as a claim that every security property remains true after every underlying component has been compromised.

All four files use the same role-separated protocol process:

- `UE`: generates SUCI, verifies AUTN/MAC and SQN, derives `RES*`, `K_AUSF`, and `K_SEAF`;
- `SN`: relays SUCI, verifies `HRES* = HXRES*`, forwards `RES*`, and installs the anchor key only after HN confirmation;
- `HN`: deconceals and verifies SUCI, creates the authentication vector, verifies `RES*`, and releases SUPI and `K_SEAF`;
- `radio`: a public channel controlled by a Dolev–Yao adversary;
- `core`: a private channel representing the protected core-network path assumed by the model;
- replication `!`: an unbounded number of UE, SN, and HN process instances;
- `phase 1`: post-session disclosure of the HN's long-term X-Wing private components and the subscriber long-term key `K`, used to test forward secrecy of a completed session.

The message flow, validation conditions, and events are shared across S1–S4. The four component-compromise scenarios are decisive for Q1–Q3. The Q4 and Q5 correspondence queries are retained in all four files. The more expensive nested Q6 correspondence is solved in S1 and S2 and is not repeated in S3 and S4 because it is independent of which HN-to-UE hybrid component is disclosed.

## 2. Scenario definitions

| File | Additional session-component disclosure | Intended interpretation |
|---|---|---|
| `(S1-Usually)5G-AKA-HPQC.pv` | none | Both X-Wing components operate normally. The later `phase 1` disclosure tests PFS after long-term-key compromise. |
| `(S2-ECDH breech)5G-AKA-HPQC.pv` | `sshn_dh` | The X25519/ECDH component of the HN-to-UE hybrid exchange is compromised. The ML-KEM component remains secret. |
| `(S3-PQC breech)5G-AKA-HPQC.pv` | `sshn_pq` | The ML-KEM component of the HN-to-UE hybrid exchange is compromised. The X25519/ECDH component remains secret. |
| `(S4-All breech)5G-AKA-HPQC.pv` | `(sshn_pq, sshn_dh)` | Both components are compromised. This is the expected failure-boundary case for hybrid secrecy, not an all-properties-secure case. |

The filenames retain the original word `breech` for link and repository compatibility; the intended English term is `breach`.

## 3. Hybrid-security interpretation

The HN-to-UE hybrid secret is represented abstractly as

```text
ss_hybrid = XWingCombine(ss_pq, ss_dh, ciphertexts, public_keys, context)
PHK       = KDF(label_phk, ss_ue, ss_hybrid)
```

Under the robust-hybrid-combiner assumption, secrecy is retained when at least one independent component remains unknown to the adversary:

| ML-KEM component | X25519/ECDH component | Expected hybrid-secret status |
|---|---|---|
| secure | secure | secure |
| secure | compromised | secure |
| compromised | secure | secure |
| compromised | compromised | not guaranteed |

Accordingly, S1–S3 test the security benefit intended by the HPQC construction. S4 records the construction's explicit security boundary. Once both component secrets are disclosed, the robust-combiner assumption no longer supplies secrecy. When the post-session `phase 1` disclosure also releases `K`, ProVerif no longer proves secrecy of the completed-session `PHK`, `K_AUSF`, and `K_SEAF` witnesses. This expected `cannot be proved` result marks the modeled boundary; it is not a claim that the protocol remains secure in S4, nor is it a ProVerif execution error.

## 4. Relationship between Q0–Q6 and the scenario files

### Q0 — SUPI concealment

Q0 checks whether the adversary can derive the subscriber identity. The S1–S4 phase models deliberately disclose the HN's long-term private components after session completion. These scenario files therefore do **not** use Q0 to claim long-term-key-compromise-resistant SUCI confidentiality. The component-compromise experiment is primarily intended to evaluate the completed-session key material through Q1–Q3.

### Q1–Q3 — secure key exchange and PFS

The secrecy witnesses corresponding to the UE, SN, and HN copies of the derived key material test whether the adversary can derive the completed-session `PHK`, `K_AUSF`, or `K_SEAF` material after the modeled disclosures.

- S1: expected to remain secret after post-session long-term-key disclosure because both fresh hybrid components remain protected;
- S2: expected to remain secret because the ML-KEM component remains protected;
- S3: expected to remain secret because the X25519/ECDH component remains protected;
- S4: expected to be derivable after both hybrid components and the modeled long-term keys are disclosed.

Thus, the intended HPQC claim is **at-least-one-component security**, not security after simultaneous compromise of every component.

### Q4 — SUCI origin and replay behavior

The non-injective correspondence checks whether an accepted SUCI has a legitimate UE creation event. The injective correspondence additionally requires each acceptance to correspond to a unique creation event.

```text
event(accept_suci(...)) ==> event(begin_suci(...))
inj-event(accept_suci(...)) ==> inj-event(begin_suci(...))
```

An injective result of `false` together with a non-injective result of `true` means that the SUCI has a legitimate origin but can be replayed. This corresponds to the paper's “partially true” availability assessment; it does not mean that the attacker forged a new valid SUCI.

### Q5 — UE–HN authentication

Q5 checks the AUTN/MAC direction through correspondence between the UE acceptance event and the HN generation event. Both injective and non-injective forms are retained to distinguish unique-session authentication from basic message origin.

### Q6 — SN verification and anchor-key release

Q6 checks that SN anchor-key installation is preceded by the matching UE response, SN `HRES*` verification, and HN `RES*` acceptance. This is a scenario-independent authentication property. It is verified in S1 and remains present in S2; it is not re-solved in S3 and S4, whose purpose is the Q1–Q3 component-compromise boundary. This separation prevents an unrelated, computationally expensive nested correspondence query from obscuring the decisive secrecy result.

## 5. Reading ProVerif results

For a secrecy query, ProVerif prints results in the following form:

```text
RESULT not attacker(secret_witness[]) is true.
```

This means the secrecy property is proved in the symbolic model. A result of `false` means that ProVerif found a derivation by which the adversary can obtain the witness.

Reachability witnesses are intentionally public only after the honest protocol path completes. Therefore,

```text
RESULT not attacker(reach_ue[]) is false.
```

is a successful reachability sanity check, not a confidentiality failure. It confirms that the corresponding honest completion point is reachable.

For correspondence queries:

- `event(A) ==> event(B) is true` establishes non-injective origin/authentication;
- `inj-event(A) ==> inj-event(B) is true` additionally establishes one-to-one freshness;
- non-injective `true` with injective `false` indicates replay or repeated acceptance rather than origin forgery.

## 6. Expected scenario-level interpretation

| Property family | S1 | S2 | S3 | S4 |
|---|---:|---:|---:|---:|
| Q1–Q3: hybrid-secret/key secrecy after modeled disclosures | PROVED | PROVED | PROVED | NOT PROVED (expected boundary) |
| Q4: SUCI non-injective origin | PASS | PASS | PASS | PASS |
| Q4: SUCI injective freshness | expected FAIL | expected FAIL | expected FAIL | expected FAIL |
| Q5: AUTN/MAC correspondence | PASS | PASS | PASS | PASS unless the authentication primitive itself is additionally compromised |
| Q6: `RES*`/anchor-key correspondence | PROVED | PROVED; not needed for component comparison | not repeated | not repeated |

The paper's aggregate security-requirement summary is not a per-scenario assertion that all queries must return `true` in S4. The four files refine the analysis by showing both the resilience region of the hybrid construction and its simultaneous-compromise boundary.

## 7. Reproduction

The models were checked with ProVerif 2.05. The table above records the actual scenario-level interpretation of those runs; `NOT PROVED` is used deliberately instead of presenting an inconclusive proof result as a theorem of insecurity. Run a scenario directly as follows:

```powershell
C:\ProVerif\proverif.exe ".\(S1-Usually)5G-AKA-HPQC.pv"
C:\ProVerif\proverif.exe ".\(S2-ECDH breech)5G-AKA-HPQC.pv"
C:\ProVerif\proverif.exe ".\(S3-PQC breech)5G-AKA-HPQC.pv"
C:\ProVerif\proverif.exe ".\(S4-All breech)5G-AKA-HPQC.pv"
```

The 64-bit executable is recommended for the unbounded models. For the Q1–Q3 component comparison, the role processes, validation conditions, event parameters, and secrecy queries remain identical; within the protocol process, the only scenario-specific change is the relevant disclosure output. The additional Q6 query block in S1 and S2 does not alter that Q1–Q3 experiment. Scenario-independent correspondence properties may be verified once in the general model or in a dedicated property model.
