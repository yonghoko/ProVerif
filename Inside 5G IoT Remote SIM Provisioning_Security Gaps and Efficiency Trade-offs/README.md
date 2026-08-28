# ProVerif Artifact: Inside 5G IoT Remote SIM Provisioning

This directory contains the ProVerif models released with the article
"Inside 5G IoT Remote SIM Provisioning: Security Gaps and Efficiency
Trade-offs."

## Artifact consistency note

The filenames and directory structure are retained exactly as released with
the published article. Some S1-S7 models intentionally weaken a baseline
assumption, expose a secret, omit a security gate, or otherwise represent
adversarial degradation scenarios. Therefore, scenario filenames should be
interpreted together with the explicit modeling assumptions documented below
and should not, by themselves, be read as claims of direct vulnerabilities in
the standardized GSMA IoT RSP procedure.

The extended S1-S7 models are adversarial robustness analyses rather than
uniform claims of direct flaws in the standardized protocol. Several scenarios
intentionally weaken binding, authorization, channel, state-consistency, or
key-custody assumptions to determine whether baseline security correspondences
remain valid. Consequently, a failed query must be interpreted together with
the explicit scenario assumption that caused the failure.

Across the modeled degradation scenarios, the observed property violations
primarily arise from weakened binding, authorization, state-consistency,
channel, or key-custody assumptions rather than from direct compromise of the
modeled profile-encryption primitive.

## Reproduction

The models were checked with ProVerif 2.05 on August 28, 2026. From this
directory, run each model as follows:

```text
proverif "S0_PA_RSP_common-mAUTH.pv"
proverif "S0_PB_IoT RSP_honesty.pv"
proverif "S1_TLS_KEYLEAK.pv"
proverif "S2_SESSIONSPLICING.pv"
proverif "S3_UNAUTH_TRIGGER.pv"
proverif "S4_RACE_REPLAY.pv"
proverif "S5_MISBINDING.pv"
proverif "S6_FAKE_COMPLETION.pv"
proverif "S7_PFS FAILURE.pv"
```

All nine files parse and terminate successfully with ProVerif 2.05. Raw output
files are not committed; the observed results are summarized below and can be
regenerated with the commands above.

## Phase boundary

The artifact uses two separate baseline models:

- `S0_PA_RSP_common-mAUTH.pv` verifies Phase-A mutual authentication.
- `S0_PB_IoT RSP_honesty.pv` verifies Phase-B binding, profile download,
  ordering, and secrecy under the assumption that mutual authentication has
  already completed.

These two files do not constitute a monolithic compositional proof that links
the exact Phase-A authenticated session identifier to every Phase-B
transaction. In S1, S4, S6, and S7, the private constructor
`authContext(dev,Q_U)` makes the assumed Phase-A handoff explicit by preventing
an attacker-selected `Q_U` from being accepted as the preauthenticated eUICC
context. This constructor is a symbolic capability, not an exact standardized
message and not a proof of cross-phase composition.

Without this explicit precondition, a public Phase-B request channel lets the
attacker submit its own `Q_U`, derive the resulting ECDH keys, and decrypt the
BPP. That trace concerns a missing phase-handoff assumption rather than the
scenario-specific property under study.

## Model classification and results

| ID | File | Model Type | Baseline / Degraded | Explicit Modification or Compromise | Property Tested | ProVerif 2.05 Result | Interpretation Boundary |
|---|---|---|---|---|---|---|---|
| S0-A | `S0_PA_RSP_common-mAUTH.pv` | Mutual-authentication baseline | Baseline | Private relay links; prior package and activation-code provisioning assumed | Three injective authentication correspondences | All TRUE | Phase A only; no Phase-A-to-Phase-B composition claim |
| S0-B | `S0_PB_IoT RSP_honesty.pv` | Binding/download baseline | Baseline | Mutual authentication assumed complete; private channels | Binding, ordering, profile secrecy | All TRUE | Assumes rather than proves the Phase-A handoff |
| S1 | `S1_TLS_KEYLEAK.pv` | Network/channel exposure stress test | Degraded transport | Both IPA-facing channels are public; no key is leaked; authenticated `Q_U` context retained | Binding, ordering, profile secrecy | All TRUE | Applies to the modeled transport exposure and ECDH profile protection |
| S2 | `S2_SESSIONSPLICING.pv` | Deliberately weakened binding model | Degraded / negative control | `profId` omitted from authenticated binding and receipt bodies | Binding, ordering, backend completion, secrecy | Binding FALSE; remaining properties TRUE | Conditional on the deliberate field omission; not a claim about the GSMA object |
| S3 | `S3_UNAUTH_TRIGGER.pv` | Authorization-gate omission model | Degraded / negative control | No process emits `CONSENT` before provisioning | Binding, ordering, secrecy, authorization | Authorization FALSE; remaining properties TRUE | Shows that cryptographic success alone does not imply authorization |
| S4 | `S4_RACE_REPLAY.pv` | Concurrent-order authorization model | Degraded / conditional | Consent only for PROF_A; malicious IPA forwards valid PROF_B order | Binding, ordering, two secrecy queries, authorization | Authorization FALSE; remaining properties TRUE | Models race/order selection, not conventional message replay |
| S5 | `S5_MISBINDING.pv` | Weak-context misbinding model | Degraded / negative control | `dev`, `tid`, and `profId` omitted from signed/MACed body | Binding, ordering, authorization, secrecy, misbinding reachability | Binding and authorization FALSE; ordering and secrecy TRUE; misbinding reachable | Conditional on deliberately incomplete authenticated context |
| S6 | `S6_FAKE_COMPLETION.pv` | Explicit key-compromise model | Compromise | `k_tag` intentionally released using `out(c,k_tag)` | Binding, ordering, backend/device completion, secrecy | Completion FALSE; remaining properties TRUE | Does not model forgery by an uncompromised attacker or the exact standardized receipt |
| S7 | `S7_PFS FAILURE.pv` | Long-term-key/PFS-related compromise model | Compromise / robustness | SM-DP+ signing key and both channels public; ephemeral ECDH secrets private | Binding, ordering, profile secrecy | Binding FALSE; ordering and secrecy TRUE | No retrospective transcript phase; filename alone is not proof of PFS failure |

## Exact query outcomes

### S0-A: mutual authentication

The released model used `U_AUTH_OK ==> S_AUTH_BEGIN` and
`S_AUTH_OK ==> U_AUTH_OK`. The antecedents are now written explicitly as
`inj-event`, and the publication-aligned direct correspondence
`S_AUTH_OK ==> S_AUTH_BEGIN` is also checked.

```text
inj-event(U_AUTH_OK(U,tid))
  ==> inj-event(S_AUTH_BEGIN(U,tid))                         TRUE

inj-event(S_AUTH_OK(U,tid))
  ==> inj-event(U_AUTH_OK(U,tid))                            TRUE

inj-event(S_AUTH_OK(U,tid))
  ==> inj-event(S_AUTH_BEGIN(U,tid))                         TRUE
```

The direct third query differs semantically from the first query: it uses final
server completion rather than eUICC acceptance as the antecedent. No event was
moved and no artificial session identifier was introduced.

### S0-B: Phase-B baseline

```text
inj-event(BIND_OK(U,P,tid))
  ==> inj-event(BIND_BEGIN(U,P,tid))                         TRUE

inj-event(DL_OK(U,P,tid))
  ==> inj-event(BIND_OK(U,P,tid))                            TRUE

not attacker(prof_plain)                                    TRUE
```

### S1: channel exposure

```text
inj-event(BIND_OK(U,P,tid))
  ==> inj-event(BIND_BEGIN(U,P,tid))                         TRUE

inj-event(DL_OK(U,P,tid))
  ==> inj-event(BIND_OK(U,P,tid))                            TRUE

not attacker(prof_plain)                                    TRUE
```

Both transport channels are public, but `authContext(dev,Q_U)` retains the
already-completed authentication precondition. No long-term or ECDH secret is
explicitly leaked in S1.

### S2: session splicing with weak profile binding

```text
inj-event(BIND_OK(U,P,tid,Q_U,Q_S))
  ==> inj-event(BIND_BEGIN(U,P,tid,Q_U,Q_S))                 FALSE
even event(BIND_OK(...)) ==> event(BIND_BEGIN(...))          FALSE

inj-event(DL_OK(...)) ==> inj-event(BIND_OK(...))            TRUE
inj-event(DL_S_ACCEPT(...)) ==> inj-event(DL_OK(...))        TRUE
not attacker(prof_plain)                                    TRUE
```

The false result is caused by omitting `profId` from the authenticated binding
body and receipt body. It is a conditional counterexample.

### S3: authorization-gate omission

```text
inj-event(BIND_OK(...)) ==> inj-event(BIND_BEGIN(...))       TRUE
inj-event(DL_OK(...)) ==> inj-event(BIND_OK(...))            TRUE
not attacker(prof_plain)                                    TRUE
event(DL_OK(U,P,...)) ==> event(CONSENT(U,P))                FALSE
```

`CONSENT` is declared but no process emits it. The failed authorization query
therefore demonstrates the consequence of omitting the gate; it is not an
independent discovery that the standardized procedure lacks authorization.

### S4: concurrent-order authorization mismatch

```text
inj-event(BIND_OK(...)) ==> inj-event(BIND_BEGIN(...))       TRUE
inj-event(DL_OK(...)) ==> inj-event(BIND_OK(...))            TRUE
not attacker(profA_plain)                                   TRUE
not attacker(profB_plain)                                   TRUE
event(DL_OK(U,P,...)) ==> event(CONSENT(U,P))                FALSE
```

The implementation creates two current orders and forwards the non-authorized
one. It does not reuse a previously valid protocol message.

### S5: deliberately weak authenticated context

```text
inj-event(BIND_OK(...)) ==> inj-event(BIND_BEGIN(...))       FALSE
even event(BIND_OK(...)) ==> event(BIND_BEGIN(...))          FALSE
inj-event(DL_OK(...)) ==> inj-event(BIND_OK(...))            TRUE
event(DL_OK(...)) ==> event(CONSENT(...))                    FALSE
not attacker(prof_plain)                                    TRUE
event(S5_MISBIND(...))                                  REACHABLE
```

The weak authenticated object contains `Q_S`, `Q_U`, and `BPP_cipher`, but
omits `dev`, `tid`, and `profId`. The results do not assert that a standardized
GSMA object has the same omission.

### S6: explicit receipt-key compromise

```text
inj-event(BIND_OK(...)) ==> inj-event(BIND_BEGIN(...))       TRUE
inj-event(DL_OK(...)) ==> inj-event(BIND_OK(...))            TRUE
inj-event(DL_S_ACCEPT(...)) ==> inj-event(DL_OK(...))        FALSE
even event(DL_S_ACCEPT(...)) ==> event(DL_OK(...))           FALSE
not attacker(prof_plain)                                    TRUE
```

The completion failure depends on the explicit release of `k_tag`. A
nonce-bound HMAC under that same compromised key would not remove this
compromise assumption.

### S7: exposed signing key with ephemeral ECDH profile protection

```text
inj-event(BIND_OK(...)) ==> inj-event(BIND_BEGIN(...))       FALSE
even event(BIND_OK(...)) ==> event(BIND_BEGIN(...))          FALSE
inj-event(DL_OK(...)) ==> inj-event(BIND_OK(...))            TRUE
not attacker(prof_plain)                                    TRUE
```

The public signing key enables an active attacker to construct a forged
binding response, so binding agreement fails. The honest profile remains
protected by the fresh ECDH-derived encryption key. Because the model has no
"record now, compromise later" phases, it does not establish a general
retrospective PFS theorem.

## Paper-code consistency corrections

1. The direct injective `S_AUTH_OK ==> S_AUTH_BEGIN` query is now explicit in
   S0-A; the two original correspondence checks are retained.
2. The Phase-A/Phase-B separation and absence of a full composition proof are
   explicit.
3. S1, S4, S6, and S7 carry an abstract authenticated `Q_U` context into public
   Phase-B channels. This corrects an unrelated chosen-`Q_U` trace while
   preserving each scenario's intended degradation.
4. S2 and S5 are identified as deliberately weakened negative-control models.
5. S3 is identified as an authorization-gate omission experiment.
6. S4 is classified as a concurrent-order authorization mismatch; strict
   replay is not implemented by the historical file.
7. S6 prominently documents the explicit `k_tag` disclosure and the abstract
   nature of its receipt.
8. S7 documents the actual signing-key/channel exposure, the failed binding
   property, preserved profile secrecy, and the absence of a retrospective PFS
   experiment.

No published ProVerif file was renamed, deleted, or moved.
