# Fixed-version pairs (chapter 2.3)

Every labelled contract in the samples is vulnerable, so Precision/Recall alone cannot show whether the
method stays quiet on *safe* code. The pairs are the only source of true negatives: for 32 vulnerable
SmartBugs-Curated contracts a repaired version is written by hand, and the fixed-class unit on it should
be a true negative (REFUTED, or no target at all). The headline pair metric is the specificity

```
Spec = TN / (TN + FP)
```

on the fixed-class units, reported in both the `strict` and `moderate` modes, for every method
configuration (M1–M4) and the baselines (Slither, Mythril).

## How the 32 pairs are chosen

* **SmartBugs Curated only.** SolidiFI injects dozens of bugs per file, so "fixing" one would be
  rewriting the contract; its pairs would not be comparable (chapter 2.3).
* **8 per class** — SC01, SC06, SC08, SC09 — drawn with the experiment seed (`experiments.configs.SEED`)
  from the same compilable candidate pool `experiments.sample` uses, so the dataset exclusions carry
  over.
* **Option B pool narrowing.** The literal rule of 2.3 is "contracts labelled with the class"; the draw
  is narrowed to contracts whose *static* stage actually raises a target of that class (read from the
  committed `experiments/coverage.json`), so a fix to that class is meaningful rather than a no-op. This
  narrowing is logged for the thesis text (deferred change).
* **Two fix styles, 4 contracts each**, so each pair exercises a different branch of the class predicate
  on real code:

  | class | style A (4) | style B (4) |
  |-------|-------------|-------------|
  | SC01 access control | `modifier` — an `onlyOwner` modifier | `require` — `require(msg.sender == owner)` in the body |
  | SC06 unchecked call | `require` — `require(ok)` | `revert` — `if (!ok) revert()` |
  | SC08 reentrancy | `cei` — state write before the call | `guard` — a `nonReentrant` lock variable |
  | SC09 overflow | `require` — an explicit bound check | `safemath` — a checked internal call (inlined) |

* **Only the fixed class is scored** on the repaired version: a pre-0.8 overflow target left in a
  repaired reentrancy contract is *not* a pair false positive.
* **The solc version is inherited from the original** — the fixed file keeps the original pragma, so
  `prep.compile_contract` pins the same compiler and the difference cannot come from the toolchain.

### Degenerate substitution (variant c)

If an original is already REFUTED for its class on the *original* under M1, the pair is degenerate (the
method already calls it safe, so a correct fix proves nothing). Such an original is replaced by the next
seed-order candidate of the same class, keeping the fix-style slot. UNKNOWN originals are **kept** — for
SC09 almost all originals are UNKNOWN by design, and an UNKNOWN is a positive in `moderate`, so the pair
still tests the fix.

Substitutions actually applied:

* `access_control/arbitrary_location_write_simple.sol` → **`incorrect_constructor_name1.sol`** (SC01,
  `modifier` slot). The original writes to a computed storage slot via a construct the engine treats as
  `unsupported_op`, so its SC01 unit is REFUTED-by-omission on the original — degenerate.

### Variant B specificity scoring

`predicted` is intersected with the negative universe `N` (the fixed class's ground-truth-labelled
functions in the original) **before** the confusion is computed. A fixed-class positive on a function
that never carried the label — a pre-existing finding the fix never touched — is therefore *ignored*
here; it belongs to the manual FP review on the main sample, not to the repair's specificity. This
refines the earlier "any fixed-class positive = FP" rule and is logged for the thesis text.

## Running

```
python -m experiments.pairs list    # the 32 pairs and which fixtures exist (default)
python -m experiments.pairs score   # specificity per evaluator/mode, per class and overall
```

`score` writes a per-pair confusion JSON (`--out`, default `experiments/runs/pairs.json`) and prints the
specificity table. `--timeout` bounds the *baselines* per contract; the method uses `Config.budget`.
Mythril is skipped automatically when it is not installed.

## The 32 pairs and their fixed-class verdict (M1)

The verdict below is the fixed-class unit's strongest verdict on the repaired version under M1. None are
CONFIRMED — the only hard requirement for a fixture. REFUTED is a strict+moderate true negative; UNKNOWN
is a strict true negative but a moderate false positive (this is exactly the strict/moderate gap the
pairs are built to expose). "(no target)" means the static stage already discharged the class, a
true negative in both modes.

| class | style | contract | fixed-class unit verdict (M1) |
|-------|-------|----------|-------------------------------|
| SC01 | modifier | `incorrect_constructor_name1` | Missing.IamMissing(): REFUTED |
| SC01 | modifier | `incorrect_constructor_name2` | Missing.missing(): REFUTED |
| SC01 | modifier | `incorrect_constructor_name3` | Missing.Constructor(): REFUTED |
| SC01 | modifier | `parity_wallet_bug_2` | WalletLibrary.kill(address): REFUTED |
| SC01 | require | `rubixi` | Rubixi.DynamicPyramid(): REFUTED, Rubixi.changeOwner(address): REFUTED |
| SC01 | require | `simple_suicide` | SimpleSuicide.sudicideAnyone(): REFUTED |
| SC01 | require | `unprotected0` | Unprotected.changeOwner(address): REFUTED |
| SC01 | require | `wallet_03_wrong_constructor` | Wallet.initWallet(): REFUTED |
| SC06 | require | `0x07f7ecb66d788ab01dc93b9b71a88401de7d0f2e` | PoCGame.donateToWhale(uint256): REFUTED, PoCGame.loseWager(uint256): REFUTED |
| SC06 | require | `0x627fa62ccbb1c1b04ffaecd72a53e37fc0e17839` | TokenBank.WithdrawToHolder(address,uint256): UNKNOWN |
| SC06 | require | `0x663e4229142a27f00bafb5d087e1e730648314c3` | PandaBreeding.giveBirth(uint256,uint256[2],uint256[2]): UNKNOWN |
| SC06 | require | `0x7d09edb07d23acb532a82be3da5c17d9d85806b4` | PoCGame.donateToWhale(uint256): REFUTED, PoCGame.loseWager(uint256): REFUTED |
| SC06 | revert | `0xb7c5c5aa4d42967efe906e1b66cb8df9cebf04f7` | keepMyEther.withdraw(): REFUTED |
| SC06 | revert | `0xe09b1ab8111c2729a76f16de96bc86a7af837928` | FiftyFlip.wager(bool,uint256,uint256,uint8,bytes32,bytes32): REFUTED |
| SC06 | revert | `etherpot_lotto` | Lotto.fallback(): UNKNOWN, Lotto.cash(uint256,uint256): UNKNOWN |
| SC06 | revert | `king_of_the_ether_throne` | KingOfTheEtherThrone.claimThrone(string): UNKNOWN |
| SC08 | cei | `0x01f8c4e3fa3edeb29e514cba738d87ce8c091d3f` | (no SC08 target) |
| SC08 | cei | `0x4320e6f8c05b27ab4707cd1f6d5ce6f3e4b3a5a1` | (no SC08 target) |
| SC08 | cei | `0x561eac93c92360949ab1f1403323e6db345cbf31` | (no SC08 target) |
| SC08 | cei | `0x627fa62ccbb1c1b04ffaecd72a53e37fc0e17839` | (no SC08 target) |
| SC08 | guard | `0x8c7777c45481dba411450c228cb692ac3d550344` | ETH_VAULT.CashOut(uint256): REFUTED |
| SC08 | guard | `0x941d225236464a25eb18076df7da6a91d0f95e9e` | ETH_FUND.CashOut(uint256): REFUTED |
| SC08 | guard | `0xb5e1b1ee15c6fa0e48fce100125569d430f1bd12` | Private_Bank.CashOut(uint256): REFUTED |
| SC08 | guard | `etherstore` | EtherStore.withdrawFunds(uint256): REFUTED |
| SC09 | require | `BECToken` | PausableToken.batchTransfer(address[],uint256): UNKNOWN, SafeMath.add(uint256,uint256): UNKNOWN |
| SC09 | require | `insecure_transfer` | IntegerOverflowAdd.transfer(address,uint256): UNKNOWN |
| SC09 | require | `integer_overflow_add` | IntegerOverflowAdd.run(uint256): UNKNOWN |
| SC09 | require | `integer_overflow_minimal` | IntegerOverflowMinimal.run(uint256): REFUTED |
| SC09 | safemath | `integer_overflow_mul` | SafeMath.mul(uint256,uint256): UNKNOWN |
| SC09 | safemath | `integer_overflow_multitx_multifunc_feasible` | (no SC09 target) |
| SC09 | safemath | `integer_overflow_multitx_onefunc_feasible` | (no SC09 target) |
| SC09 | safemath | `timelock` | SafeMath.add(uint256,uint256): UNKNOWN, TimeLock.deposit(): UNKNOWN |

## Specificity (M1)

The headline metric for the pairs is specificity `Spec = TN / (TN + FP)` on the units of the fixed
class, in strict and moderate (section 2.3). The numbers below come from the real
`pairs.aggregate_scores` / `metrics.confusion` code, fed the M1 verdicts above and the per-pair negative
universes. Variant B is applied: the predicted positives are intersected with the negative universe
`N` (the original's ground-truth-labelled units of the fixed class) before the confusion, so a positive
on a function that never carried the label is dropped instead of counted as a false positive.

| class | strict Spec (TN/FP) | moderate Spec (TN/FP) |
|-------|---------------------|-----------------------|
| SC01 | 1.000 (9/0) | 1.000 (9/0) |
| SC06 | 1.000 (14/0) | 0.714 (10/4) |
| SC08 | 1.000 (8/0) | 1.000 (8/0) |
| SC09 | 1.000 (8/0) | 0.625 (5/3) |
| **overall (micro)** | **1.000 (39/0)** | **0.821 (32/7)** |
| **macro over classes** | **1.000** | **0.835** |

Strict specificity is a perfect 1.0: no fixed-class unit is ever CONFIRMED, which is the hard
requirement every fixture is checked against. The moderate drop is driven entirely by the UNKNOWN
verdicts that count as positives in moderate, and only where the UNKNOWN lands *on the labelled unit*:

* **SC06, 4 moderate FPs** — `giveBirth` (1), `etherpot_lotto` (2), `king_of_the_ether_throne`
  `claimThrone` (1): large contracts whose checked call site sits behind heavy guards/loops, so the
  φ_UC path does not close within budget. `0x627f…` UNKNOWN is on `TokenBank.WithdrawToHolder`, which is
  **not** the labelled unit (`Token.WithdrawToken`), so Variant B drops it — not an FP.
* **SC09, 3 moderate FPs** — `BECToken` `batchTransfer` (1), `insecure_transfer` `transfer` (1),
  `integer_overflow_add` `run` (1): addition/mul guarded by the wrap-detection idiom, UNKNOWN
  `storage_dependent` by construction (see *Findings*). The SafeMath positives (`SafeMath.add`/`mul`
  in `BECToken`, `integer_overflow_mul`, `timelock`, plus `TimeLock.deposit`) are attributed to the
  library/other function, fall outside `N`, and are dropped by Variant B — exactly the behaviour the
  intersection is there to produce.

These figures were collected at a per-target budget of 60 s (the fixed-class verdicts are identical to a
300 s budget run — every REFUTED stays REFUTED and no UNKNOWN converges further). The full
M1–M4 + Slither/Mythril specificity table (section 2.3 asks the pairs to be run by every config and both
baselines) is **not** yet populated: Mythril is not installed in this environment, and a full M1–M4
`score` run over the six non-converging contracts is long. Those columns are left for a dedicated run.

## Per-class fix notes

**SC01 (access control).** The attacker model fixes `sender = a*` with `a* != owner` for every state
variable `owner` that is compared with `msg.sender` (V_auth). Both styles put the owner variable into
V_auth and gate the privileged write on it, so the write is unreachable for the attacker → REFUTED.
`parity_wallet_bug_2` additionally drops the `onlymanyowners(sha3(msg.data))` multisig modifier from
`kill`, because its `2**ownerIndex` path is a symbolic exponent (`unsupported_op`); the scalar-owner
modifier is the faithful AC-hardening and is what the pair scores.

**SC06 (unchecked call).** Both styles consume the low-level call result: `require(ok)` reverts on
failure, `if (!ok) revert()` does the same by hand. On the surviving path the φ_UC premise `r_i = false`
is unsatisfiable → REFUTED. Large contracts whose call sites sit behind heavy guards or loops
(`giveBirth`, `WithdrawToHolder`, `etherpot_lotto`, `king_of_the_ether_throne`) time out to UNKNOWN —
a legitimate strict-TN / moderate-FP data point, not a fixture to be gamed.

**SC08 (reentrancy).** `cei` moves the state write before the external call, so there is no post-call
write and the static stage raises no RE target (no target → TN). `guard` adds a `nonReentrant` lock
(a scalar lock variable set to a constant across the call); the post-call write survives as a target but
is REFUTED because the guard blocks the re-entrant path.

**SC09 (overflow).** Only pre-0.8 contracts carry OV targets (all arithmetic is unchecked there). The
two styles behave asymmetrically, and this is a genuine, reportable property of the method rather than a
fixture defect (see *Findings* below):

* **subtraction** guarded by a pre-comparison (`require(a >= b)` or SafeMath `sub` with `require(b <= a)`)
  → the underflow predicate contradicts the guard on every path → REFUTED, or no target at all when the
  guarded subtraction is a `return a - b` whose result only flows to a `return`;
* **addition / multiplication** guarded by either the wrap-detection idiom (`require(a + b >= a)`,
  `require(_value == 0 || amount / _value == cnt)`) or SafeMath `add`/`mul` → the guard **computes the
  operation first**, so the operation itself stays an OV target; its strong condition fails at the
  zero-storage state (e.g. `count == 0` admits no overflowing `input`), so the verdict is UNKNOWN
  `storage_dependent` — never CONFIRMED.

## Findings flagged to the author (method-level, for the deferred-changes log)

1. **The require/safemath OV fixes cannot be *refuted* for addition and multiplication**, only marked
   UNKNOWN `storage_dependent`, because the overflow-guard idioms evaluate the guarded operation before
   the check. Consequence: in the pairs, require-/safemath-style OV specificity is high in `strict`
   (UNKNOWN = TN) but low in `moderate` (UNKNOWN = FP). No OV fix produces a false CONFIRMED. This is
   consistent with the documented `Overflow_transfer.sol` expectation ("addition → UNKNOWN
   `storage_dependent`"), so it is expected behaviour, not a contradiction.
2. **Inlined internal/library arithmetic is attributed to the *containing* function.** A SafeMath
   `add`/`mul` call lands its OV target on `SafeMath.add` / `SafeMath.mul`, not on the public labelled
   function. Under Variant B that unit is outside the negative universe `N` (which is keyed on the
   original's labelled function), so it is ignored, and the safemath-style OV pairs tend to score
   specificity 1.0 in both modes trivially. The same label-vs-unit mismatch will appear on the main
   sample and is worth a line in chapter 2.3.
3. **SafeMath `sub` (`require(b <= a); return a - b;`) raises no OV target at all**, because the
   subtraction's result flows only into a `return`, which the static OV rule (condition 2) does not count
   as "reaching the stack". Clean true negative, but worth noting that it is detected statically rather
   than refuted symbolically.

## Per-pair diffs

Unified diffs of each fixed version against its SmartBugs original (the header comment block is part of
every fixture and is included). Paths are relative to the SmartBugs dataset root and the repository root.

### SC01 / modifier — incorrect_constructor_name1

```diff
--- dataset/access_control/incorrect_constructor_name1.sol
+++ experiments/pairs/access_control/modifier/incorrect_constructor_name1.sol
@@ -1,2 +1,9 @@
 /*
+ * Fixed version of smartbugs-curated access_control/incorrect_constructor_name1.sol
+ * (pair, fix style: modifier).
+ * Fix: the misnamed-constructor function IamMissing (which lets anyone take ownership) is guarded by
+ * the onlyowner modifier, so under the attacker model (sender != owner) the privileged write is
+ * unreachable and the SC01 target is refuted. Only the SC01 unit is scored here.
+ * solc version inherited from the original (0.4.x).
+ *
  * @source: https://github.com/trailofbits/not-so-smart-contracts/blob/master/wrong_constructor_name/incorrect_constructor.sol
@@ -21,2 +28,3 @@
         public
+        onlyowner
     {
```

### SC01 / modifier — incorrect_constructor_name2

```diff
--- dataset/access_control/incorrect_constructor_name2.sol
+++ experiments/pairs/access_control/modifier/incorrect_constructor_name2.sol
@@ -1,2 +1,9 @@
 /*
+ * Fixed version of smartbugs-curated access_control/incorrect_constructor_name2.sol
+ * (pair, fix style: modifier).
+ * Fix: the misnamed-constructor function missing (which lets anyone take ownership) is guarded by the
+ * onlyowner modifier, so under the attacker model (sender != owner) the privileged write is
+ * unreachable and the SC01 target is refuted. Only the SC01 unit is scored here.
+ * solc version inherited from the original (0.4.x).
+ *
  * @source: https://smartcontractsecurity.github.io/SWC-registry/docs/SWC-118#incorrect-constructor-name1sol
@@ -19,2 +26,3 @@
         public
+        onlyowner
     {
```

### SC01 / modifier — incorrect_constructor_name3

```diff
--- dataset/access_control/incorrect_constructor_name3.sol
+++ experiments/pairs/access_control/modifier/incorrect_constructor_name3.sol
@@ -1,2 +1,9 @@
 /*
+ * Fixed version of smartbugs-curated access_control/incorrect_constructor_name3.sol
+ * (pair, fix style: modifier).
+ * Fix: the misnamed-constructor function Constructor (which lets anyone take ownership) is guarded by
+ * the onlyowner modifier, so under the attacker model (sender != owner) the privileged write is
+ * unreachable and the SC01 target is refuted. Only the SC01 unit is scored here.
+ * solc version inherited from the original (0.4.x).
+ *
  * @source: https://smartcontractsecurity.github.io/SWC-registry/docs/SWC-118#incorrect-constructor-name2sol
@@ -18,2 +25,3 @@
         public
+        onlyowner
     {
```

### SC01 / modifier — parity_wallet_bug_2

```diff
--- dataset/access_control/parity_wallet_bug_2.sol
+++ experiments/pairs/access_control/modifier/parity_wallet_bug_2.sol
@@ -1,2 +1,14 @@
 /*
+ * Fixed version of smartbugs-curated access_control/parity_wallet_bug_2.sol
+ * (pair, fix style: modifier).
+ * The method's SC01 target on this contract is the unprotected selfdestruct in kill (empty V_auth, so
+ * suicide reachable by any sender). Fix: a scalar `owner` state variable and a single-owner modifier
+ * `onlyWalletOwner { require(msg.sender == owner); _; }` replace the method-opaque onlymanyowners guard
+ * on kill, so under the attacker model (sender != owner) the selfdestruct is unreachable and the SC01
+ * target is refuted. (Keeping onlymanyowners would leave the path UNKNOWN: confirmAndCheck uses a
+ * symbolic 2**ownerIndex, an unsupported operation.) initWallet (the
+ * SWC-118 wrong-constructor-name line) writes no privileged state variable and is not raised as a
+ * target by the method, so it stays a true negative. Only the SC01 unit is scored here.
+ * solc version inherited from the original (0.4.x).
+ *
  * @source: https://smartcontractsecurity.github.io/SWC-registry/docs/SWC-106#walletlibrarysol
@@ -92,2 +104,8 @@
       _;
+  }
+  // scalar single-owner guard added by the fix (recognised as an access-control check on `owner`).
+  address public owner;
+  modifier onlyWalletOwner {
+    require(msg.sender == owner);
+    _;
   }
@@ -232,3 +250,3 @@
   // <yes> <report> ACCESS_CONTROL
-  function kill(address _to) onlymanyowners(sha3(msg.data)) external {
+  function kill(address _to) onlyWalletOwner external {
     suicide(_to);
```

### SC01 / require — rubixi

```diff
--- dataset/access_control/rubixi.sol
+++ experiments/pairs/access_control/require/rubixi.sol
@@ -1,2 +1,9 @@
 /*
+ * Fixed version of smartbugs-curated access_control/rubixi.sol
+ * (pair, fix style: require).
+ * Fix: the misnamed-constructor function DynamicPyramid (which lets anyone take over as creator) checks
+ * `require(msg.sender == creator)` in its body, so under the attacker model (sender != creator) the
+ * privileged write is unreachable and the SC01 target is refuted. Only the SC01 unit is scored here.
+ * solc version inherited from the original (0.4.x).
+ *
  * @source: https://github.com/trailofbits/not-so-smart-contracts/blob/master/wrong_constructor_name/Rubixi_source_code/Rubixi.sol
@@ -23,3 +30,4 @@
          function DynamicPyramid() {
-                 creator = msg.sender; //anyone can call this
+                 require(msg.sender == creator);
+                 creator = msg.sender;
          }
```

### SC01 / require — simple_suicide

```diff
--- dataset/access_control/simple_suicide.sol
+++ experiments/pairs/access_control/require/simple_suicide.sol
@@ -1,2 +1,10 @@
 /*
+ * Fixed version of smartbugs-curated access_control/simple_suicide.sol
+ * (pair, fix style: require).
+ * Fix: the unprotected selfdestruct is guarded by `require(msg.sender == owner)` in the body (owner is
+ * a state variable compared with the sender, so it enters V_auth); under the attacker model
+ * (sender != owner) the selfdestruct is unreachable and the SC01 target is refuted. Only the SC01 unit
+ * is scored here.
+ * solc version inherited from the original (0.4.x).
+ *
  * @source: https://github.com/SmartContractSecurity/SWC-registry/blob/master/test_cases/unprotected_critical_functions/simple_suicide.sol
@@ -10,4 +18,6 @@
 contract SimpleSuicide {
+  address owner;
   // <yes> <report> ACCESS_CONTROL
   function sudicideAnyone() {
+    require(msg.sender == owner);
     selfdestruct(msg.sender);
```

### SC01 / require — unprotected0

```diff
--- dataset/access_control/unprotected0.sol
+++ experiments/pairs/access_control/require/unprotected0.sol
@@ -1,2 +1,10 @@
 /*
+ * Fixed version of smartbugs-curated access_control/unprotected0.sol
+ * (pair, fix style: require).
+ * Fix: the unprotected changeOwner (which lets anyone overwrite the owner) checks
+ * `require(msg.sender == owner)` in its body (owner is a state variable compared with the sender, so
+ * it enters V_auth); under the attacker model (sender != owner) the privileged write is unreachable
+ * and the SC01 target is refuted. Only the SC01 unit is scored here.
+ * solc version inherited from the original (0.4.x).
+ *
  * @source: https://github.com/trailofbits/not-so-smart-contracts/blob/master/unprotected_function/Unprotected.sol
@@ -27,2 +35,3 @@
      {
+        require(msg.sender == owner);
         owner = _newOwner;
```

### SC01 / require — wallet_03_wrong_constructor

```diff
--- dataset/access_control/wallet_03_wrong_constructor.sol
+++ experiments/pairs/access_control/require/wallet_03_wrong_constructor.sol
@@ -1,2 +1,10 @@
 /*
+ * Fixed version of smartbugs-curated access_control/wallet_03_wrong_constructor.sol
+ * (pair, fix style: require).
+ * Fix: the misnamed-constructor function initWallet (which lets anyone take over as creator) checks
+ * `require(msg.sender == creator)` in its body (creator is a state variable compared with the sender,
+ * so it enters V_auth); under the attacker model (sender != creator) the privileged write is
+ * unreachable and the SC01 target is refuted. Only the SC01 unit is scored here.
+ * solc version inherited from the original (0.4.x).
+ *
  * @source: https://smartcontractsecurity.github.io/SWC-registry/docs/SWC-105#wallet-03-wrong-constructorsol
@@ -19,2 +27,3 @@
      function initWallet() public {
+         require(msg.sender == creator);
          creator = msg.sender;
```

### SC06 / require — 0x07f7ecb66d788ab01dc93b9b71a88401de7d0f2e

```diff
--- dataset/unchecked_low_level_calls/0x07f7ecb66d788ab01dc93b9b71a88401de7d0f2e.sol
+++ experiments/pairs/unchecked_low_level_calls/require/0x07f7ecb66d788ab01dc93b9b71a88401de7d0f2e.sol
@@ -1,3 +1,9 @@
 /*
- * @source: etherscan.io 
+ * Fixed version of smartbugs-curated unchecked_low_level_calls/0x07f7ecb66d788ab01dc93b9b71a88401de7d0f2e.sol
+ * (pair, fix style: require).
+ * Fix: each low-level whale.call is wrapped in require(...), so the success flag is checked and a
+ * failed call reverts instead of continuing to the state write. Only the SC06 unit is scored here.
+ * solc version inherited from the original (0.4.x).
+ *
+ * @source: etherscan.io
  * @author: -
@@ -200,3 +206,3 @@
         // <yes> <report> UNCHECKED_LL_CALLS
-        whale.call.value(amount)(bytes4(keccak256("donate()")));
+        require(whale.call.value(amount)(bytes4(keccak256("donate()"))));
         totalDonated += amount;
@@ -212,3 +218,3 @@
         // <yes> <report> UNCHECKED_LL_CALLS
-        whale.call.value(amount)(bytes4(keccak256("donate()")));
+        require(whale.call.value(amount)(bytes4(keccak256("donate()"))));
         totalDonated += amount;
```

### SC06 / require — 0x627fa62ccbb1c1b04ffaecd72a53e37fc0e17839

```diff
--- dataset/unchecked_low_level_calls/0x627fa62ccbb1c1b04ffaecd72a53e37fc0e17839.sol
+++ experiments/pairs/unchecked_low_level_calls/require/0x627fa62ccbb1c1b04ffaecd72a53e37fc0e17839.sol
@@ -1,3 +1,9 @@
 /*
- * @source: etherscan.io 
+ * Fixed version of smartbugs-curated unchecked_low_level_calls/0x627fa62ccbb1c1b04ffaecd72a53e37fc0e17839.sol
+ * (pair, fix style: require).
+ * Fix: the low-level token.call in WithdrawToken is wrapped in require(...), so the success flag is
+ * checked and a failed call reverts instead of being ignored. Only the SC06 unit is scored here.
+ * solc version inherited from the original (0.4.x).
+ *
+ * @source: etherscan.io
  * @author: -
@@ -43,3 +49,3 @@
          // <yes> <report> UNCHECKED_LL_CALLS
-        token.call(bytes4(sha3("transfer(address,uint256)")),to,amount); 
+        require(token.call(bytes4(sha3("transfer(address,uint256)")),to,amount));
     }
```

### SC06 / require — 0x663e4229142a27f00bafb5d087e1e730648314c3

```diff
--- dataset/unchecked_low_level_calls/0x663e4229142a27f00bafb5d087e1e730648314c3.sol
+++ experiments/pairs/unchecked_low_level_calls/require/0x663e4229142a27f00bafb5d087e1e730648314c3.sol
@@ -1,3 +1,9 @@
 /*
- * @source: etherscan.io 
+ * Fixed version of smartbugs-curated unchecked_low_level_calls/0x663e4229142a27f00bafb5d087e1e730648314c3.sol
+ * (pair, fix style: require).
+ * Fix: each unchecked `.send(...)` (lines 1152, 1496, 2467) is wrapped in require(...), so a failed
+ * send reverts instead of being ignored. Only the SC06 units are scored here.
+ * solc version inherited from the original (0.4.x).
+ *
+ * @source: etherscan.io
  * @author: -
@@ -1151,3 +1157,3 @@
          // <yes> <report> UNCHECKED_LL_CALLS
-        msg.sender.send(autoBirthFee);
+        require(msg.sender.send(autoBirthFee));
 
@@ -1495,3 +1501,3 @@
         // <yes> <report> UNCHECKED_LL_CALLS
-        bool res = nftAddress.send(this.balance);
+        require(nftAddress.send(this.balance));
     }
@@ -2466,3 +2472,3 @@
              // <yes> <report> UNCHECKED_LL_CALLS
-            cfoAddress.send(balance - subtractFees);
+            require(cfoAddress.send(balance - subtractFees));
         }
```

### SC06 / require — 0x7d09edb07d23acb532a82be3da5c17d9d85806b4

```diff
--- dataset/unchecked_low_level_calls/0x7d09edb07d23acb532a82be3da5c17d9d85806b4.sol
+++ experiments/pairs/unchecked_low_level_calls/require/0x7d09edb07d23acb532a82be3da5c17d9d85806b4.sol
@@ -1,5 +1,12 @@
 /*
- * @source: etherscan.io 
+ * Fixed version of smartbugs-curated unchecked_low_level_calls/0x7d09edb07d23acb532a82be3da5c17d9d85806b4.sol
+ * (pair, fix style: require).
+ * Fix: each low-level whale.call (lines 198, 210) is wrapped in require(...), so the success flag is
+ * checked and a failed call reverts instead of continuing to the state write. Only the SC06 units are
+ * scored here.
+ * solc version inherited from the original (0.4.x).
+ *
+ * @source: etherscan.io
  * @author: -
- * @vulnerable_at_lines: 198,210 
+ * @vulnerable_at_lines: 198,210
  */
@@ -197,3 +204,3 @@
         // <yes> <report> UNCHECKED_LL_CALLS
-        whale.call.value(amount)(bytes4(keccak256("donate()")));
+        require(whale.call.value(amount)(bytes4(keccak256("donate()"))));
         totalDonated += amount;
@@ -209,3 +216,3 @@
         // <yes> <report> UNCHECKED_LL_CALLS
-        whale.call.value(amount)(bytes4(keccak256("donate()")));
+        require(whale.call.value(amount)(bytes4(keccak256("donate()"))));
         totalDonated += amount;
```

### SC06 / revert — 0xb7c5c5aa4d42967efe906e1b66cb8df9cebf04f7

```diff
--- dataset/unchecked_low_level_calls/0xb7c5c5aa4d42967efe906e1b66cb8df9cebf04f7.sol
+++ experiments/pairs/unchecked_low_level_calls/revert/0xb7c5c5aa4d42967efe906e1b66cb8df9cebf04f7.sol
@@ -1,3 +1,10 @@
 /*
- * @source: etherscan.io 
+ * Fixed version of smartbugs-curated unchecked_low_level_calls/0xb7c5c5aa4d42967efe906e1b66cb8df9cebf04f7.sol
+ * (pair, fix style: revert).
+ * Fix: the low-level call in withdraw is guarded by `if (!call) revert();`, so the success flag is
+ * checked and a failed call reverts instead of being ignored. Only the SC06 unit is scored here (the
+ * pre-0.8 reentrancy write that remains is not a pair false positive).
+ * solc version inherited from the original (0.4.x).
+ *
+ * @source: etherscan.io
  * @author: -
@@ -24,3 +31,3 @@
         // <yes> <report> UNCHECKED_LL_CALLS
-        msg.sender.call.value(balances[msg.sender])();
+        if (!msg.sender.call.value(balances[msg.sender])()) revert();
         balances[msg.sender] = 0;
```

### SC06 / revert — 0xe09b1ab8111c2729a76f16de96bc86a7af837928

```diff
--- dataset/unchecked_low_level_calls/0xe09b1ab8111c2729a76f16de96bc86a7af837928.sol
+++ experiments/pairs/unchecked_low_level_calls/revert/0xe09b1ab8111c2729a76f16de96bc86a7af837928.sol
@@ -1,3 +1,10 @@
 /*
- * @source: etherscan.io 
+ * Fixed version of smartbugs-curated unchecked_low_level_calls/0xe09b1ab8111c2729a76f16de96bc86a7af837928.sol
+ * (pair, fix style: revert).
+ * Fix: the low-level whale.call (line 150) is guarded by `if (!call) revert();`, so the success flag
+ * is checked and a failed call reverts instead of continuing to the state write. Only the SC06 unit is
+ * scored here.
+ * solc version inherited from the original (0.4.x).
+ *
+ * @source: etherscan.io
  * @author: -
@@ -149,3 +156,3 @@
         // <yes> <report> UNCHECKED_LL_CALLS
-        whale.call.value(donate_amount)(bytes4(keccak256("donate()")));
+        if (!whale.call.value(donate_amount)(bytes4(keccak256("donate()")))) revert();
         totalAmountToWhale += donate_amount;
```

### SC06 / revert — etherpot_lotto

```diff
--- dataset/unchecked_low_level_calls/etherpot_lotto.sol
+++ experiments/pairs/unchecked_low_level_calls/revert/etherpot_lotto.sol
@@ -1,2 +1,8 @@
 /*
+ * Fixed version of smartbugs-curated unchecked_low_level_calls/etherpot_lotto.sol
+ * (pair, fix style: revert).
+ * Fix: each unchecked `.send(...)` (lines 109, 141) is guarded by `if (!send) revert();`, so a failed
+ * send reverts instead of being ignored. Only the SC06 units are scored here.
+ * solc version inherited from the original (0.4.x).
+ *
  * @source: https://github.com/etherpot/contract/blob/master/app/contracts/lotto.sol
@@ -108,3 +114,3 @@
          // <yes> <report> UNCHECKED_LL_CALLS
-         winner.send(subpot);
+         if (!winner.send(subpot)) revert();
 
@@ -140,3 +146,3 @@
              // <yes> <report> UNCHECKED_LL_CALLS
-             msg.sender.send(msg.value-value);
+             if (!msg.sender.send(msg.value-value)) revert();
          }
```

### SC06 / revert — king_of_the_ether_throne

```diff
--- dataset/unchecked_low_level_calls/king_of_the_ether_throne.sol
+++ experiments/pairs/unchecked_low_level_calls/revert/king_of_the_ether_throne.sol
@@ -1,2 +1,8 @@
 /*
+ * Fixed version of smartbugs-curated unchecked_low_level_calls/king_of_the_ether_throne.sol
+ * (pair, fix style: revert).
+ * Fix: each unchecked `.send(...)` (lines 110, 118, 132, 174) is guarded by `if (!send) revert();`,
+ * so a failed send reverts instead of being ignored. Only the SC06 units are scored here.
+ * solc version inherited from the original (0.4.x).
+ *
  * @source: https://github.com/kieranelby/KingOfTheEtherThrone/blob/v0.4.0/contracts/KingOfTheEtherThrone.sol
@@ -109,3 +115,3 @@
             // <yes> <report> UNCHECKED_LL_CALLS
-            msg.sender.send(valuePaid);
+            if (!msg.sender.send(valuePaid)) revert();
             return;
@@ -117,3 +123,3 @@
             // <yes> <report> UNCHECKED_LL_CALLS
-            msg.sender.send(excessPaid);
+            if (!msg.sender.send(excessPaid)) revert();
             valuePaid = valuePaid - excessPaid;
@@ -131,3 +137,3 @@
             // <yes> <report> UNCHECKED_LL_CALLS
-            currentMonarch.etherAddress.send(compensation);
+            if (!currentMonarch.etherAddress.send(compensation)) revert();
         } else {
@@ -173,3 +179,3 @@
         // <yes> <report> UNCHECKED_LL_CALLS
-        wizardAddress.send(amount);
+        if (!wizardAddress.send(amount)) revert();
     }
```

### SC08 / cei — 0x01f8c4e3fa3edeb29e514cba738d87ce8c091d3f

```diff
--- dataset/reentrancy/0x01f8c4e3fa3edeb29e514cba738d87ce8c091d3f.sol
+++ experiments/pairs/reentrancy/cei/0x01f8c4e3fa3edeb29e514cba738d87ce8c091d3f.sol
@@ -1,5 +1,8 @@
 /*
- * @source: etherscan.io 
- * @author: -
- * @vulnerable_at_lines: 54
+ * Fixed version of smartbugs-curated reentrancy/0x01f8c4e3fa3edeb29e514cba738d87ce8c091d3f.sol
+ * (pair, fix style: cei).
+ * Fix: in Collect the balance is debited BEFORE the external call (checks-effects-interactions),
+ * so no state write remains after the call and the SC08 target disappears. Only the SC08 unit is
+ * scored on this version.
+ * solc version inherited from the original (0.4.x).
  */
@@ -10,10 +13,10 @@
 {
-    mapping (address=>uint256) public balances;   
-   
+    mapping (address=>uint256) public balances;
+
     uint public MinSum = 1 ether;
-    
+
     LogFile Log = LogFile(0x0486cF65A2F2F3A392CBEa398AFB7F5f0B72FF46);
-    
+
     bool intitalized;
-    
+
     function SetMinSum(uint _val)
@@ -24,3 +27,3 @@
     }
-    
+
     function SetLogFile(address _log)
@@ -31,3 +34,3 @@
     }
-    
+
     function Initialized()
@@ -37,3 +40,3 @@
     }
-    
+
     function Deposit()
@@ -45,3 +48,3 @@
     }
-    
+
     function Collect(uint _am)
@@ -52,6 +55,6 @@
         {
-            // <yes> <report> REENTRANCY
+            // effects before interaction: debit first, then call
+            balances[msg.sender]-=_am;
             if(msg.sender.call.value(_am)())
             {
-                balances[msg.sender]-=_am;
                 Log.AddMessage(msg.sender,_am,"Collect");
@@ -60,5 +63,5 @@
     }
-    
-    function() 
-    public 
+
+    function()
+    public
     payable
@@ -67,3 +70,3 @@
     }
-    
+
 }
@@ -81,7 +84,7 @@
     }
-    
+
     Message[] public History;
-    
+
     Message LastMsg;
-    
+
     function AddMessage(address _adr,uint _val,string _data)
```

### SC08 / cei — 0x4320e6f8c05b27ab4707cd1f6d5ce6f3e4b3a5a1

```diff
--- dataset/reentrancy/0x4320e6f8c05b27ab4707cd1f6d5ce6f3e4b3a5a1.sol
+++ experiments/pairs/reentrancy/cei/0x4320e6f8c05b27ab4707cd1f6d5ce6f3e4b3a5a1.sol
@@ -1,6 +1,8 @@
-
 /*
- * @source: etherscan.io 
- * @author: -
- * @vulnerable_at_lines: 55
+ * Fixed version of smartbugs-curated reentrancy/0x4320e6f8c05b27ab4707cd1f6d5ce6f3e4b3a5a1.sol
+ * (pair, fix style: cei).
+ * Fix: in Collect the balance is debited BEFORE the external call (checks-effects-interactions),
+ * so no state write remains after the call and the SC08 target disappears. Only the SC08 unit is
+ * scored on this version.
+ * solc version inherited from the original (0.4.x).
  */
@@ -11,10 +13,10 @@
 {
-    mapping (address=>uint256) public balances;   
-   
+    mapping (address=>uint256) public balances;
+
     uint public MinSum = 1 ether;
-    
+
     LogFile Log = LogFile(0x0486cF65A2F2F3A392CBEa398AFB7F5f0B72FF46);
-    
+
     bool intitalized;
-    
+
     function SetMinSum(uint _val)
@@ -25,3 +27,3 @@
     }
-    
+
     function SetLogFile(address _log)
@@ -32,3 +34,3 @@
     }
-    
+
     function Initialized()
@@ -38,3 +40,3 @@
     }
-    
+
     function Deposit()
@@ -46,3 +48,3 @@
     }
-    
+
     function Collect(uint _am)
@@ -53,6 +55,6 @@
         {
-            // <yes> <report> REENTRANCY
+            // effects before interaction: debit first, then call
+            balances[msg.sender]-=_am;
             if(msg.sender.call.value(_am)())
             {
-                balances[msg.sender]-=_am;
                 Log.AddMessage(msg.sender,_am,"Collect");
@@ -61,5 +63,5 @@
     }
-    
-    function() 
-    public 
+
+    function()
+    public
     payable
@@ -68,3 +70,3 @@
     }
-    
+
 }
@@ -82,7 +84,7 @@
     }
-    
+
     Message[] public History;
-    
+
     Message LastMsg;
-    
+
     function AddMessage(address _adr,uint _val,string _data)
```

### SC08 / cei — 0x561eac93c92360949ab1f1403323e6db345cbf31

```diff
--- dataset/reentrancy/0x561eac93c92360949ab1f1403323e6db345cbf31.sol
+++ experiments/pairs/reentrancy/cei/0x561eac93c92360949ab1f1403323e6db345cbf31.sol
@@ -1,5 +1,8 @@
 /*
- * @source: etherscan.io 
- * @author: -
- * @vulnerable_at_lines: 54
+ * Fixed version of smartbugs-curated reentrancy/0x561eac93c92360949ab1f1403323e6db345cbf31.sol
+ * (pair, fix style: cei).
+ * Fix: in Collect the balance is debited BEFORE the external call (checks-effects-interactions),
+ * so no state write remains after the call and the SC08 target disappears. Only the SC08 unit is
+ * scored on this version.
+ * solc version inherited from the original (0.4.x).
  */
@@ -10,10 +13,10 @@
 {
-    mapping (address=>uint256) public balances;   
-   
+    mapping (address=>uint256) public balances;
+
     uint public MinSum;
-    
+
     LogFile Log;
-    
+
     bool intitalized;
-    
+
     function SetMinSum(uint _val)
@@ -24,3 +27,3 @@
     }
-    
+
     function SetLogFile(address _log)
@@ -31,3 +34,3 @@
     }
-    
+
     function Initialized()
@@ -37,3 +40,3 @@
     }
-    
+
     function Deposit()
@@ -45,3 +48,3 @@
     }
-    
+
     function Collect(uint _am)
@@ -52,6 +55,6 @@
         {
-            // <yes> <report> REENTRANCY
+            // effects before interaction: debit first, then call
+            balances[msg.sender]-=_am;
             if(msg.sender.call.value(_am)())
             {
-                balances[msg.sender]-=_am;
                 Log.AddMessage(msg.sender,_am,"Collect");
@@ -60,5 +63,5 @@
     }
-    
-    function() 
-    public 
+
+    function()
+    public
     payable
@@ -67,3 +70,3 @@
     }
-    
+
 }
@@ -81,7 +84,7 @@
     }
-    
+
     Message[] public History;
-    
+
     Message LastMsg;
-    
+
     function AddMessage(address _adr,uint _val,string _data)
```

### SC08 / cei — 0x627fa62ccbb1c1b04ffaecd72a53e37fc0e17839

```diff
--- dataset/reentrancy/0x627fa62ccbb1c1b04ffaecd72a53e37fc0e17839.sol
+++ experiments/pairs/reentrancy/cei/0x627fa62ccbb1c1b04ffaecd72a53e37fc0e17839.sol
@@ -1,5 +1,8 @@
 /*
- * @source: etherscan.io 
- * @author: -
- * @vulnerable_at_lines: 94
+ * Fixed version of smartbugs-curated reentrancy/0x627fa62ccbb1c1b04ffaecd72a53e37fc0e17839.sol
+ * (pair, fix style: cei).
+ * Fix: in WithdrawToHolder the holder balance is debited BEFORE the external call
+ * (checks-effects-interactions), so no state write remains after the call and the SC08 target
+ * disappears. Only the SC08 unit is scored on this version.
+ * solc version inherited from the original (0.4.x).
  */
@@ -12,3 +15,3 @@
     address owner = msg.sender;
-    
+
     function changeOwner(address addr)
@@ -19,4 +22,4 @@
     }
-    
-    function confirmOwner() 
+
+    function confirmOwner()
     public
@@ -28,3 +31,3 @@
     }
-    
+
     modifier onlyOwner
@@ -39,6 +42,6 @@
     function WithdrawToken(address token, uint256 amount,address to)
-    public 
+    public
     onlyOwner
     {
-        token.call(bytes4(sha3("transfer(address,uint256)")),to,amount); 
+        token.call(bytes4(sha3("transfer(address,uint256)")),to,amount);
     }
@@ -50,3 +53,3 @@
     mapping (address => uint) public Holders;
-    
+
      ///Constructor
@@ -58,3 +61,3 @@
     }
-    
+
     function()
@@ -64,4 +67,4 @@
     }
-   
-    function Deposit() 
+
+    function Deposit()
     payable
@@ -73,3 +76,3 @@
     }
-    
+
     function WitdrawTokenToHolder(address _to,address _token,uint _amount)
@@ -81,7 +84,7 @@
             Holders[_to]=0;
-            WithdrawToken(_token,_amount,_to);     
+            WithdrawToken(_token,_amount,_to);
         }
     }
-   
-    function WithdrawToHolder(address _addr, uint _wei) 
+
+    function WithdrawToHolder(address _addr, uint _wei)
     public
@@ -92,7 +95,5 @@
         {
-            // <yes> <report> REENTRANCY
-            if(_addr.call.value(_wei)())
-            {
-                Holders[_addr]-=_wei;
-            }
+            // effects before interaction: debit first, then call
+            Holders[_addr]-=_wei;
+            _addr.call.value(_wei)();
         }
```

### SC08 / guard — 0x8c7777c45481dba411450c228cb692ac3d550344

```diff
--- dataset/reentrancy/0x8c7777c45481dba411450c228cb692ac3d550344.sol
+++ experiments/pairs/reentrancy/guard/0x8c7777c45481dba411450c228cb692ac3d550344.sol
@@ -1,7 +1,10 @@
 /*
- * @source: etherscan.io 
- * @author: -
- * @vulnerable_at_lines: 41
+ * Fixed version of smartbugs-curated reentrancy/0x8c7777c45481dba411450c228cb692ac3d550344.sol
+ * (pair, fix style: guard).
+ * Fix: a nonReentrant lock variable guards CashOut, so the re-entrant call cannot re-enter before
+ * `balances` is written. The SC08 target stays (write after the call) but is refuted. Only the SC08
+ * unit is scored on this version.
+ * solc version inherited from the original (0.4.x).
  */
- 
+
 pragma solidity ^0.4.19;
@@ -11,9 +14,19 @@
     mapping (address => uint) public balances;
-    
+
     Log TransferLog;
-    
+
     uint public MinDeposit = 1 ether;
-    
+
+    bool private locked;
+
+    modifier nonReentrant()
+    {
+        require(!locked);
+        locked = true;
+        _;
+        locked = false;
+    }
+
     function ETH_VAULT(address _log)
-    public 
+    public
     {
@@ -21,3 +34,3 @@
     }
-    
+
     function Deposit()
@@ -32,3 +45,3 @@
     }
-    
+
     function CashOut(uint _am)
@@ -36,2 +49,3 @@
     payable
+    nonReentrant
     {
@@ -39,3 +53,2 @@
         {
-            // <yes> <report> REENTRANCY
             if(msg.sender.call.value(_am)())
@@ -47,10 +60,10 @@
     }
-    
-    function() public payable{}    
-    
+
+    function() public payable{}
+
 }
 
-contract Log 
+contract Log
 {
-   
+
     struct Message
@@ -62,7 +75,7 @@
     }
-    
+
     Message[] public History;
-    
+
     Message LastMsg;
-    
+
     function AddMessage(address _adr,uint _val,string _data)
```

### SC08 / guard — 0x941d225236464a25eb18076df7da6a91d0f95e9e

```diff
--- dataset/reentrancy/0x941d225236464a25eb18076df7da6a91d0f95e9e.sol
+++ experiments/pairs/reentrancy/guard/0x941d225236464a25eb18076df7da6a91d0f95e9e.sol
@@ -1,5 +1,8 @@
 /*
- * @source: etherscan.io 
- * @author: -
- * @vulnerable_at_lines: 44
+ * Fixed version of smartbugs-curated reentrancy/0x941d225236464a25eb18076df7da6a91d0f95e9e.sol
+ * (pair, fix style: guard).
+ * Fix: a nonReentrant lock variable guards CashOut, so the re-entrant call cannot re-enter before
+ * `balances` is written. The SC08 target stays (write after the call) but is refuted. Only the SC08
+ * unit is scored on this version.
+ * solc version inherited from the original (0.4.x).
  */
@@ -11,11 +14,21 @@
     mapping (address => uint) public balances;
-    
+
     uint public MinDeposit = 1 ether;
-    
+
     Log TransferLog;
-    
+
     uint lastBlock;
-    
+
+    bool private locked;
+
+    modifier nonReentrant()
+    {
+        require(!locked);
+        locked = true;
+        _;
+        locked = false;
+    }
+
     function ETH_FUND(address _log)
-    public 
+    public
     {
@@ -23,3 +36,3 @@
     }
-    
+
     function Deposit()
@@ -35,3 +48,3 @@
     }
-    
+
     function CashOut(uint _am)
@@ -39,2 +52,3 @@
     payable
+    nonReentrant
     {
@@ -42,3 +56,2 @@
         {
-            // <yes> <report> REENTRANCY
             if(msg.sender.call.value(_am)())
@@ -50,10 +63,10 @@
     }
-    
-    function() public payable{}    
-    
+
+    function() public payable{}
+
 }
 
-contract Log 
+contract Log
 {
-   
+
     struct Message
@@ -65,7 +78,7 @@
     }
-    
+
     Message[] public History;
-    
+
     Message LastMsg;
-    
+
     function AddMessage(address _adr,uint _val,string _data)
```

### SC08 / guard — 0xb5e1b1ee15c6fa0e48fce100125569d430f1bd12

```diff
--- dataset/reentrancy/0xb5e1b1ee15c6fa0e48fce100125569d430f1bd12.sol
+++ experiments/pairs/reentrancy/guard/0xb5e1b1ee15c6fa0e48fce100125569d430f1bd12.sol
@@ -1,5 +1,8 @@
 /*
- * @source: etherscan.io 
- * @author: -
- * @vulnerable_at_lines: 40
+ * Fixed version of smartbugs-curated reentrancy/0xb5e1b1ee15c6fa0e48fce100125569d430f1bd12.sol
+ * (pair, fix style: guard).
+ * Fix: a nonReentrant lock variable guards CashOut, so the re-entrant call cannot re-enter before
+ * `balances` is written. The SC08 target stays (write after the call) but is refuted. Only the SC08
+ * unit is scored on this version.
+ * solc version inherited from the original (0.4.x).
  */
@@ -11,7 +14,17 @@
     mapping (address => uint) public balances;
-    
+
     uint public MinDeposit = 1 ether;
-    
+
     Log TransferLog;
-    
+
+    bool private locked;
+
+    modifier nonReentrant()
+    {
+        require(!locked);
+        locked = true;
+        _;
+        locked = false;
+    }
+
     function Private_Bank(address _log)
@@ -20,3 +33,3 @@
     }
-    
+
     function Deposit()
@@ -31,3 +44,3 @@
     }
-    
+
     function CashOut(uint _am)
@@ -35,2 +48,3 @@
     payable
+    nonReentrant
     {
@@ -38,3 +52,2 @@
         {
-            // <yes> <report> REENTRANCY
             if(msg.sender.call.value(_am)())
@@ -46,10 +59,10 @@
     }
-    
-    function() public payable{}    
-    
+
+    function() public payable{}
+
 }
 
-contract Log 
+contract Log
 {
-   
+
     struct Message
@@ -61,7 +74,7 @@
     }
-    
+
     Message[] public History;
-    
+
     Message LastMsg;
-    
+
     function AddMessage(address _adr,uint _val,string _data)
```

### SC08 / guard — etherstore

```diff
--- dataset/reentrancy/etherstore.sol
+++ experiments/pairs/reentrancy/guard/etherstore.sol
@@ -1,5 +1,6 @@
 /*
- * @source: https://github.com/sigp/solidity-security-blog
- * @author: Suhabe Bugrara
- * @vulnerable_at_lines: 27
+ * Fixed version of smartbugs-curated reentrancy/etherstore.sol (pair, fix style: guard).
+ * Fix: a nonReentrant lock variable guards withdrawFunds, so the re-entrant call cannot re-enter
+ * before `balances` is written. Only the SC08 unit is scored on this version.
+ * solc version inherited from the original (0.4.x).
  */
@@ -15,2 +16,11 @@
 
+    bool private locked;
+
+    modifier nonReentrant() {
+        require(!locked);
+        locked = true;
+        _;
+        locked = false;
+    }
+
     function depositFunds() public payable {
@@ -19,3 +29,3 @@
 
-    function withdrawFunds (uint256 _weiToWithdraw) public {
+    function withdrawFunds (uint256 _weiToWithdraw) public nonReentrant {
         require(balances[msg.sender] >= _weiToWithdraw);
@@ -25,3 +35,2 @@
         require(now >= lastWithdrawTime[msg.sender] + 1 weeks);
-        // <yes> <report> REENTRANCY
         require(msg.sender.call.value(_weiToWithdraw)());
```

### SC09 / require — BECToken

```diff
--- dataset/arithmetic/BECToken.sol
+++ experiments/pairs/arithmetic/require/BECToken.sol
@@ -1,2 +1,10 @@
 /*
+ * Fixed version of smartbugs-curated arithmetic/BECToken.sol
+ * (pair, fix style: require).
+ * Fix: the unchecked `amount = cnt * _value` in batchTransfer (the historical BEC overflow) is guarded
+ * by an explicit multiplication-overflow check `require(_value == 0 || amount / _value == cnt)`, which
+ * contradicts the multiplication-overflow predicate on every surviving path, so the SC09 target on the
+ * multiplication is refuted. Only the SC09 unit is scored here.
+ * solc version inherited from the original (0.4.x).
+ *
  * @source: https://smartcontractsecurity.github.io/SWC-registry/docs/SWC-101#bectokensol
@@ -264,2 +272,3 @@
     uint256 amount = uint256(cnt) * _value;
+    require(_value == 0 || amount / _value == cnt);
     require(cnt > 0 && cnt <= 20);
```

### SC09 / require — insecure_transfer

```diff
--- dataset/arithmetic/insecure_transfer.sol
+++ experiments/pairs/arithmetic/require/insecure_transfer.sol
@@ -1,2 +1,10 @@
 /*
+ * Fixed version of smartbugs-curated arithmetic/insecure_transfer.sol
+ * (pair, fix style: require).
+ * Fix: the unchecked credit `balanceOf[_to] += _value` is guarded by an explicit bounds check
+ * `require(balanceOf[_to] + _value >= balanceOf[_to])`, which contradicts the addition-overflow
+ * predicate on every path, so the SC09 target on the add is refuted. Only the SC09 unit is scored
+ * here (the subtraction was already guarded by the existing balance require).
+ * solc version inherited from the original (0.4.x).
+ *
  * @source: https://consensys.github.io/smart-contract-best-practices/known_attacks/#front-running-aka-transaction-ordering-dependence
@@ -17,2 +25,3 @@
         // <yes> <report> ARITHMETIC
+        require(balanceOf[_to] + _value >= balanceOf[_to]);
         balanceOf[_to] += _value;
```

### SC09 / require — integer_overflow_add

```diff
--- dataset/arithmetic/integer_overflow_add.sol
+++ experiments/pairs/arithmetic/require/integer_overflow_add.sol
@@ -1,2 +1,9 @@
 /*
+ * Fixed version of smartbugs-curated arithmetic/integer_overflow_add.sol
+ * (pair, fix style: require).
+ * Fix: the unchecked `count += input` is guarded by `require(count + input >= count)`, which
+ * contradicts the addition-overflow predicate on every path, so the SC09 target is refuted. Only the
+ * SC09 unit is scored here.
+ * solc version inherited from the original (0.4.x).
+ *
  * @source: https://github.com/ConsenSys/evm-analyzer-benchmark-suite/blob/master/benchmarks/integer_overflow_add.sol
@@ -16,2 +23,3 @@
         // <yes> <report> ARITHMETIC
+        require(count + input >= count);
         count += input;
```

### SC09 / require — integer_overflow_minimal

```diff
--- dataset/arithmetic/integer_overflow_minimal.sol
+++ experiments/pairs/arithmetic/require/integer_overflow_minimal.sol
@@ -1,2 +1,9 @@
 /*
+ * Fixed version of smartbugs-curated arithmetic/integer_overflow_minimal.sol
+ * (pair, fix style: require).
+ * Fix: the unchecked `count -= input` is guarded by `require(count >= input)`, which contradicts the
+ * subtraction-underflow predicate on every path, so the SC09 target is refuted. Only the SC09 unit is
+ * scored here.
+ * solc version inherited from the original (0.4.x).
+ *
  * @source: https://github.com/SmartContractSecurity/SWC-registry/blob/master/test_cases/integer_overflow_and_underflow/integer_overflow_minimal.sol
@@ -16,2 +23,3 @@
         // <yes> <report> ARITHMETIC
+        require(count >= input);
         count -= input;
```

### SC09 / safemath — integer_overflow_mul

```diff
--- dataset/arithmetic/integer_overflow_mul.sol
+++ experiments/pairs/arithmetic/safemath/integer_overflow_mul.sol
@@ -1,2 +1,11 @@
 /*
+ * Fixed version of smartbugs-curated arithmetic/integer_overflow_mul.sol
+ * (pair, fix style: safemath).
+ * Fix: the unchecked `count *= input` is routed through a SafeMath-like `mul` whose body guards the
+ * product with `require(a == 0 || c / a == b)`. The internal library call is inlined (JUMP, not
+ * DELEGATECALL) so the engine evaluates the guard exactly. The multiplication stays a storage-dependent
+ * target (at count == 0 no input overflows, so the strong condition fails), hence the SC09 unit is
+ * UNKNOWN `storage_dependent`, never CONFIRMED. Only the SC09 unit is scored here.
+ * solc version inherited from the original (0.4.x).
+ *
  * @source: https://github.com/SmartContractSecurity/SWC-registry/blob/master/test_cases/integer_overflow_and_underflow/integer_overflow_mul.sol
@@ -11,3 +20,12 @@
 
+library SafeMath {
+    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
+        uint256 c = a * b;
+        require(a == 0 || c / a == b);
+        return c;
+    }
+}
+
 contract IntegerOverflowMul {
+    using SafeMath for uint256;
     uint public count = 2;
@@ -16,3 +34,3 @@
         // <yes> <report> ARITHMETIC
-        count *= input;
+        count = count.mul(input);
     }
```

### SC09 / safemath — integer_overflow_multitx_multifunc_feasible

```diff
--- dataset/arithmetic/integer_overflow_multitx_multifunc_feasible.sol
+++ experiments/pairs/arithmetic/safemath/integer_overflow_multitx_multifunc_feasible.sol
@@ -1,2 +1,10 @@
 /*
+ * Fixed version of smartbugs-curated arithmetic/integer_overflow_multitx_multifunc_feasible.sol
+ * (pair, fix style: safemath).
+ * Fix: the unchecked `count -= input` is routed through a SafeMath-like `sub` whose body guards the
+ * subtraction with `require(b <= a)`. The internal library call is inlined (JUMP, not DELEGATECALL),
+ * so on every surviving path the guard contradicts the underflow predicate and the SC09 target is
+ * refuted. Only the SC09 unit is scored here.
+ * solc version inherited from the original (0.4.x).
+ *
  * @source: https://github.com/ConsenSys/evm-analyzer-benchmark-suite
@@ -11,3 +19,11 @@
 
+library SafeMath {
+    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
+        require(b <= a);
+        return a - b;
+    }
+}
+
 contract IntegerOverflowMultiTxMultiFuncFeasible {
+    using SafeMath for uint256;
     uint256 private initialized = 0;
@@ -24,3 +40,3 @@
         // <yes> <report> ARITHMETIC
-        count -= input;
+        count = count.sub(input);
     }
```

### SC09 / safemath — integer_overflow_multitx_onefunc_feasible

```diff
--- dataset/arithmetic/integer_overflow_multitx_onefunc_feasible.sol
+++ experiments/pairs/arithmetic/safemath/integer_overflow_multitx_onefunc_feasible.sol
@@ -1,2 +1,10 @@
 /*
+ * Fixed version of smartbugs-curated arithmetic/integer_overflow_multitx_onefunc_feasible.sol
+ * (pair, fix style: safemath).
+ * Fix: the unchecked `count -= input` is routed through a SafeMath-like `sub` whose body guards the
+ * subtraction with `require(b <= a)`. The internal library call is inlined (JUMP, not DELEGATECALL),
+ * so on every surviving path the guard contradicts the underflow predicate and the SC09 target is
+ * refuted. Only the SC09 unit is scored here.
+ * solc version inherited from the original (0.4.x).
+ *
  * @source: https://github.com/ConsenSys/evm-analyzer-benchmark-suite
@@ -11,3 +19,11 @@
 
+library SafeMath {
+    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
+        require(b <= a);
+        return a - b;
+    }
+}
+
 contract IntegerOverflowMultiTxOneFuncFeasible {
+    using SafeMath for uint256;
     uint256 private initialized = 0;
@@ -21,3 +37,3 @@
         // <yes> <report> ARITHMETIC
-        count -= input;
+        count = count.sub(input);
     }
```

### SC09 / safemath — timelock

```diff
--- dataset/arithmetic/timelock.sol
+++ experiments/pairs/arithmetic/safemath/timelock.sol
@@ -1,2 +1,11 @@
 /*
+ * Fixed version of smartbugs-curated arithmetic/timelock.sol
+ * (pair, fix style: safemath).
+ * Fix: the unchecked `lockTime[msg.sender] += _secondsToIncrease` is routed through a SafeMath-like
+ * `add` whose body guards the sum with `require(c >= a)`. The internal library call is inlined (JUMP,
+ * not DELEGATECALL). As with every pre-0.8 addition guard, the sum stays a storage-dependent target
+ * (at lockTime == 0 no increment overflows, so the strong condition fails), hence the SC09 unit is
+ * UNKNOWN `storage_dependent`, never CONFIRMED. Only the SC09 unit is scored here.
+ * solc version inherited from the original (0.4.x).
+ *
  * @source: https://github.com/sigp/solidity-security-blog
@@ -8,4 +17,13 @@
  pragma solidity ^0.4.10;
- 
+
+ library SafeMath {
+     function add(uint256 a, uint256 b) internal pure returns (uint256) {
+         uint256 c = a + b;
+         require(c >= a);
+         return c;
+     }
+ }
+
  contract TimeLock {
+     using SafeMath for uint256;
 
@@ -21,3 +39,3 @@
          // <yes> <report> ARITHMETIC
-         lockTime[msg.sender] += _secondsToIncrease;
+         lockTime[msg.sender] = lockTime[msg.sender].add(_secondsToIncrease);
      }
```

