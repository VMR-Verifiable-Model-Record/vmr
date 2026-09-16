# KHALM-VMR demo: data governance

The KHALM-VMR demo record pins this document by its SHA-256, as
`data_governance.documentation_hash` (`docs/demo/record-manifest.json`).

- **The data.** The training input, `docs/demo/training-frames.khalmtrn`, is
  16 frames generated deterministically by the engine's test frame
  generator, `kt_make_frame` in `tests/test_util.hpp`, which the C++ tests
  use; the demo takes 16 of them (frames 1 to 16). They are synthetic and
  hold no personal data.
- **Illustrative claims.** The record's `data_residency` and
  `collection_period` are illustrative. So are its issuer (`issuer_id`,
  `issuer_name`), its training period (`training_started_at`,
  `training_ended_at`) and its deployment (`deployment_id`, `deployed_at`,
  `deployed_by`, `inference_boundary`): the demo has no real issuer, training
  run or deployment. Its `accelerator_software` is named illustrative in
  `docs/demo/software-environment.json`.
- **No bias examination.** No examination for possible biases (Art. 10(2)(f)
  of Regulation (EU) 2024/1689) was done, as there is nothing to examine.
- **No real setting.** The data represents no real setting (Art. 10(3) and
  10(4)), and the model must not be used for any decision.
- **Not evidence of compliance.** This document is not evidence of compliance
  with Art. 10.
