# Tasks for dev team

- [ ] finish work on HAL
  - [ ] AES peripheral
  - [ ] Temperature sensor peripheral
  - [ ] interrupts + DMA
  - [ ] integration tests for peripherals
  - [ ] write docs/usage for HAL
  - [ ] potentially remove references to UIUC? I don't think we used any of their code
  - [ ] alternatively, upstream changes to UIUC repo
  - [ ] convert all peripherals to use error handling w/ thiserror

- [ ] write gen_secrets code
  - [ ] finalize protocol design + review crypto

- [ ] write design
  - [ ] write host communication
  - [ ] design + write inter-board communication
  - [ ] write tests (infra team responsible?)
  - [ ] sidechannel mitigations (vendor crypto libraries? hardware AES?)
