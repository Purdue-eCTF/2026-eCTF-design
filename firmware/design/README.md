# Design

Main HSM firmware.

## Building and Running
1. Make sure cargo and openocd are installed
2. `cargo run --release`
3. To debug:
```
$ openocd -f run.cfg &
$ gdb
> target remote localhost:3333
```

TODO: does this still work with bootloader? if not, update instructions

TODO: integrate w/ infra

## Files
- `src/`
  - `context.rs`: structs for managing flash and UART as well as initializing the HSM
  - `crypto.rs`: helper functions implementing the cryptographic protocol
  - `file.rs`: functions and structs for files and associated metadata
  - `listen.rs`: helpers for responding to Interrogate and Receive commands when in listen mode
  - `main.rs`: main loop for the firmware and handlers for host commands
  - `message.rs`: structs and helpers for the communication protocol
  - `protocol.rs`: functions and structs for handling a Receive command from host
  - `salt.rs`: functions and struct for deriving salts on boot
  - `secrets.rs`: secrets and helpers for obtaining secrets
- `openocd/run.cfg`:
- `build.rs`: build script to include generated secrets in the firmware
- `link.x`:
- `memory.x`: