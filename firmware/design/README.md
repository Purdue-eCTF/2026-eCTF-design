# Design

Main HSM firmware.

## Building and Running
1. Make sure cargo and openocd are installed
2. `cargo run --release`
3. To debug:
```
$ openocd -f openocd/run.cfg
$ gdb -x run.gbd # in another tab
```

The name of the device in run.sh varies between platforms, so you will likely need to update it.

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
- `link.x`: flash layout as described by functional requirements
- `memory.x`: locations of flash + memory

## Crates

- `firmware/common`: code shared between build.rs and HSM code
- `firmware/design_macros`: proc-macros for anti-glitching
