1. Make sure cargo and openocd are installed
2. `cargo run --release`
3. To debug:
```
$ openocd -f run.cfg &
$ gdb
> target remote localhost:3333
```
