## godot-key-finder
Is just a proof of concept program, which purpose is to find an encryption key
embedded into a godot game by brute-forcing every contiguous 32-byte sequence as
the decryption key. If the key is found then program stops and prints the key.

This is tested work on linux & windows binaries, and as said only a proof of concept.
If this doesn't work on android, macos, etc, without changes, then so be it.
This is not meant to be a very well supported project.

## Building

1. This program is built with rust so you need to download the rust compiler
1. Run 'cargo build --release`
1. The built binary can be found in `target/release/godot-find`.
1. Run `cd ./target/release/` to get into the directory

## Usage

Running these commands can you give you more additional information for the commands.
```sh
./godot-find help
./godot-find help pck
./godot-find help embedded
```

### Brute force an embedded binary.
```sh
./godot-find -j <num-of-cores-to-use> embedded --bin <path-to-binary>
```

### Brute force a separated pck & binary file.
```sh
./godot-find -j <num-of-cores-to-use> pck --pck <path-to-pck> --bin <path-to-binary>
```
