# sniffer-tool

A full packet sniffer tool using [ys-sniffer](https://github.com/ys4e/ys-sniffer) and [protoshark](https://github.com/ys4e/protoshark).

See the frontend interface at [KingRainbow44/Packet-Visualizer](https://github.com/KingRainbow44/Packet-Visualizer), or use any other supported frontend!

## Features

- Decode with given packet IDs and protobuf messages
  - Add `all.proto` and `protocol_definition.json` (packet IDs file, `name -> id` mapping) to current working directory
  - A dumped `dump.proto` with `// cmdId = <id>` comments can be used as `all.proto` directly; without
    `protocol_definition.json` the packet IDs are read from those comments
  - IDs shared by several messages are resolved per packet (the candidate that decodes cleanly wins)
  - Fields missing from the definitions are kept, schema-less, as `#<field number>`
- Decode without any schema
  - This is the fallback if no `all.proto` file is specified, or the message isn't included in it
- Command line interface
  - Type anything into the terminal to see a list of commands

## Usage

```
sniffer-tool [--device <index|name|description>] [--log <file.jsonl>] [--ports <22101-22102,...>]
             [--save <file.pcap>] [--replay <file.pcap>] [--key <private_key.pem>]...
             [--session-key <key.bin>]...
```

- `--device` picks the capture device without prompting (an unknown value lists the devices)
- `--log` also writes every decoded packet to a file, one JSON object per line
- `--ports` sets the game server's UDP ports (default `22101-22102`)
- `--save` writes the raw capture to a pcap file; `--replay` decodes a saved capture offline
- `--key` adds an RSA private key (PEM) for the login handshake; `keys/*.pem` are loaded too
- `--session-key` adds a candidate session key (4096 raw bytes); `keys/*.bin` are loaded too, also
  while running, and the `key <file>` console command does the same

IPv4 and IPv6 traffic are both handled. Setting `YS_DUMP_DIR` dumps every reassembled, still encrypted
message to that directory for analysis.

Start the sniffer **before** logging in: the session key is recovered from the login handshake.

## Session keys from the game (7.x)

Since 7.x (seen on 7.1.0), the login response body carries an extra encryption layer, so the session
key can no longer be brute-forced from the handshake. It can be read from the running game instead:

1. Start the sniffer (with `--save`, to keep the raw capture) before logging in.
2. After logging in, run `python tools/keyscan.py` **as administrator** from the sniffer's working
   directory. It only reads the game's memory and writes candidate keys to `keys/`.
3. The sniffer picks up `keys/*.bin`, finds the one that decrypts the packets, and decodes the packets
   it held back so far. A saved capture can also be decoded later with `--replay`.

## Building

Requires a nightly toolchain (pinned in `rust-toolchain.toml`, needed by `ys-kcp`) and Npcap.
Linking needs `wpcap.lib` from the [Npcap SDK](https://npcap.com/#download); point `LIBPCAP_LIBDIR`
at its `Lib/x64` folder. Without the SDK, an import library can be made from the installed DLL:

```
dumpbin /exports C:\Windows\System32\Npcap\wpcap.dll   # write the names into wpcap.def
lib /def:wpcap.def /machine:x64 /out:wpcap.lib
```

## See Other

- https://github.com/ys4e/ys-sniffer - Underlying `pcap` wrapper & packet sniffer
- https://github.com/ys4e/protoshark - Arbitrary protobuf message decoder
- https://github.com/andrewhickman/prost-reflect - Rust reflective protobuf message decoding
- https://github.com/andrewhickman/protox - `.proto` compiler in Rust

---

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.