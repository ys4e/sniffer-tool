# sniffer-tool

A full packet sniffer tool using [ys-sniffer](https://github.com/ys4e/ys-sniffer) and [protoshark](https://github.com/ys4e/protoshark).

See the frontend interface at [KingRainbow44/Packet-Visualizer](https://github.com/KingRainbow44/Packet-Visualizer), or use any other supported frontend!

## Features

- Decode with given packet IDs and protobuf messages
  - Add `all.proto` and `protocol_definition.json` (packet IDs file, `name -> id` mapping) to current working directory
- Decode without any schema
  - This is the fallback if no `all.proto` file is specified, or the message isn't included in it
- Command line interface
  - Type anything into the terminal to see a list of commands

## See Other

- https://github.com/ys4e/ys-sniffer - Underlying `pcap` wrapper & packet sniffer
- https://github.com/ys4e/protoshark - Arbitrary protobuf message decoder
- https://github.com/andrewhickman/prost-reflect - Rust reflective protobuf message decoding
- https://github.com/andrewhickman/protox - `.proto` compiler in Rust

---

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.