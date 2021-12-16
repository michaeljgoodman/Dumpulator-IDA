# Dumpulator-IDA
Currently proof-of-concept

This project is a small POC plugin for launching dumpulator emulation within IDA, passing it addresses from your IDA view using the context menu.

Find the amazing dumpulator project by @mrexodia at [link](https://github.com/mrexodia/dumpulator)

## Disclaimer
The plugin currently just has a .dmp file address hardcoded into it, in such a way that said file must be in the same folder as your binary.

## Currently only allows you to:
- Set your call address
- Right click an address and select Dumpulator run with single arg

This will emulate the chosen call address, and pass the single value as the only argument.