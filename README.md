# Dumpulator-IDA
Currently proof-of-concept

This project is a small POC plugin for launching dumpulator emulation within IDA, passing it addresses from your IDA view using the context menu.

Find the amazing dumpulator project by @mrexodia at [link](https://github.com/mrexodia/dumpulator)

## Configure
You can now go to Edit -> Plugins -> Dumpulate and this will prompt you to select your dump file

## Currently only allows you to:
For the example file found [here](https://github.com/mrexodia/dumpulator/releases/download/v0.0.1/StringEncryptionFun_x64.dmp) you can

- Set your call address
- Right click an address and select Dumpulator run with single arg

This will emulate the chosen call address, and pass the single value as the only argument.

## Future Work
Dumpulator is a very dynamic solution so the emulation is going to be different for different function. For example, in this proof-of-concept, it only works for a function that takes in a buffer, and a single address.

Once dumpulator's features are expanded, I'd like to create a somewhat dynamic solution for this plugin, whereby the plugin can recognise the number of args in a function, and let you map values and addresses to those args, then emulate.