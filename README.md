# Dumpulator-IDA
Currently proof-of-concept

This project is a small POC plugin for launching dumpulator emulation within IDA, passing it addresses from your IDA view using the context menu.

Find the amazing dumpulator project by @mrexodia at [link](https://github.com/mrexodia/dumpulator)

## Configure
You can now go to Edit -> Plugins -> Dumpulate and this will prompt you to select your dump file

## Currently only allows you to:
For the example file found [here](https://github.com/mrexodia/dumpulator/releases/download/v0.0.1/StringEncryptionFun_x64.dmp) you can

- Set your call address and choose a number of arguments to pass
- Right click an address, choose select argument, and then select which arg you'd like to pass it as
- Right click and select allocate temporary space for any arg you'd like to monitor the output of
- Finally right click and choose emulate function

This will emulate the chosen call address, pass your assigned arguments, and output the passed addresses as strings if possible

## Limitations
If you right click the variable within the function call line, you'll get the wrong address, so you have to be selecting it directly by clicking through to it.

Additionally, I haven't yet coded this to support stack variables. I will need to confirm how that is coded with dumpulator, before I try and impliment.

*The biggest limitation is that that's insanely buggy*

## Future Work
I feel that this could be more dynamic, and there are a lot more options and scenarios to account for than the basic string decryption POC.

I will look into more dynamic ways of building your function argument structure, as well as ways of controlling what you monitor and how it is outputted, potentially with enums or comments as an option