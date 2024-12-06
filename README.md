# Miner-Detector
Hacky method to detect miners running in memory


## How it works
By taking a snapshot of all processes currently running in the system, we can open them and look at the private memory usage of each process, and considering most miners will take a lot of usage in terms of both CPU cycles and private bytes to run them in memory, we can use that against them to spot irregular processes.

This can detect the Unam Miner, and presumably most currently on the market.
