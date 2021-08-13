Inspired from [hblock](https://github.com/hectorm/hblock), and extension of that project for Windows ecosystem.

## What is this for?

A python script that gets a list of domains that serve ads, tracking scripts and malware from [multiple sources](./SOURCES.md) and creates a [hosts file](https://en.wikipedia.org/wiki/Hosts_(file)), that prevents your system from connecting to them.

Refer this [Website](https://hblock.molinero.dev/) to check if you are set up with hBlock correctly.

## Installation

Clone this repository and run the main.py script with administrative privileges.
```
python3 main.py
```

## Temporarily disable hBlock

Sometimes you may need to temporarily disable the ad-Blocker, a quick option is to restore the old hosts file without any blocked domains by running the following
command:

```
python3 main.py --restore
```
