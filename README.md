Xiaomi bindkey extractor
========================
This tool is a port of https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor to Go. Build binary is cross 
platform and only a few mbs.

You need to first pair your Xiaomi BLE device with their official app. This provision process will make your BLE device 
generate a *bindkey*. You can interact with the device directly using this bindkey, i.e. the app isn't required from 
this point onwards.


Usage
-----
Syntax: `xiaomicloudtoken [opt] <username> <password>`

The `username` can be your user ID or email.


Build from source
-----------------
You need to have [Go](https://go.dev/dl) installed. Then:

```
git clone https://github.com/imacks/xiaomicloudtoken .
go build -ldflags "-s -w"
```
