
# 🖥️ NimProxy

A Simple Dll Proxy Generator Written in **Nim**.

## ❓ Usage
After Having Compiled **NimProxy**, You Can Compile it With This Command
```
$ nim c -d:release nimproxy.nim
```
To Start Using **NimProxy** Run This
```
$ ./nimproxy.exe -d <DLL_PATH> -o <OUTPUT_PATH>
```
## ✨ Credits
[@S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t) For Most of the **EAT** Parsing Code.
## 👀 Examples
```
$ ./nimproxy.exe -d C:\Windows\System32\advapi32.dll -o main.c
```
```
$ ./nimproxy.exe -d C:\Windows\System32\ntdll.dll -o main.c
```
