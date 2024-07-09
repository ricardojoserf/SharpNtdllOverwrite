# SharpNtdllOverwrite

Overwrite ntdll.dll's ".text" section using a clean version of the DLL. 

It can help to evade security measures that install API hooks such as EDRs. 

The unhooked version of the DLL can be obtained from:

- A DLL file already on disk - For example "C:\Windows\System32\ntdll.dll".
- The KnownDlls folder - "\KnownDlls\ntdll.dll" for 64-bit processes and "\KnownDlls32\ntdll.dll" for 32-bit processes.
- A process created in debug mode - Processes created in suspended or debug mode have a clean ntdll.dll.
- A URL - Similar to the first option, but the file is downloaded from a web server.

---------------------------------

### From disk

Get the clean ntdll.dll from disk. You can specify a file path or use the default value "C:\Windows\System32\ntdll.dll":

```
SharpNtdllOverwrite.exe disk [FILE_PATH]
```

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/ntdll_overwrite/Screenshot_1.png)

### From KnownDlls folder

Get the clean ntdll.dll from the KnownDlls folder:

```
SharpNtdllOverwrite.exe knowndlls
```

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/ntdll_overwrite/Screenshot_2.png)

### From a debug process

Get the clean ntdll.dll from a new process created with the DEBUG_PROCESS flag. You can specify a binary to create the process or use the default value "C:\Windows\System32\calc.exe":

```
SharpNtdllOverwrite.exe debugproc [BINARY_PATH]
```

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/ntdll_overwrite/Screenshot_3.png)

### From a URL

Get the clean ntdll.dll from a URL. The default value is "http://127.0.0.1:80/ntdll.dll":

```
SharpNtdllOverwrite.exe download [URL]
```

![img4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/ntdll_overwrite/Screenshot_4.png)


-------------------------------

### Sources

- [Maldev Academy](https://maldevacademy.com/) explains this technique in one of their lessons using code written in C/C++.


-------------------------------

### Other links

- Python implementation: [pyNtdllOverwrite](https://github.com/ricardojoserf/pyNtdllOverwrite)

- Golang implementation: [goNtdllOverwrite](https://github.com/ricardojoserf/goNtdllOverwrite)
