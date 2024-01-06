# simple-scanner

yep. try a faster and simpler scanning framework.

```bash
usage: ss.py [-h] -t TARGETS [TARGETS ...] [-m MODULE [MODULE ...]] [-p PROCESS_NUMBER] [-o OUTPUT_FORMAT] [-s]

    ███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
    ██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
    ███████╗    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
    ╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
    ███████║    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
    ╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
    v0.1.1
    by 0xn0ne, https://github.com/0xn0ne/simple-scanner

options:
  -h, --help            show this help message and exit
  -t TARGETS [TARGETS ...], --targets TARGETS [TARGETS ...]
                        扫描目标，或者扫描目标列表文件（样例："127.0.0.1:80"）
  -m MODULE [MODULE ...], --module MODULE [MODULE ...]
                        使用的漏洞插件，默认扫描所有插件（样例："CVE-2014-*"）
  -p PROCESS_NUMBER, --process-number PROCESS_NUMBER
                        调用进程数，默认 5 个进程
  -o OUTPUT_FORMAT, --output-format OUTPUT_FORMAT
                        输出的文件格式，可用格式有 json、csv，默认输出 csv 格式
  -s, --is-silent       静默模式：开启后控制台上不会输出测试的信息
```

```bash
$ python3 ss.py -t 192.168.245.128
[+] CVE-2014-4210 url: http://192.168.245.128:7001/, 信息: http://192.168.245.128:7001/uddiexplorer/SearchPublicRegistries.jsp
[+] CVE-2016-0638 url: t3://192.168.245.128/, 信息: success
[+] Weblogic Console Login Page url: http://192.168.245.128:7001/, 信息: http://192.168.245.128:7001/console/login/LoginForm.jsp
3/3 [████████████████████████████████████████████████████] 00:02<00:00, 1.23it/s
```
