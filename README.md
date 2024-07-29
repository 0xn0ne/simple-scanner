# Simple Scanner

Simple Scanner，尽可能简单化的扫描，搭载 DNS 反射功能。

## 依赖

- Python 3.11+ 64bit

```bash
usage: ss.py [-h] -t TARGETS [TARGETS ...] [-m MODULE [MODULE ...]] [-p PROCESS_NUMBER] [-o OUTPUT_FORMAT] [-i INTERVAL] [-is] [-dps]

    ███████╗██╗███╗   ███╗██████╗ ██╗     ███████╗    ███████╗
    ██╔════╝██║████╗ ████║██╔══██╗██║     ██╔════╝    ██╔════╝
    ███████╗██║██╔████╔██║██████╔╝██║     █████╗      ███████╗
    ╚════██║██║██║╚██╔╝██║██╔═══╝ ██║     ██╔══╝      ╚════██║
    ███████║██║██║ ╚═╝ ██║██║     ███████╗███████╗    ███████║
    ╚══════╝╚═╝╚═╝     ╚═╝╚═╝     ╚══════╝╚══════╝    ╚══════╝
    v0.2.4
    by 0xn0ne, https://github.com/0xn0ne/simple-scanner

                        扫描目标，或者扫描目标列表文件（样例："127.0.0.1:80"）
  -m MODULE [MODULE ...], --module MODULE [MODULE ...]
                        使用的漏洞插件，默认扫描所有插件（样例："CVE-2014-*"）
  -p PROCESS_NUMBER, --process-number PROCESS_NUMBER
                        调用进程数，默认 5 个进程
  -o OUTPUT_FORMAT, --output-format OUTPUT_FORMAT
                        输出的文件格式，可用格式有 json、csv，默认输出 csv 格式
  -i INTERVAL, --interval INTERVAL
                        向进程池提交任务之间的时间间隔（以秒为单位）。
  -is, --is-silent      静默模式：开启后控制台上不会输出测试的信息
  -dps, --disable-port-scan
                        禁用端口扫描。注意：如果端口未打开，发送PAYLOAD的程序将导致无意义的响应等待时间
```

```bash
$ python3 ss.py -t 192.168.245.128
[+] CVE-2014-4210 url: http://192.168.245.128:7001/, 信息: http://192.168.245.128:7001/uddiexplorer/SearchPublicRegistries.jsp
[+] CVE-2016-0638 url: t3://192.168.245.128/, 信息: success
[+] Weblogic Console Login Page url: http://192.168.245.128:7001/, 信息: http://192.168.245.128:7001/console/login/LoginForm.jsp
3/3 [████████████████████████████████████████████████████] 00:02<00:00, 1.23it/s
```

## TODOLIST

- 添加配置文件控制，方便使用默认配置操作；
- 允许配置文件输入插件参数，如用户名字典、密码字典、指纹等；
- 优化 NET ECHO 功能逻辑。

## CHANGE LOG

### 0.2.4 2024/07/29

- 增加端口扫描，优化执行逻辑
- 删除DNSLOG功能，还不完善

### 0.2.3 2024/05/18

- 默认禁用DNSLOG功能；
- 增加requirements.txt方便部署；
- 优化返回数据，尽可能多保留数据到CSV。
