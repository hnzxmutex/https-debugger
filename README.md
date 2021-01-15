# linux 下的 https 抓包思路&工具

## 实现思路

二选一

* LD_PRELOAD 去 hook 底层的 socket 方法(未实现)
* iptables 做流量转发

## iptables 做流量转发

需要两台机器才能实现

### 机器 1 执行

```bash
#打开流量转发功能
sysctl -w net.ipv4.ip_forward=1

#流量转发配置，172.19.0.1所有发到443端口的请求转发到172.19.0.2:30080
iptables -t nat -A POSTROUTING -p tcp --dport 443 -j SNAT --to-source 172.19.0.1
iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination 172.19.0.2:30080
```

### 不使用的时候还原转发规则,清除规则

```bash
iptables -t nat -F
```

### 机器 2 监听流量

```bash
./bin/https-debugger -l 30080
```
