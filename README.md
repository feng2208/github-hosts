# github-hosts
拥有以下功能：

- [加速github](https://github.com/feng2208/github-hosts)([mirror](https://gh.feng2208.gleeze.com/))，相关说明(https://feng2208.gleeze.com/posts/github-speed-up.html)
- [国内注册使用spotify](https://feng2208.gleeze.com/posts/spotify.html)，无广告，无14天限制，可以任意切歌。
- 更改苹果app store地区


## 加速github
从`命令提示符`启动：

### 谷歌浏览器

```bat
"C:\Program Files\Google\Chrome\Application\chrome.exe" --host-rules="MAP github.com octocaptcha.com, MAP github.githubassets.com yelp.com, MAP *.githubusercontent.com githubusercontent.com" --host-resolver-rules="MAP octocaptcha.com 20.27.177.113, MAP yelp.com 199.232.240.116, MAP githubusercontent.com 199.232.176.133"

```


### 微软Edge浏览器
先在浏览器`设置`-`系统和性能`关闭`启动增强`。

```bat
"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --host-rules="MAP github.com octocaptcha.com, MAP github.githubassets.com yelp.com, MAP *.githubusercontent.com githubusercontent.com" --host-resolver-rules="MAP octocaptcha.com 20.27.177.113, MAP yelp.com 199.232.240.116, MAP githubusercontent.com 199.232.176.133"

```


## 加速其他网站
1. [安装mitmproxy](https://mitmproxy.org/)
2. [下载github-hosts](https://github.com/feng2208/github-hosts/archive/refs/heads/main.zip) 并解压
3. 双击运行`github-hosts.bat`打开代理
4. 以管理员身份运行`install-CA.bat`信任证书
5. 设置浏览器或其他程序使用http代理 `127.0.0.1:8180`

