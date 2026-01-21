
- 加速 GitHub：[https://github.com/feng2208/github-hosts](https://github.com/feng2208/github-hosts)
- 备用：[https://feng2208.cloudns.cl/github-hosts/](https://feng2208.cloudns.cl/github-hosts/)


## 加速github
从`命令提示符`启动，在执行命令前**先关闭**浏览器。

### 谷歌浏览器
支持 140 及以下版本，141 及以上看下面说明。

Windows
```bat
"C:\Program Files\Google\Chrome\Application\chrome.exe" --host-rules="MAP github.com octocaptcha.com, MAP github.githubassets.com www.yelp.com, MAP *.githubusercontent.com www.yelp.com"
```

macOS
```sh
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --host-rules="MAP github.com octocaptcha.com, MAP github.githubassets.com www.yelp.com, MAP *.githubusercontent.com www.yelp.com"
```

### 浏览器及其他程序
[下载 github-hosts](https://github.com/feng2208/github-hosts/archive/refs/heads/main.zip) ([备用](https://feng2208.cloudns.cl/gh/feng2208/github-hosts/archive/refs/heads/main.zip)) 解压出来，双击打开 `github-hosts.vbs`，点击 `是` 安装证书。

浏览器及其他程序就可以使用 github-hosts 加速了。

