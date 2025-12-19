
- 加速 GitHub：[https://github.com/feng2208/github-hosts](https://github.com/feng2208/github-hosts)
- 备用：[https://feng2208.cloudns.cl/github-hosts/](https://feng2208.cloudns.cl/github-hosts/)


## 加速github
从`命令提示符`启动，在执行命令前**先关闭**浏览器。

### 谷歌浏览器
支持 140 及以下版本。

Windows
```bat
"C:\Program Files\Google\Chrome\Application\chrome.exe" --host-rules="MAP github.com octocaptcha.com, MAP github.githubassets.com yelp.com, MAP *.githubusercontent.com yelp.com" --host-resolver-rules="MAP octocaptcha.com 20.200.245.247, MAP yelp.com 146.75.48.116"
```

macOS
```sh
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --host-rules="MAP github.com octocaptcha.com, MAP github.githubassets.com yelp.com, MAP *.githubusercontent.com yelp.com" --host-resolver-rules="MAP octocaptcha.com 20.200.245.247, MAP yelp.com 146.75.48.116"
```
