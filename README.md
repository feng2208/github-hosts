# github-hosts

- [加速github](https://github.com/feng2208/github-hosts)([mirror](https://feng2208.pages.dev/github-hosts))
- [国内注册使用spotify](https://feng2208.pages.dev/posts/spotify)，无广告可以任意切歌。



## 加速github
### 谷歌浏览器

从`命令提示符`启动：

```bat
"C:\Program Files\Google\Chrome\Application\chrome.exe" --host-rules="MAP github.com octocaptcha.com, MAP github.githubassets.com yelp.com, MAP *.githubusercontent.com githubusercontent.com" --host-resolver-rules="MAP octocaptcha.com 20.27.177.113, MAP yelp.com 199.232.240.116, MAP githubusercontent.com 199.232.176.133"
```

### 微软Edge浏览器
```bat
"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --host-rules="MAP github.com octocaptcha.com, MAP github.githubassets.com yelp.com, MAP *.githubusercontent.com githubusercontent.com" --host-resolver-rules="MAP octocaptcha.com 20.27.177.113, MAP yelp.com 199.232.240.116, MAP githubusercontent.com 199.232.176.133"
```


### git命令
- 首先启动http代理
- 设置`git`使用代理`git config --global http.proxy http://127.0.0.1:8180`
- 使用`git`命令，类似：
  ```
  git -c http.sslVerify=false clone https://github.com/feng2208/github-hosts.git
  ```
- 取消使用代理：`git config --global --unset http.proxy`


## http代理
1. [下载github-hosts](https://github.com/feng2208/github-hosts/archive/refs/heads/main.zip) 并解压
2. 双击`github-hosts.bat`打开代理
3. 以管理员身份运行`install-CA.bat`信任证书
4. 运行`set-proxy.bat`和`unset-proxy.bat`设置或取消系统代理
5. 不使用系统代理的程序自行设置 `127.0.0.1:8180`

