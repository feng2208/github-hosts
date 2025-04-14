
- 加速github：https://github.com/feng2208/github-hosts
- 镜像：https://feng2208.pages.dev/github-hosts


## 加速github
从`命令提示符`启动，在执行命令前**先关闭**浏览器。

### 谷歌浏览器
Windows
```bat
"C:\Program Files\Google\Chrome\Application\chrome.exe" --host-rules="MAP github.com octocaptcha.com, MAP github.githubassets.com yelp.com, MAP *.githubusercontent.com yelp.com" --host-resolver-rules="MAP octocaptcha.com 20.27.177.113, MAP yelp.com 199.232.240.116"
```

macOS
```sh
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --host-rules="MAP github.com octocaptcha.com, MAP github.githubassets.com yelp.com, MAP *.githubusercontent.com yelp.com" --host-resolver-rules="MAP octocaptcha.com 20.27.177.113, MAP yelp.com 199.232.240.116"
```


### 微软Edge浏览器
在浏览器`设置`-`系统和性能`将`启动增强`关闭。

```bat
"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --host-rules="MAP github.com octocaptcha.com, MAP github.githubassets.com yelp.com, MAP *.githubusercontent.com yelp.com" --host-resolver-rules="MAP octocaptcha.com 20.27.177.113, MAP yelp.com 199.232.240.116"
```


### git命令
- [下载github-hosts](https://github.com/feng2208/github-hosts/archive/refs/heads/main.zip) 解压，运行`github-hosts.bat`
- 设置`git`使用代理
  ```
  git config --global http.proxy http://127.0.0.1:8180`
  ```
- 使用`git`命令，类似
  ```
  git -c http.sslVerify=false clone https://github.com/feng2208/github-hosts.git
  ```
- 取消使用代理
  ```
  git config --global --unset http.proxy`
  ```

