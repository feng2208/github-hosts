# github-hosts
[加速github](https://github.com/feng2208/github-hosts)([mirror](https://gh.feng2208.gleeze.com/))，
以及在[国内注册使用spotify](https://feng2208.gleeze.com/posts/spotify.html)。

相关说明(https://feng2208.gleeze.com/posts/github-speed-up.html)

## 谷歌浏览器
从`powershell`命令行启动：

```powershell
# 电信网络
 & "C:\Program Files\Google\Chrome\Application\chrome.exe" --host-rules="MAP github.com octocaptcha.com:443, MAP github.githubassets.com yelp.com:443, MAP *.githubusercontent.com yelp.com:443" --host-resolver-rules="MAP octocaptcha.com 20.27.177.113, MAP yelp.com 151.101.40.116"

```

```powershell
# 其他网络
 & "C:\Program Files\Google\Chrome\Application\chrome.exe" --host-rules="MAP github.com octocaptcha.com:443, MAP github.githubassets.com yelp.com:443, MAP *.githubusercontent.com yelp.com:443" --host-resolver-rules="MAP octocaptcha.com 20.27.177.113, MAP yelp.com 151.101.232.116"

```




## 微软Edge浏览器
先在浏览器`设置`-`系统和性能`关闭`启动增强`。

```powershell
# 电信网络
 & "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --host-rules="MAP github.com octocaptcha.com:443, MAP github.githubassets.com yelp.com:443, MAP *.githubusercontent.com yelp.com:443" --host-resolver-rules="MAP octocaptcha.com 20.27.177.113, MAP yelp.com 151.101.40.116"

```

```powershell
# 其他网络
 & "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --host-rules="MAP github.com octocaptcha.com:443, MAP github.githubassets.com yelp.com:443, MAP *.githubusercontent.com yelp.com:443" --host-resolver-rules="MAP octocaptcha.com 20.27.177.113, MAP yelp.com 151.101.232.116"

```
