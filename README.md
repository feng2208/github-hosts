# github-hosts
[加速github](https://github.com/feng2208/github-hosts)([mirror](https://github-hosts.onrender.com/))。

相关说明(https://feng2208.onrender.com/posts/github-speed-up.html)

## 谷歌浏览器
从命令行启动：
```bat
"C:\Program Files\Google\Chrome\Application\chrome.exe" --host-rules="MAP github.com octocaptcha.com:443, MAP *.githubusercontent.com github.githubassets.com:443" --host-resolver-rules="MAP octocaptcha.com 20.27.177.113"
```
如果提示`您使用的是不受支持的命令行标记`，不用管它。

电信网络使用下面的可能更好：
```bat
"C:\Program Files\Google\Chrome\Application\chrome.exe" --host-rules="MAP github.com octocaptcha.com:443, MAP github.githubassets.com www.yelp.com:443, MAP *.githubusercontent.com www.yelp.com:443" --host-resolver-rules="MAP octocaptcha.com 20.27.177.113, MAP www.yelp.com 151.101.40.116"
```

