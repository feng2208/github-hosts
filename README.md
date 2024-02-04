# github-hosts
加速github。

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

## mitmproxy代理
安装[mitmproxy](https://www.mitmproxy.org/)，下载[github-hosts.py](https://raw.githubusercontent.com/glue208/github-hosts/main/github-hosts.py)到`D:\mitm\`。运行`mitmdump`，电信网络在后面加上：` --set dianxin=true`
```bat
mitmdump.exe -s D:/mitm/github-hosts.py -p 8080
```
设置系统或软件使用HTTP代理`127.0.0.1:8080`。

根据[mitmproxy的说明](https://docs.mitmproxy.org/stable/concepts-certificates/#installing-the-mitmproxy-ca-certificate-manually)安装CA证书，或者用已配置代理的浏览器打开 http://mitm.it/ 并按提示安装。

