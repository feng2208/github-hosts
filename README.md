# github-hosts
加速github。

在桌面或者开始菜单找到`谷歌浏览器`快捷方式，右击图标选择`属性`，然后在`目标`栏的后面增加以下参数：
```
 --host-rules="MAP github.com octocaptcha.com:443, MAP github.githubassets.com www.yelp.com:443, MAP *.githubusercontent.com www.yelp.com:443" --host-resolver-rules="MAP octocaptcha.com 20.27.177.113, MAP www.yelp.com 151.101.40.116"
```
注意参数前面有空格。运行的时候如果提示`您使用的是不受支持的命令行标记`，不用管它。

如果不是电信网络，使用下面的可能更好：
```
 --host-rules="MAP github.com octocaptcha.com:443, MAP *.githubusercontent.com github.githubassets.com:443" --host-resolver-rules="MAP octocaptcha.com 20.27.177.113"
```
