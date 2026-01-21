Set objShell = CreateObject("WScript.Shell")

' objShell.Run command, window_style, wait_on_return
' 参数说明：
' 0 = 隐藏窗口
' 1 = 显示窗口
' True = 等待 PowerShell 运行完再结束 VBS
objShell.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -File "".\_setup.ps1""", 0, False
