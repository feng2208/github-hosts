
# ==========================================
# 安装 CA 证书
# ==========================================

# CA 证书 .cer 文件实际路径
$CertFileName = "mitmproxy-ca-cert.cer"
$CertFilePath = Join-Path -Path $HOME -ChildPath ".mitmproxy\$CertFileName"
$MitmdumpExe = "./bin/mitmdump.exe"

try {
    # 1. 验证文件是否存在
    if (-not (Test-Path $CertFilePath)) {
        Start-Process -FilePath $MitmdumpExe -ArgumentList "-p 10010"
        Start-Sleep -Seconds 3
        Get-Process mitmdump -ErrorAction SilentlyContinue | Stop-Process -Force
    }

    # 2. 读取证书信息（获取指纹）
    $certObj = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertFilePath)
    $thumbprint = $certObj.Thumbprint
    $subject = $certObj.Subject

    Write-Host "正在检测证书: $subject" -ForegroundColor Cyan
    Write-Host "证书指纹: $thumbprint" -ForegroundColor Gray

    # 3. 定义当前用户的根证书存储路径
    $userRootStorePath = "Cert:\CurrentUser\Root\$thumbprint"

    # 4. 检查是否已安装
    if (Test-Path $userRootStorePath) {
        # --- 情况 A: 已安装 ---
        Write-Host "`n[状态] 该证书已存在于您的信任列表中。" -ForegroundColor Green
        Write-Host "无需进行任何操作。" -ForegroundColor Gray
    }
    else {
        # --- 情况 B: 未安装，开始安装 ---
        Write-Host "`n[状态] 未检测到该证书。" -ForegroundColor Yellow
        Write-Host "正在安装到当前用户受信任根证书列表..." -ForegroundColor Cyan
        
        # 提示用户注意弹窗
        Write-Host ">>> 注意：Windows 可能会弹出一个安全警告窗口询问是否安装证书，请点击【是(Y)】。 <<<" -ForegroundColor Magenta -BackgroundColor Black

        # 执行导入
        # Import-Certificate 会自动弹出 Windows 安全警告（这是系统强制的安全机制）
        $importResult = Import-Certificate -FilePath $CertFilePath -CertStoreLocation Cert:\CurrentUser\Root

        if ($importResult) {
            Write-Host "`n[成功] 证书安装完成！" -ForegroundColor Green
        }
    }

} catch {
    Write-Host "`n[异常] 安装 CA 证书发生错误：" -ForegroundColor Red
    Write-Host $_.Exception.Message
}




# ======================================================
# 设置系统
# ======================================================

# 定义刷新系统代理设置的函数 (调用 wininet.dll)
$code = @"
    using System;
    using System.Runtime.InteropServices;
    using Microsoft.Win32;

    public class ProxyConfig
    {
        [DllImport("wininet.dll", SetLastError = true, CharSet=CharSet.Auto)]
        private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

        public static void Refresh()
        {
            // INTERNET_OPTION_SETTINGS_CHANGED = 39
            InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);
            // INTERNET_OPTION_REFRESH = 37
            InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);
        }
    }
"@

Add-Type -TypeDefinition $code -Language CSharp



# 设置系统代理
$ProxyPort = "8180"
$PacUrl = "http://127.0.0.1:$ProxyPort/proxy.pac"
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty -Path $regPath -Name AutoConfigURL -Value $PacUrl
Set-ItemProperty -Path $regPath -Name ProxyEnable -Value 0

# 立即刷新设置
[ProxyConfig]::Refresh()

# 运行代理
Start-Process -FilePath $MitmdumpExe -ArgumentList "-s ./src/github-hosts.py --set flow_detail=0 -p $ProxyPort" -Wait

# 取消系统代理
Remove-ItemProperty -Path $regPath -Name AutoConfigURL -ErrorAction SilentlyContinue
