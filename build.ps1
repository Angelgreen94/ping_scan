$compiler = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

if (-not (Test-Path $compiler)) {
    $compiler = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
}

if (-not (Test-Path $compiler)) {
    throw "No se encontro csc.exe de .NET Framework."
}

& $compiler `
    /target:winexe `
    /out:ping_scan.exe `
    /platform:x64 `
    /win32icon:app_icon.ico `
    /reference:System.dll `
    /reference:System.Core.dll `
    /reference:System.Drawing.dll `
    /reference:System.Windows.Forms.dll `
    /reference:System.Xml.dll `
    /reference:System.IO.Compression.dll `
    /reference:System.IO.Compression.FileSystem.dll `
    /resource:ping_scan_logo.png,PingScanLogo `
    /resource:account_button_frame.png,AccountButtonFrame `
    /resource:account_avatar_default.png,AccountAvatarDefault `
    PingMonitorApp.cs
