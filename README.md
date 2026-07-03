# FindPb

FindPb 是一个 Windows 控制台工具，用于从文件中定位 Protocol Buffers 描述符痕迹，并尝试恢复 `FileDescriptorProto` 和 `FileDescriptorSet`

## 构建

1. 安装 Visual Studio 并安装 '使用 C++ 桌面开发' 工作负荷

2. 打开 'Developer Command Prompt' 并在项目目录执行

x86
```powershell
MSBuild.exe FindPb.slnx /p:Configuration=Release /p:Platform=x86
```

x64
```powershell
MSBuild.exe FindPb.slnx /p:Configuration=Release /p:Platform=x64
```

输出文件：

x86
- `Release\FindPb.exe`

x64
- `x64\Release\FindPb.exe`

## 用法

请使用 `--help` 参数查看

