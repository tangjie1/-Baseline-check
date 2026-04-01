# 🔒 Baseline-Check - 系统安全基线检查工具

> 一款开源的 Windows 和 Linux 系统安全基线自动化检查工具,纯手工编写,为您提供全面的安全合规性检查。

![GitHub stars](https://img.shields.io/github/stars/tangjie1/-Baseline-check?style=social)
![GitHub forks](https://img.shields.io/github/forks/tangjie1/-Baseline-check?style=social)
![License](https://img.shields.io/github/license/tangjie1/-Baseline-check)
![Last commit](https://img.shields.io/github/last-commit/tangjie1/-Baseline-check)

---

## ✨ 特性

- 🔍 **全面检查** - 涵盖账号、口令、授权、日志、IP通信等多个安全维度
- ⚡ **自动化执行** - 一键运行,自动生成检查报告
- 📊 **标准报告** - 生成 CSV 格式检查清单,便于分析和归档
- 🎯 **跨平台支持** - 同时支持 Windows 和 Linux 操作系统
- 📝 **纯手工编写** - 代码清晰,易于理解和二次开发
- 🔧 **灵活配置** - 配套详细的配置文档,满足不同场景需求

---

## 🎯 适用场景

- ✅ **系统安全合规检查** - 企业信息安全等级保护
- ✅ **服务器安全加固** - 新上线服务器基线配置
- ✅ **定期安全审计** - 定期检查系统安全状态
- ✅ **安全整改验证** - 验证安全加固措施的有效性
- ✅ **安全培训教学** - 系统管理员安全培训实践工具

---

## 📦 安装使用

### Windows 检查

```powershell
# 1. 设置 PowerShell 执行策略
Set-ExecutionPolicy Unrestricted

# 2. 运行检查脚本
.\windowsCheck2.1.ps1

# 3. 查看检查报告
# 脚本运行后会在当前目录生成 ip.csv 文件
```

**⚠️ 注意事项:**
- 如果 Excel 2007 打开 CSV 出现乱码,请修改脚本编码从 `utf8` 改为 `oem`
- 建议使用 Excel 2016 或更高版本打开 CSV 文件

### Linux 检查

```bash
# 1. 赋予执行权限
chmod +x linuxcheeklist2.2.sh

# 2. 运行检查脚本
./linuxcheeklist2.2.sh

# 3. 查看检查报告
# 脚本运行后会在当前目录生成 checklist.csv 文件
```

**⚠️ 重要警告:**
- **6.8 项目**(检查用户认证失败次数限制)暂时不要配置,会导致无法远程 SSH 和本地登录
- CSV 文件建议按 Tab 键分列以便阅读

---

## 📋 检查项目

### Windows 检查项

| 类别 | 检查内容 | 说明 |
|------|---------|------|
| 账号配置 | 账号锁定策略 | 检查账号锁定时间和次数设置 |
| 口令配置 | 口令复杂度策略 | 检查密码长度、复杂度要求 |
| 授权配置 | 用户权限配置 | 检查管理员权限分配 |
| 日志配置 | 审计策略 | 检查系统审计日志配置 |
| 网络配置 | 防火墙规则 | 检查网络端口和服务 |
| 其他 | 注册表安全 | 检查注册表安全配置 |

### Linux 检查项

| 类别 | 检查内容 | 说明 |
|------|---------|------|
| 账号管理 | 账号生命周期 | 检查账号创建、删除、禁用 |
| 口令策略 | 密码复杂度 | 检查密码策略和有效期 |
| 认证配置 | SSH 安全 | 检查 SSH 登录配置 |
| 文件权限 | 关键文件权限 | 检查系统文件权限设置 |
| 日志审计 | 日志记录 | 检查系统日志和审计配置 |
| 服务管理 | 不必要服务 | 检查启动项和守护进程 |

---

## 📁 项目结构

```
-Baseline-check/
├── README.md                        # 项目说明文档
├── linuxcheeklist2.2.sh            # Linux 基线检查脚本
├── linux基线配置文档2.2.docx        # Linux 基线配置文档
├── windowsCheck2.1.ps1              # Windows 基线检查脚本
└── windows基线配置文档2.1.docx      # Windows 基线配置文档
```

---

## 🔄 更新日志

### v2.2 (Linux) / v2.1 (Windows)
- ✅ 优化检查逻辑,提高准确性
- ✅ 新增多个安全检查项
- ✅ 改进报告格式,便于阅读
- ✅ 修复已知问题,提升稳定性

### 2026-04-01
- ✨ 重新设计 README.md,添加徽章和详细文档
- 📝 完善使用说明和检查项目清单
- 🎨 优化文档排版和可读性

---

## 🛠️ 技术栈

- **Windows 脚本**: PowerShell
- **Linux 脚本**: Bash Shell
- **报告格式**: CSV
- **配置文档**: Microsoft Word

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request!

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

---

## 📄 开源协议

本项目采用 MIT 协议开源 - 查看 [LICENSE](LICENSE) 文件了解详情

---

## 👨‍💻 作者

**tangjie1** - [GitHub](https://github.com/tangjie1)

---

## 🙏 致谢

感谢所有使用和贡献本项目的用户和开发者!

---

## 📮 联系方式

- 提交 Issue: https://github.com/tangjie1/-Baseline-check/issues
- 发送邮件: [通过 GitHub 联系]

---

<div align="center">

**如果这个项目对您有帮助,请给个 ⭐️ Star 支持一下!**

Made with ❤️ by tangjie1

</div>