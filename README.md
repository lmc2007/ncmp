# ncmp

ncmp(NetEase Cloud Music Partner/网易云音乐合伙人)

基于 Python 的网易云音乐-音乐合伙人任务脚本，支持本地运行和 GitHub Actions 自动执行。

## 功能特点

- 全自动完成音乐合伙人日常任务
  - 完成每日5个基础任务
  - 完成每日7个额外评分任务
- 便捷的部署方式
  - 支持本地手动运行
  - 支持 GitHub Actions 自动执行
- 完善的通知机制
  - Cookie 失效自动发送邮件提醒
- 一次配置持续使用
  - 支持自动登录账号并刷新Cookie，基于[pyncm](https://github.com/mos9527/pyncm)库

## 使用前准备

如果你从来没有接触过GitHub Actions以及Cookies相关的网络知识，请戳[ncmp 使用指北](https://blog.nyaashino.com/post/ncmp_quickstart)。

### 获取网易云音乐 Cookie

1. 登录[网易云音乐网页版](https://music.163.com/)
2. 打开浏览器开发者工具（F12）
3. 切换到 Network（网络）选项卡
4. 刷新页面，在请求中找到 cookie 中的 `MUSIC_U` 和 `__csrf` 值

### Cookie自动刷新配置（可选）

为了让Cookie自动刷新功能正常工作，您需要创建一个具有特定权限的GitHub Personal Access Token (PAT)。以下是详细步骤：

#### 1. 创建GitHub Personal Access Token

1. 登录您的 GitHub 账号
2. 访问 [Token设置页面](https://github.com/settings/tokens)
3. 点击"Generate new token" > "Fine-grained tokens" or "Generate new token (classic)"
4. 在"Note"字段给您的Token起一个描述性名称，如"NCMP Cookie Refresh"
5. 设置 Token 有效期

#### 2. 选择正确的权限范围

您只需要为 Token 配置最小必要的权限。
如果使用 Fine-grained tokens (更精细的权限控制):

1. 选择只对您的ncmp仓库有效
2. 将 "secrets" 设为 "Read and write"

如果使用 Generate new token (classic):

**如果是公开仓库**，选择以下权限：

- `repo` > `public_repo` (仅访问公开仓库)
- `codespace` > `codespace:secrets`

**如果是私有仓库**，选择以下权限：

- `repo` (完整的仓库访问，包括私有仓库)
- `codespace` > `codespace:secrets`

#### 3. 保存Token

1. 滚动到页面底部，点击"Generate token"
2. **立即复制生成的token**（离开页面后将无法再次查看）
3. 将复制的token添加到您fork的ncmp仓库的GitHub Secrets中，命名为`GH_TOKEN`

#### 4. 添加额外的自动刷新Cookie所需Secrets

在仓库的Secrets中添加以下内容：

- `NETEASE_PHONE`: 您的网易云音乐账号手机号
- 网易云音乐账号密码（2选1，强烈建议使用MD5加密密码）
  - `NETEASE_PASSWORD`: 明文密码
  - `NETEASE_MD5_PASSWORD`: MD5加密密码
- `GH_TOKEN`: 刚才创建的GitHub Token

可选（抗风控 / 排错用）：

- `NETEASE_REAL_IP`: 登录请求携带的 `X-Real-IP` 头，默认 `118.88.88.88`。GitHub Actions 的 runner 在海外机房，网易风控常直接给 `8821 需要行为验证`，这个头是 pyncm 文档里给出的官方绕法；填 `off` 可关闭。
- `NETEASE_DEVICE_ID`: 设备指纹。**不要随便乱填**——实测用一个新的设备 ID 从新 IP 登录会立刻触发 8821，默认沿用 pyncm 的 `pyncm!` 就好。

#### 5. 启用自动刷新工作流

- 确保仓库中`.github/workflows/refresh_cookie.yml`工作流已启用
- 在 Actions 页面手动运行 "Refresh Cookie"，`Run workflow` 时可选择模式：
  - `refresh`（默认）：正常登录并写入 Secrets
  - `dry-run`：只登录+校验，不写 Secrets
  - `diagnose`：环境自检 + 逐通道登录诊断，排错用这个

#### 6. 登录失败怎么查

本地直接跑诊断模式，会打印现有 cookie 是否有效、登录走了哪个通道、网易返回的真实错误码：

```bash
export NETEASE_PHONE=你的手机号
export NETEASE_PASSWORD=你的密码
python refresh_cookie.py --diagnose
```

常见错误码：

| code | 含义 | 处理 |
| --- | --- | --- |
| 502 | 账号或密码错误 | 检查密码；若用的是 `NETEASE_MD5_PASSWORD`，那串 md5 必须**是当前密码**的 md5（手抄旧密码、改过密码最常见）。拿不准就直接填 `NETEASE_PASSWORD` 明文，代码会自动转 md5 |
| 509 | 密码错误次数超限，账号被临时锁定 | 等 30~60 分钟再试。**不要连续重跑工作流**，否则锁定会延长 |
| 460 | IP 被判异常（海外/机房） | 启用 `NETEASE_REAL_IP` |
| 8821 | 需要行为验证码（滑块） | 机房 IP 风控。启用 `NETEASE_REAL_IP`，仍不行就手动更新 cookie 或改用 self-hosted runner |
| 8816 | 账号风险，要求二次验证 | 手机上登录一次客户端解除验证后再试 |
| 403 | GitHub Token 权限不足 | classic PAT 需要 `repo`；fine-grained PAT 需要 `Secrets: Read and write` |

注意：`502 / 501 / 509 / 8822` 属于凭据类错误，程序会**立刻停止**所有尝试（不重试、不换通道），避免把账号撞成锁定态；只有 `503`（限流）和网络层错误才重试。

自己算一遍 md5 核对：

```bash
python -c "import hashlib;print(hashlib.md5('你的密码'.encode()).hexdigest())"
```

另外：登录失败但**现有 `MUSIC_U` 仍然有效**时，工作流会选择沿用旧 cookie 并只发一封告警邮件，不会把 Secret 写成空值，也不会把 Actions 刷红。

### 配置邮箱通知（可选）

支持所有提供 SMTP 服务的邮箱，以下是常见邮箱的配置示例：

1. Gmail (推荐)

   ```json
   {
     "notify_email": "your.email@gmail.com",
     "email_password": "YOUR_APP_SPECIFIC_PASSWORD",
     "smtp_server": "smtp.gmail.com",
     "smtp_port": 465
   }
   ```

   注意：Gmail 需要开启两步验证并使用应用专用密码

2. QQ邮箱

   ```json
   {
     "notify_email": "your_qq@qq.com",
     "email_password": "YOUR_AUTH_CODE",
     "smtp_server": "smtp.qq.com",
     "smtp_port": 465
   }
   ```

   注意：需要在QQ邮箱设置中开启SMTP服务并获取授权码

## 使用方法

### 方式一：本地手动执行

1. 克隆仓库到本地：

   ```bash
   git clone https://github.com/ACAne0320/ncmp.git
   cd ncmp
   ```

2. 安装依赖：

   ```bash
   pip install -r requirements.txt
   ```

3. 复制并编辑配置文件：

   ```bash
   cp config/setting.example.json config/setting.json
   ```

4. 编辑 `config/setting.json`，填写以下配置：

   ```json
   {
     "Cookie_MUSIC_U": "YOUR_MUSIC_U_COOKIE",
     "Cookie___csrf": "YOUR_CSRF_TOKEN",
     "notify_email": "your.email@gmail.com",
     "email_password": "YOUR_APP_SPECIFIC_PASSWORD",
     "smtp_server": "smtp.gmail.com",
     "smtp_port": 465,
     "wait_time_min": 15,
     "wait_time_max": 20,
     "full_extra_tasks": false,  // 完成所有的额外任务，而不是只完成固定加分的7个
     "score": 3  // 评分策略：1=1-2分，2=2-3分，3=3-4分（默认），4=固定4分
   }
   ```

5. 运行测试脚本确认配置正确：

   ```bash
   python tests/test_auto_score.py
   ```

6. 运行主程序：

   ```bash
   python main.py
   ```

### 方式二：GitHub Actions 自动执行

1. Fork 本仓库到你的 GitHub 账号

2. 配置 GitHub Secrets：
   在你 fork 的仓库中，进入 Settings -> Secrets and variables -> Actions，添加以下配置：
   - `MUSIC_U`：网易云音乐 MUSIC_U Cookie
   - `CSRF`：网易云音乐 CSRF Token
   - `NOTIFY_EMAIL`：邮箱地址（可选）
   - `EMAIL_PASSWORD`：邮箱密码（可选）
   - `SMTP_SERVER`：smtp.gmail.com（可选）
   - `SMTP_PORT`：465（可选）
   - `WAIT_TIME_MIN`：最小等待时间（可选，默认15）
   - `WAIT_TIME_MAX`：最大等待时间（可选，默认20）
   - `FULL_EXTRA_TASKS`: 是否完成所有的额外任务 (可选，默认False)
   - `SCORE`：评分策略（可选，默认3）
   - `NETEASE_PHONE` / `NETEASE_PASSWORD`（或 `NETEASE_MD5_PASSWORD`）/ `GH_TOKEN`：自动刷新 Cookie 用
   - `NETEASE_REAL_IP`：抗风控头（可选，默认 118.88.88.88）

3. 启用 GitHub Actions：
   - 进入仓库的 Actions 页面
   - 点击 "I understand my workflows, go ahead and enable them"
   - Actions 将会按照预设时间自动运行（默认北京时间1点）

## 注意事项

- 目前仅对 Gmail/QQ邮箱 进行了验证，其他邮箱可能需要自行测试
- 邮箱密码为授权码，而非邮箱登录密码
- 任务提交默认添加了 15-20 秒的等待时间，避免被检测异常
- 建议使用 GitHub Actions 的定时任务功能，避免遗漏每日任务
- 网易云音乐的 Cookie 两周左右就会过期，建议配置邮箱以便及时收到失效通知
- Cookie 自动刷新使用了[pyncm](https://github.com/mos9527/pyncm)库进行登陆，如果使用明文会自动将密码进行md5加密
- `refresh_cookie.py` 失败时会以退出码 1 结束，Actions 会显示红灯（早期版本不管成败都返回 0，于是"看起来成功、实际邮件说失败"）

## 声明

- 本项目仅供学习交流使用
- 不得用于商业用途
- 使用本脚本产生的一切后果由使用者自行承担

## 致谢

- [qinglong-sign](https://github.com/KotoriMinami/qinglong-sign)
- [CloudMusicBot](https://github.com/C20C01/CloudMusicBot)
- [NeteaseCloudMusicApi](https://github.com/Binaryify/NeteaseCloudMusicApi)
- [pyncm](https://github.com/mos9527/pyncm)

## 反馈

使用过程中如果有任何问题或者建议，欢迎在[Issues](https://github.com/ACAne0320/ncmp/issues)中提出，或者联系我

- 邮箱：[nyaashino@gmail.com](mailto:nyaashino@gmail.com)

如果觉得这个项目对你有帮助，欢迎给个 Star 支持一下~
