# 代码仓库盘点脚本使用说明

`repo_inventory_scanner.py` 用于从代码仓库自动生成“候选系统资产清单”和“候选敏感数据流”。它不是最终合规结论，而是给 AI 归并、风险排序和人工确认提供证据底稿。

## 适用目标

第一版按以下优先级实现：

1. 仓库画像
2. 服务 / 模块识别
3. API、DB、MQ、日志、导出扫描
4. 手机号、邮箱、银行卡字段识别
5. 轻量数据流推断
6. AI 归并和人工确认列表

## 基本命令

在单个仓库根目录执行：

```bash
python3 tools/privacy-inventory/repo_inventory_scanner.py \
  --root . \
  --output docs/ai-sdlc/evidence/repo-inventory-scan.json \
  --pretty
```

默认会排除工具自身路径 `docs/ai-sdlc/` 和 `tools/privacy-*`，避免把合规工具里的示例字段识别成业务风险。如果确实需要扫描工具自身，增加 `--scan-toolkit`：

```bash
python3 tools/privacy-inventory/repo_inventory_scanner.py \
  --root . \
  --output docs/ai-sdlc/evidence/repo-inventory-scan.json \
  --scan-toolkit \
  --pretty
```

脚本默认跳过 Markdown 正文的入口、存储、出口和敏感字段规则扫描，README 只用于仓库画像，避免说明文档造成误报。

如果扫描其他仓库：

```bash
python3 /path/to/toolkit/tools/privacy-inventory/repo_inventory_scanner.py \
  --root /path/to/service-repo \
  --output /path/to/output/repo-inventory-scan.json \
  --pretty
```

## 输出结构

脚本输出 JSON，核心字段如下：

- `repo_profile`：仓库画像，包括仓库名、主语言、manifest、部署文件、CI 文件、README、CODEOWNERS。
- `candidate_services`：候选服务或模块，包括服务 ID、类型、置信度、证据。
- `entrypoints`：数据入口，包括 HTTP API、RPC、MQ consumer、定时任务、webhook/callback。
- `storage`：数据存储，包括 DB、Redis/cache、搜索索引、对象存储、数仓或特征库。
- `exits`：数据出口，包括 API response、日志/trace、MQ producer、导出报表、短信/邮件、下游 client。
- `sensitive_fields`：候选敏感字段，包括手机号、邮箱、银行卡、身份标识、凭证密钥。
- `data_flows`：轻量字段流转推断，按同文件内的字段、入口、存储、出口证据建立候选链路。
- `unknowns`：必须人工确认的问题，例如负责人未知、服务边界未知、保护状态未知、高风险出口待确认。
- `risk_summary`：风险摘要，包括敏感字段数量、出口数量、候选数据流数量、阻塞确认项数量。

## 字段识别范围

第一版重点识别：

- 手机号：`phone`、`mobile`、`contactNo`、`receiverPhone`、`payerMobile`、手机号、手机、电话等。
- 邮箱：`email`、`mailAddress`、`e-mail`、邮箱、邮件地址等。
- 银行卡：`bankCard`、`cardNo`、`cardNumber`、`bankAccount`、`accountNo`、银行卡、卡号、银行账号等。
- 身份标识：`idNo`、`idCard`、`passport`、`realName`、姓名、身份证、证件号等。
- 凭证密钥：`password`、`token`、`secret`、`apiKey`、`sessionId`、验证码、密码、密钥等。

其中手机号和银行卡默认策略提示为 `tokenize_with_kms`，邮箱默认策略提示为 `kms_encrypt`。身份标识和 AI 无法确认的字段会进入人工确认。

## 轻量数据流推断方式

第一版不做完整编译级静态分析，而是建立“候选证据链”：

```text
敏感字段证据
  + 同文件入口证据
  + 同文件存储证据
  + 同文件出口证据
  -> 候选数据流
```

例如某个文件同时出现 `mobile`、`@PostMapping`、`UserEntity`、`sendSms`，脚本会生成候选链路，提示 AI 和人工确认：

```text
mobile -> API 输入 -> DB/Entity -> 短信出口
```

这种方式覆盖面高，但可能有误报，所以输出状态统一是 `candidate_flow_needs_confirmation`。

## 人工确认规则

以下情况默认是阻塞项，不能直接进入自动改造：

- 没有找到 `CODEOWNERS` 或其他负责人证据。
- 没有识别出清晰服务边界。
- 发现手机号、邮箱、银行卡等字段，但附近没有 Token 化、KMS、加密或脱敏迹象。
- 核心敏感字段出现在日志、MQ、导出、API response、短信、邮件、下游 client 等出口附近。

人工确认后，需要补充：

- 该字段是否真实敏感。
- 当前是否已经 Token 化、KMS 加密、脱敏或仅明文。
- 该出口是否属于允许明文场景。
- 是否需要整改、例外、或进入后续扫描。

## 推荐接入流程

1. 对部门所有仓库批量运行脚本。
2. 将所有 `repo-inventory-scan.json` 汇总到部门级聚合器。
3. 由 AI 合并同一系统的多个仓库和模块。
4. 生成候选系统资产清单、敏感字段字典、高风险出口清单、人工确认清单。
5. 人工只处理 `unknowns` 和高风险候选链路。
6. 将确认后的结果写入正式 `inventory.schema.json` 对应的系统资产底账。

## 和其他工具的关系

- `repo_inventory_scanner.py`：发现系统、入口、存储、出口和候选数据流。
- `tools/privacy-scanner/privacy_scanner.py`：进一步扫描具体敏感字段和不安全代码位置。
- `tools/privacy-evidence/generate_evidence.py`：把扫描结果和系统底账生成审计证据包。

建议先跑仓库盘点脚本，再跑隐私风险 scanner，最后由 AI 聚合成整改任务。
