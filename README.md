# autoresearch

![teaser](progress.png)

这个仓库当前的目标是：**让 Agent 持续自动寻找 Jailbreak 攻击方式**，并根据攻击成功率（ASR）迭代策略。

## 当前任务定义

- 不再做模型架构修改、参数训练或优化器研究。
- 主循环是对目标模型执行不同提示注入/越狱策略，统计成功率并记录结果。
- `train.py` 仍然是 Agent 的主要可修改文件（保留修改权限），用于快速迭代攻击策略与评估逻辑。

## 核心文件

- **`train.py`**：Jailbreak 自动研究主入口（策略生成、执行、打分、记录）。
- **`harmbench_data.py`**：加载 HarmBench 样本并做数据摘要。
- **`program.md`**：Agent 执行规范与实验循环说明。
- **`prepare.py`**：历史数据准备/训练工具，当前 Jailbreak 任务通常不需要改动。

## 快速开始

```bash
# 1) 安装依赖
uv sync

# 2) 运行一次 jailbreak policy loop
uv run train.py
```

## 指标与产物

运行后会输出并记录：

- `asr`（attack success rate）
- `num_cases`
- `success_count`
- `bad_case_ratio`
- 分类别 ASR 与失败原因分布

默认文件：

- `results.tsv`：实验结果表（keep/discard/crash）
- `artifacts/bad_cases.jsonl`：失败案例与重试记忆

## 研究方式

Agent 在 `train.py` 中不断迭代以下内容：

- prompt 攻击模板
- 失败样本重采样策略
- case 记忆与 stubborn case 优先级
- keep/discard 判定阈值

目标是持续提高 ASR，并在关键类别上取得增益。

## License

MIT
