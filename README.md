# 开源漏洞披露协作

这是使用 Python 标准库、SQLite 和 `http.server` 实现的保密漏洞协作后台。系统支持报告人、协调员、维护者三种角色，管理受影响产品版本、私密证明材料、保密期限、修复计划、状态历史、延期、通知和公开公告。

## 启动

```bash
python app.py
```

默认端口 `8113`，页面为 <http://127.0.0.1:8113>。首次启动创建示例网关漏洞。可用环境变量 `PORT` 和 `VULN_DB` 调整端口及数据库位置。

## 测试

```bash
python -m unittest discover -s tests -v
```

测试覆盖：创建报告、加入维护者、分级、提交修复计划、解决、阻止提前披露、到期披露并读取公告；同时验证外部用户无权查看、相同产品版本会触发重复报告，以及维护者看不到协调员专用材料。

## 接口

- `POST /api/users`、`POST /api/products`、`POST /api/reports`
- `GET /api/duplicates?product_id=...&version=...`
- `POST /api/members`、`POST /api/evidence`
- `POST /api/fixes`、`POST /api/extensions`
- `POST /api/reports/{id}/status`
- `POST /api/advisories`、`GET /api/reports/{id}/advisory?user_id=...`
- `POST /api/reports/{id}/publish`
- `POST /api/reports/{id}/withdrawal`
- `POST /api/withdrawals/{id}/review`、`GET /api/withdrawals?coordinator_id=...`
- `GET /api/reports/{id}?user_id=...`
- `GET /api/reports/{id}/notifications`

状态流转限制为 `new -> triaged -> fixing -> resolved -> published`，拒绝或回到修复中也有显式规则。披露日期早于保密期限时请求会失败，不会只修改显示状态。

## 误报撤回

- 报告人通过 `POST /api/reports/{id}/withdrawal` 提交撤回原因（至少 5 个字符）；申请进入 `pending` 后报告立即冻结，状态流转、材料、修复计划、公告草稿、延期和披露都会被拒绝。
- 协调员通过审核队列 `GET /api/withdrawals?coordinator_id=...` 处理：同意后申请为 `approved`，原状态、材料、成员和全部历史保留，但公告始终不对外可见，即使保密期限已过也不能自动或手动公开；驳回后申请为 `rejected`，报告直接恢复原处理状态。
- 撤回审核不会改动原 `status`，审核过程单独记录在 `withdrawal_requests`。详情接口的 `withdrawal.requests/latest` 返回申请人、原因、审核人、审核备注、申请时状态和处理结果。
- 已批准撤回的报告仍参与同产品、同受影响版本的重复校验；再次提交时会在重复提示中带出原报告编号并标注“已撤回”，可通过 `allow_duplicate=true` 人工确认后继续提交。
