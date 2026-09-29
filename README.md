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
- `POST /api/reports/{id}/withdrawal`、`POST /api/reports/{id}/withdrawal-decision`
- `POST /api/advisories`、`GET /api/reports/{id}/advisory?user_id=...`
- `POST /api/reports/{id}/publish`
- `GET /api/reports/{id}?user_id=...`
- `GET /api/reports/{id}/notifications`

状态流转限制为 `new -> triaged -> fixing -> resolved -> published`，拒绝或回到修复中也有显式规则。披露日期早于保密期限时请求会失败，不会只修改显示状态。

报告人可提交误报撤回申请并填写原因；申请期间报告冻结，协调状态、材料、修复计划、公告草稿和延期都不能修改，即使保密期到期也不能披露。协调员同意后保留原报告及全部材料和历史，但撤回报告继续对外不可见；驳回后撤回冻结解除并恢复原处理状态。已撤回报告会继续作为相同产品和受影响版本的重复候选，再次提交时会带出原报告编号。报告详情的 `withdrawals` 字段返回申请人、原因、处理结果、处理人和处理备注。

撤回接口：

- `POST /api/reports/{id}/withdrawal`，请求体：`{"reporter_id":1,"reason":"误报原因"}`
- `POST /api/reports/{id}/withdrawal-decision`，请求体：`{"coordinator_id":2,"approved":true,"decision_note":"处理备注"}`；`approved:false` 表示驳回，也可用 `action:"approve"` 或 `"reject"`。
