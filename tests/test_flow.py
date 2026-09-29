import os, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from database import DomainError, VulnerabilityDB

class VulnerabilityFlowTest(unittest.TestCase):
    def setUp(self):
        fd,self.path=tempfile.mkstemp(suffix=".db"); os.close(fd); self.db=VulnerabilityDB(self.path)
        self.reporter=self.db.add_user("报告人","reporter","研究所"); self.coord=self.db.add_user("协调员","coordinator","响应中心"); self.maint=self.db.add_user("维护者","maintainer","项目组"); self.outsider=self.db.add_user("旁观者","reporter","外部")
        self.product=self.db.add_product("网关","项目组")
        self.report=self.db.create_report("鉴权绕过",self.product,self.reporter,"特制请求可绕过鉴权","2026-10-30",["3.2.0"])
    def tearDown(self): self.db.close(); os.unlink(self.path)
    def _advance_to_resolved(self):
        self.db.add_member(self.report,self.maint,"maintainer",self.coord)
        self.db.set_status(self.report,"triaged",self.coord)
        self.db.set_status(self.report,"fixing",self.coord)
        self.db.set_fix_plan(self.report,self.maint,"增加鉴权前置校验", "2026-10-20")
        self.db.set_status(self.report,"resolved",self.coord)
        self.db.create_advisory_draft(self.report,"受影响版本 3.2.0。请升级到 3.2.1。",self.coord)
    def test_full_disclosure_flow_and_early_publish_rejected(self):
        self._advance_to_resolved()
        with self.assertRaisesRegex(DomainError,"提前披露"):
            self.db.publish_report(self.report,self.coord,"2026-10-01")
        self.db.publish_report(self.report,self.coord,"2026-10-30")
        advisory=self.db.get_advisory(self.report,self.outsider)
        self.assertEqual("published",advisory["status"])
        self.assertTrue(self.db.notifications_for(self.maint))
    def test_denies_outsider_and_duplicate_report(self):
        with self.assertRaisesRegex(DomainError,"无权"):
            self.db.get_report_for_user(self.report,self.outsider)
        with self.assertRaisesRegex(DomainError,"重复"):
            self.db.create_report("重复问题",self.product,self.reporter,"相同版本的另一份报告","2026-11-01",["3.2.0"])
        self.db.add_member(self.report,self.maint,"maintainer",self.coord)
        self.db.add_evidence(self.report,"协调材料","secret","coordinator",self.coord)
        visible=self.db.get_report_for_user(self.report,self.maint)
        self.assertEqual([],visible["evidence"])
    def test_pending_withdrawal_freezes_report_and_blocks_expiry_publish(self):
        request_id=self.db.request_withdrawal(self.report,self.reporter,"复测发现是测试环境配置问题")
        self.assertEqual("pending",self.db.get_report_for_user(self.report,self.reporter)["withdrawal"]["latest"]["status"])
        with self.assertRaisesRegex(DomainError,"冻结"):
            self.db.set_status(self.report,"triaged",self.coord)
        with self.assertRaisesRegex(DomainError,"冻结"):
            self.db.publish_report(self.report,self.coord,"2026-12-01")
        with self.assertRaisesRegex(DomainError,"冻结"):
            self.db.extend_embargo(self.report,"2026-12-31","冻结期间不应允许延期",self.coord)
        with self.assertRaisesRegex(DomainError,"只有协调员"):
            self.db.review_withdrawal(request_id,self.maint,"approved")
        self.db.review_withdrawal(request_id,self.coord,"rejected","经核实漏洞成立")
        detail=self.db.get_report_for_user(self.report,self.reporter)
        self.assertEqual("new",detail["status"])
        self.assertEqual("rejected",detail["withdrawal"]["latest"]["status"])
        self.db.set_status(self.report,"triaged",self.coord)
    def test_approved_withdrawal_keeps_history_private_and_warns_on_resubmission(self):
        self._advance_to_resolved()
        self.db.add_evidence(self.report,"复现日志","抓包内容","private",self.reporter)
        request_id=self.db.request_withdrawal(self.report,self.reporter,"确认是误报，请求撤回")
        pending_ids=[row["id"] for row in self.db.pending_withdrawals(self.coord)]
        self.assertIn(request_id,pending_ids)
        self.db.review_withdrawal(request_id,self.coord,"approved","同意撤回")
        with self.assertRaisesRegex(DomainError,"不能提前披露|已撤回"):
            self.db.publish_report(self.report,self.coord,"2026-10-01")
        with self.assertRaisesRegex(DomainError,"已撤回"):
            self.db.publish_report(self.report,self.coord,"2026-12-01")
        with self.assertRaisesRegex(DomainError,"无权"):
            self.db.get_advisory(self.report,self.outsider)
        detail=self.db.get_report_for_user(self.report,self.coord)
        self.assertEqual("resolved",detail["status"])
        self.assertTrue(detail["evidence"])
        self.assertTrue(detail["history"])
        latest=detail["withdrawal"]["latest"]
        self.assertEqual("approved",latest["status"])
        self.assertEqual("报告人",latest["requester_name"])
        self.assertIn("撤回",latest["reason"])
        with self.assertRaisesRegex(DomainError,r"VULN-\d+-\d+（已撤回，请核对是否重复）"):
            self.db.create_report("疑似同一问题",self.product,self.reporter,"再次提交相同产品版本","2026-11-01",["3.2.0"])
        second=self.db.create_report("确认新问题",self.product,self.reporter,"人工确认非重复","2026-11-01",["3.2.0"],allow_duplicate=True)
        self.assertGreater(second,self.report)

if __name__=="__main__": unittest.main()
