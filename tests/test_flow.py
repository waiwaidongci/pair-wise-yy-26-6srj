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
        self.assertEqual([],self.db.snapshot(self.outsider)["reports"])
        with self.assertRaisesRegex(DomainError,"重复"):
            self.db.create_report("重复问题",self.product,self.reporter,"相同版本的另一份报告","2026-11-01",["3.2.0"])
        self.db.add_member(self.report,self.maint,"maintainer",self.coord)
        self.db.add_evidence(self.report,"协调材料","secret","coordinator",self.coord)
        visible=self.db.get_report_for_user(self.report,self.maint)
        self.assertEqual([],visible["evidence"])

    def test_withdrawal_request_freezes_report_and_approved_report_stays_private(self):
        self._advance_to_resolved()
        self.db.add_evidence(self.report,"复测记录","private content","private",self.reporter)
        self.db.request_withdrawal(self.report,self.reporter,"复测发现是测试环境配置导致")
        detail=self.db.get_report_for_user(self.report,self.reporter)
        self.assertEqual("pending",detail["withdrawal_state"])
        self.assertEqual("resolved",detail["status"])
        self.assertEqual("pending",detail["withdrawals"][0]["state"])
        self.assertEqual("复测发现是测试环境配置导致",detail["withdrawals"][0]["reason"])
        with self.assertRaisesRegex(DomainError,"冻结"):
            self.db.publish_report(self.report,self.coord,"2026-10-30")
        with self.assertRaisesRegex(DomainError,"冻结"):
            self.db.publish_report(self.report,self.coord,"2026-12-31")
        with self.assertRaisesRegex(DomainError,"冻结"):
            self.db.set_status(self.report,"published",self.coord)
        with self.assertRaisesRegex(DomainError,"冻结"):
            self.db.add_evidence(self.report,"新材料","private content","private",self.reporter)
        self.db.decide_withdrawal(self.report,self.coord,True,"确认误报，保留资料备查")
        approved=self.db.get_report_for_user(self.report,self.coord)
        self.assertEqual("withdrawn",approved["withdrawal_state"])
        self.assertEqual("resolved",approved["status"])
        self.assertTrue(approved["evidence"])
        self.assertTrue(approved["fix_plan"])
        self.assertTrue(approved["members"])
        self.assertEqual("draft",self.db.get_advisory(self.report,self.coord)["status"])
        self.assertGreaterEqual(len(approved["history"]),6)
        self.assertEqual("approved",approved["withdrawals"][-1]["state"])
        self.assertEqual("协调员",approved["withdrawals"][-1]["coordinator_name"])
        with self.assertRaisesRegex(DomainError,"无权|尚未公开"):
            self.db.get_report_for_user(self.report,self.outsider)
        with self.assertRaisesRegex(DomainError,"已撤回"):
            self.db.publish_report(self.report,self.coord,"2026-12-31")
        with self.assertRaisesRegex(DomainError,"公告尚未公开|无权"):
            self.db.get_advisory(self.report,self.outsider)
        duplicates=self.db.find_duplicate_reports(self.product,"3.2.0")
        self.assertEqual("withdrawn",duplicates[0]["withdrawal_state"])
        with self.assertRaisesRegex(DomainError,"VULN-"):
            self.db.create_report("再次提交",self.product,self.reporter,"同一产品和版本","2026-11-01",["3.2.0"])
        new_report=self.db.create_report(
            "再次提交",self.product,self.reporter,"同一产品和版本","2026-11-01",["3.2.0"],allow_duplicate=True
        )
        self.assertNotEqual(self.report,new_report)

    def test_withdrawal_rejection_restores_processing_state(self):
        self.db.set_status(self.report,"triaged",self.coord)
        self.db.request_withdrawal(self.report,self.reporter,"复现步骤失效")
        with self.assertRaisesRegex(DomainError,"只有报告人"):
            self.db.request_withdrawal(self.report,self.outsider,"其他人撤回")
        with self.assertRaisesRegex(DomainError,"只有协调员"):
            self.db.decide_withdrawal(self.report,self.reporter,False,"报告人不能自审")
        self.db.decide_withdrawal(self.report,self.coord,False,"补充材料后仍可复现")
        restored=self.db.get_report_for_user(self.report,self.reporter)
        self.assertEqual("none",restored["withdrawal_state"])
        self.assertEqual("triaged",restored["status"])
        self.assertEqual("rejected",restored["withdrawals"][-1]["state"])
        self.assertEqual("triaged",restored["history"][-1]["new_status"])
        self.db.set_status(self.report,"fixing",self.coord)
        self.db.request_withdrawal(self.report,self.reporter,"再次确认误报")
        self.db.decide_withdrawal(self.report,self.coord,False,"需要继续处理")
        withdrawals=self.db.get_report_for_user(self.report,self.coord)["withdrawals"]
        self.assertEqual(["rejected","rejected"],[item["state"] for item in withdrawals])
        self.assertEqual("补充材料后仍可复现",withdrawals[0]["decision_note"])

if __name__=="__main__": unittest.main()
