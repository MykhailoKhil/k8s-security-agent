from scan import reduce_ks, reduce_pss, reduce_trivy, sev_name

ks = {"summaryDetails": {"controls": {"C-1": {"name": "x", "status": "failed", "scoreFactor": 8}, "C-2": {"name": "y", "status": "passed", "scoreFactor": 8}},
                         "frameworks": [{"name": "NSA", "complianceScore": 59.51, "controls": {"C-1": {"status": "failed"}, "C-2": {"status": "passed"}, "C-3": {"status": "skipped"}}}]},
      "results": [{"resourceID": "/ns/Deployment/web/extra/stuff", "controls": [{"controlID": "C-1", "status": {"status": "failed"}}]}]}
r = reduce_ks(ks)
assert r["frameworks"][0] == {"name": "NSA", "score": 59.5, "passed": 1, "failed": 1, "skipped": 1}
assert r["failed_controls"][0]["severity"] == "HIGH" and r["failed_controls"][0]["examples"] == ["ns/Deployment/web"]
assert sev_name({"severity": "Critical"}) == "CRITICAL" and sev_name({"scoreFactor": 1}) == "LOW"

t = {"Findings": [{"Namespace": "kube-system", "Kind": "Deployment", "Name": "a", "Results": [
    {"Vulnerabilities": [{"Severity": "CRITICAL", "PkgName": "p", "VulnerabilityID": "CVE-1", "InstalledVersion": "1", "FixedVersion": "2"}, {"Severity": "LOW"}],
     "Misconfigurations": [{"ID": "KSV-1", "Title": "t", "Severity": "HIGH", "Status": "FAIL"}, {"ID": "KSV-2", "Status": "PASS"}],
     "Secrets": [{"RuleID": "aws", "Severity": "HIGH"}]}]}]}
r = reduce_trivy(t)
assert r["vuln_counts"] == {"CRITICAL": 1, "LOW": 1} and r["critical_high_vulns"][0]["fixed"] == "2"
assert r["misconfig_counts"] == {"HIGH": 1} and r["secrets"][0]["rule"] == "aws"
assert reduce_trivy({"Results": [{"Target": "f.yaml", "Misconfigurations": [{"ID": "X", "Severity": "LOW", "Status": "FAIL"}]}]})["misconfig_counts"] == {"LOW": 1}
assert reduce_pss({"SummaryControls": [{"ID": "1", "Name": "a", "Severity": "HIGH", "TotalFail": 0}, {"ID": "2", "Name": "b", "Severity": "LOW", "TotalFail": 3}]}) == {
    "failed": [{"id": "2", "name": "b", "severity": "LOW", "fails": 3}], "passed_controls": 1, "total_controls": 2}
print("scan ok")
assert reduce_trivy({"Resources": [{"Kind": "Pod", "Name": "p", "Results": [{"Vulnerabilities": [{"Severity": "HIGH", "PkgName": "a", "VulnerabilityID": "CVE-2"}]}]}]})["vuln_counts"] == {"HIGH": 1}
print("scan ok 2")
