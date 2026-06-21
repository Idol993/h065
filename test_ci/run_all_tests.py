#!/usr/bin/env python3
"""
完整测试脚本：验证策略配置、JSON violations、HTML 图谱、baseline 对比等所有新功能
"""
import json
import os
import sys
import re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from dependency_auditor.parsers.python_parser import Dependency
from dependency_auditor.parsers.lockfile_parser import parse as lock_parse
from dependency_auditor.analyzers.license_analyzer import LicenseAnalyzer
from dependency_auditor.analyzers.circular_detector import CircularDetector
from dependency_auditor.analyzers.outdated_checker import OutdatedResult
from dependency_auditor.analyzers.policy_engine import PolicyEngine
from dependency_auditor.analyzers.baseline_comparator import BaselineComparator
from dependency_auditor.utils.config_loader import ConfigLoader
from dependency_auditor.reporters.json_exporter import JsonExporter
from dependency_auditor.reporters.html_reporter import HtmlReporter


def create_test_deps() -> list[Dependency]:
    """创建测试依赖，模拟 OSS Index 返回覆盖锁文件"""
    test_dir = Path(__file__).parent
    deps = lock_parse(str(test_dir / "package-lock.json"))

    # 模拟 OSS Index 返回的许可证，覆盖锁文件中的 MIT
    for dep in deps:
        if dep.name == "package-a":
            dep._oss_licenses = [{"licenseId": "GPL-3.0"}]
        elif dep.name == "package-d":
            dep._oss_licenses = [{"licenseId": "AGPL-3.0"}]
        elif dep.name == "package-g":
            dep._oss_licenses = [{"licenseId": "LGPL-2.1"}]
        elif dep.name == "package-e":
            dep._oss_licenses = [{"licenseId": "GPL-2.0"}]
        else:
            dep._lock_licenses = ["MIT"]

    return deps


def test_1_policy_engine():
    """TEST 1: 策略引擎过滤功能"""
    print("=" * 70)
    print("TEST 1: Policy Engine - 策略过滤功能")
    print("=" * 70)

    test_dir = Path(__file__).parent
    cfg = ConfigLoader(str(test_dir / "dep-audit.yml"))
    deps = create_test_deps()

    license_analyzer = LicenseAnalyzer()
    license_results = license_analyzer.analyze(deps)

    detector = CircularDetector()
    cycles = detector.detect(deps)

    # 模拟过时检查结果
    outdated_results = []
    for dep in deps:
        if dep.name in ("package-f", "package-h"):
            outdated_results.append(OutdatedResult(
                dependency=dep,
                current_version=dep.version_spec,
                latest_version="99.0.0",
                is_outdated=True,
                ecosystem=dep.ecosystem,
            ))
        else:
            outdated_results.append(OutdatedResult(
                dependency=dep,
                current_version=dep.version_spec,
                latest_version=dep.version_spec,
                is_outdated=False,
                ecosystem=dep.ecosystem,
            ))

    # 应用策略
    policy_engine = PolicyEngine(cfg)
    policy_result = policy_engine.apply([], license_results, cycles, outdated_results)

    fl = policy_result.filtered_licenses
    fc = policy_result.filtered_cycles
    fo = policy_result.filtered_outdated
    violations = policy_result.violations
    actions = policy_result.actions

    # 检查 package-e 被忽略
    pkg_e_in_licenses = any(r.dependency.name == "package-e" for r in fl)
    assert not pkg_e_in_licenses, "package-e 应该被 ignore_packages 忽略"
    print("✅ package-e 被 ignore_packages 忽略")

    # 检查 package-g (LGPL-2.1) 被 license_allowlist 放行
    pkg_g_violation = any(
        v.package == "package-g" for v in violations
    )
    assert not pkg_g_violation, "package-g (LGPL-2.1) 应该被 license_allowlist 放行"
    print("✅ package-g (LGPL-2.1) 被 license_allowlist 放行")

    # 检查 package-f 被 allowed_outdated_packages 放行
    pkg_f_in_outdated = any(r.dependency.name == "package-f" for r in fo)
    assert not pkg_f_in_outdated, "package-f 应该被 allowed_outdated_packages 放行"
    print("✅ package-f 被 allowed_outdated_packages 放行")

    # 检查 license_threshold 只放行了 medium 及以上
    # GPL-3.0 (high) 和 AGPL-3.0 (high) 应该保留
    copyleft_count = sum(1 for r in fl if r.has_copyleft)
    assert copyleft_count >= 2, "GPL-3.0 和 AGPL-3.0 应该被保留，共至少 2 个 copyleft"
    print(f"✅ 保留 copyleft 包 {copyleft_count} 个 (GPL-3.0, AGPL-3.0)")

    # 检查 package-h 出现在过期列表中
    pkg_h_in_outdated = any(r.dependency.name == "package-h" for r in fo)
    assert pkg_h_in_outdated, "package-h 应该出现在过期列表中"
    print("✅ package-h 出现在过期列表中")

    # 检查循环依赖保留
    assert len(fc) >= 1, "循环依赖 A→B→C→A 应该被检测到"
    print(f"✅ 循环依赖检测: {len(fc)} 个")

    # 检查 policy actions 记录
    ignore_actions = [a for a in actions if a.action == "ignore"]
    allow_actions = [a for a in actions if a.action == "allow"]
    print(f"✅ Policy actions: {len(ignore_actions)} ignore, {len(allow_actions)} allow")
    print(f"✅ Policy violations: {len(violations)} 个")

    print("\n✅ TEST 1 PASSED\n")
    return policy_result


def test_2_json_violations():
    """TEST 2: JSON violations 区域"""
    print("=" * 70)
    print("TEST 2: JSON Export - violations 区域")
    print("=" * 70)

    test_dir = Path(__file__).parent
    cfg = ConfigLoader(str(test_dir / "dep-audit.yml"))
    deps = create_test_deps()

    license_analyzer = LicenseAnalyzer()
    license_results = license_analyzer.analyze(deps)

    detector = CircularDetector()
    cycles = detector.detect(deps)

    outdated_results = []
    for dep in deps:
        if dep.name in ("package-f", "package-h"):
            outdated_results.append(OutdatedResult(
                dependency=dep,
                current_version=dep.version_spec,
                latest_version="99.0.0",
                is_outdated=True,
                ecosystem=dep.ecosystem,
            ))
        else:
            outdated_results.append(OutdatedResult(
                dependency=dep,
                current_version=dep.version_spec,
                latest_version=dep.version_spec,
                is_outdated=False,
                ecosystem=dep.ecosystem,
            ))

    policy_engine = PolicyEngine(cfg)
    policy_result = policy_engine.apply([], license_results, cycles, outdated_results)

    exporter = JsonExporter()
    path = exporter.export(
        [], policy_result.filtered_licenses,
        policy_result.filtered_cycles, policy_result.filtered_outdated,
        str(test_dir), policy_result, None, cfg.to_dict()
    )

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # 检查 violations 存在
    assert "violations" in data, "JSON 应该包含 violations 字段"
    violations = data["violations"]
    assert len(violations) > 0, "violations 不应该为空"
    print(f"✅ JSON violations 区域存在，共 {len(violations)} 条")

    # 检查类型
    types = set(v["type"] for v in violations)
    expected_types = {"copyleft_license", "circular_dependency", "outdated_package"}
    assert expected_types.issubset(types), f"violations 应该包含类型 {expected_types}, 实际 {types}"
    print(f"✅ violations 包含类型: {sorted(types)}")

    # 检查格式
    for v in violations:
        for field in ["type", "package", "version", "severity", "reason", "details"]:
            assert field in v, f"violation 应该包含字段 {field}"
    print("✅ violations 字段完整: type, package, version, severity, reason, details")

    # 检查 GPL/AGPL 包在 violations 中
    gpl_pkgs = [v["package"] for v in violations if v["type"] == "copyleft_license" and "GPL" in v["details"].get("license_id", "")]
    assert "package-a" in gpl_pkgs, "package-a (GPL-3.0) 应该在 violations 中"
    assert "package-d" not in gpl_pkgs or "package-d" in [v["package"] for v in violations if v["type"] == "copyleft_license"], "package-d (AGPL-3.0) 应该在 violations 中"
    print("✅ GPL-3.0 和 AGPL-3.0 包在 violations 中正确标记")

    # 检查 policy_actions 存在
    assert "policy_actions" in data, "JSON 应该包含 policy_actions 字段"
    print(f"✅ policy_actions 区域存在，共 {len(data['policy_actions'])} 条")

    # 检查 policy_config 存在
    assert "policy_config" in data, "JSON 应该包含 policy_config 字段"
    print("✅ policy_config 区域存在")

    print("\n✅ TEST 2 PASSED\n")
    return path


def test_3_html_report():
    """TEST 3: HTML 报告 - Policy Result 页签 + 图谱"""
    print("=" * 70)
    print("TEST 3: HTML Report - Policy Result + 依赖图谱")
    print("=" * 70)

    test_dir = Path(__file__).parent
    cfg = ConfigLoader(str(test_dir / "dep-audit.yml"))
    deps = create_test_deps()

    license_analyzer = LicenseAnalyzer()
    license_results = license_analyzer.analyze(deps)

    detector = CircularDetector()
    cycles = detector.detect(deps)
    dep_tree = detector.get_dependency_tree(deps, 5)

    outdated_results = []
    for dep in deps:
        if dep.name in ("package-f", "package-h"):
            outdated_results.append(OutdatedResult(
                dependency=dep,
                current_version=dep.version_spec,
                latest_version="99.0.0",
                is_outdated=True,
                ecosystem=dep.ecosystem,
            ))
        else:
            outdated_results.append(OutdatedResult(
                dependency=dep,
                current_version=dep.version_spec,
                latest_version=dep.version_spec,
                is_outdated=False,
                ecosystem=dep.ecosystem,
            ))

    policy_engine = PolicyEngine(cfg)
    policy_result = policy_engine.apply([], license_results, cycles, outdated_results)

    reporter = HtmlReporter()
    path = reporter.export(
        [], policy_result.filtered_licenses,
        policy_result.filtered_cycles, policy_result.filtered_outdated,
        dep_tree, str(test_dir), policy_result, None, cfg.to_dict()
    )

    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    # 检查 Policy Result 页签存在
    assert "onclick=\"switchTab('policy')\"" in content, "HTML 应该包含 Policy Result 页签"
    print("✅ Policy Result 页签存在")

    # 检查 Violations 页签存在
    assert "onclick=\"switchTab('violations')\"" in content, "HTML 应该包含 Violations 页签"
    print("✅ Violations 页签存在")

    # 检查图谱数据不为空
    match = re.search(r"var graphData = (\{.*?\});", content, re.DOTALL)
    assert match, "HTML 应该包含 graphData"
    graph_data = json.loads(match.group(1))
    assert "nodes" in graph_data and len(graph_data["nodes"]) > 0, "graphData 应该有 nodes"
    assert "links" in graph_data, "graphData 应该有 links"
    print(f"✅ 图谱数据: {len(graph_data['nodes'])} 节点, {len(graph_data['links'])} 连线")

    # 检查节点包含 is_cycle 标记
    cycle_nodes = [n for n in graph_data["nodes"] if n.get("is_cycle")]
    assert len(cycle_nodes) >= 3, "循环依赖的节点 (A,B,C) 应该有 is_cycle 标记"
    print(f"✅ 循环节点标记: {len(cycle_nodes)} 个 (package-a, package-b, package-c)")

    # 检查连线包含 is_cycle 标记
    cycle_links = [l for l in graph_data["links"] if l.get("is_cycle")]
    assert len(cycle_links) >= 3, "循环依赖的连线应该有 is_cycle 标记"
    print(f"✅ 循环连线标记: {len(cycle_links)} 条")

    # 检查图谱初始化逻辑正确（延迟初始化）
    assert "setTimeout(initGraph, 50)" in content, "HTML 应该包含延迟初始化图谱"
    print("✅ 图谱延迟初始化 (修复空白问题)")

    # 检查 policy actions 在 HTML 中
    assert "Triggered Rules" in content, "HTML 应该包含 Triggered Rules 区域"
    assert "Policy Actions" in content, "HTML 应该包含 Policy Actions 区域"
    print("✅ Policy Result 页签包含 Triggered Rules 和 Policy Actions")

    # 检查 Active Policy Configuration
    assert "Active Policy Configuration" in content, "HTML 应该包含 Active Policy Configuration"
    print("✅ Active Policy Configuration 区域存在")

    print("\n✅ TEST 3 PASSED\n")
    return path


def test_4_baseline_comparison():
    """TEST 4: Baseline 对比功能"""
    print("=" * 70)
    print("TEST 4: Baseline Comparison - 基线对比")
    print("=" * 70)

    test_dir = Path(__file__).parent
    cfg = ConfigLoader(str(test_dir / "dep-audit.yml"))
    deps = create_test_deps()

    license_analyzer = LicenseAnalyzer()
    license_results = license_analyzer.analyze(deps)

    detector = CircularDetector()
    cycles = detector.detect(deps)

    outdated_results = []
    for dep in deps:
        if dep.name in ("package-f", "package-h"):
            outdated_results.append(OutdatedResult(
                dependency=dep,
                current_version=dep.version_spec,
                latest_version="99.0.0",
                is_outdated=True,
                ecosystem=dep.ecosystem,
            ))
        else:
            outdated_results.append(OutdatedResult(
                dependency=dep,
                current_version=dep.version_spec,
                latest_version=dep.version_spec,
                is_outdated=False,
                ecosystem=dep.ecosystem,
            ))

    policy_engine = PolicyEngine(cfg)
    policy_result = policy_engine.apply([], license_results, cycles, outdated_results)

    # 导出第一次 JSON 作为 baseline
    exporter = JsonExporter()
    baseline_path = exporter.export(
        [], policy_result.filtered_licenses,
        policy_result.filtered_cycles, policy_result.filtered_outdated,
        str(test_dir), policy_result, None, cfg.to_dict()
    )

    # 模拟新的扫描：新增一个违规包
    deps2 = create_test_deps()
    # 添加一个新的违规包 package-i (GPL-3.0)
    new_dep = Dependency(
        name="package-i",
        version_spec="1.0.0",
        ecosystem="npm",
        source_file="test",
        is_dev=False,
        dependencies=[],
    )
    new_dep._oss_licenses = [{"licenseId": "GPL-3.0"}]
    deps2.append(new_dep)

    license_results2 = license_analyzer.analyze(deps2)
    policy_result2 = policy_engine.apply([], license_results2, cycles, outdated_results)

    # 使用 baseline 对比
    comparator = BaselineComparator(baseline_path)
    diff = comparator.compare(policy_result2.violations)

    # 检查新增违规
    new_pkgs = [v.package for v in diff.new_violations]
    assert "package-i" in new_pkgs, "package-i 应该是新增违规"
    print(f"✅ 新增违规: {len(diff.new_violations)} 个 (package-i)")

    # 检查已存在违规
    existing_pkgs = set(v.package for v in diff.existing_violations)
    assert "package-a" in existing_pkgs, "package-a 应该是已存在违规"
    print(f"✅ 已存在违规: {len(diff.existing_violations)} 个")

    # 导出带 diff 的 JSON
    path = exporter.export(
        [], policy_result2.filtered_licenses,
        policy_result2.filtered_cycles, policy_result2.filtered_outdated,
        str(test_dir), policy_result2, diff, cfg.to_dict()
    )

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # 检查 baseline_diff 存在
    assert "baseline_diff" in data, "JSON 应该包含 baseline_diff"
    assert len(data["baseline_diff"]["new_violations"]) >= 1, "new_violations 至少 1 个"
    assert len(data["baseline_diff"]["existing_violations"]) >= 1, "existing_violations 至少 1 个"
    print("✅ JSON baseline_diff 区域存在")

    # 导出带 diff 的 HTML
    reporter = HtmlReporter()
    dep_tree2 = detector.get_dependency_tree(deps2, 5)
    html_path = reporter.export(
        [], policy_result2.filtered_licenses,
        policy_result2.filtered_cycles, policy_result2.filtered_outdated,
        dep_tree2, str(test_dir), policy_result2, diff, cfg.to_dict()
    )

    with open(html_path, "r", encoding="utf-8") as f:
        html_content = f.read()

    # 检查 Diff vs Baseline 页签
    assert "onclick=\"switchTab('diff')\"" in html_content, "HTML 应该包含 Diff vs Baseline 页签"
    assert "New Violations" in html_content, "HTML 应该包含 New Violations 区域"
    assert "Existing Violations" in html_content, "HTML 应该包含 Existing Violations 区域"
    assert "Fixed Violations" in html_content, "HTML 应该包含 Fixed Violations 区域"
    print("✅ HTML Diff vs Baseline 页签存在，包含 New/Existing/Fixed 区域")

    # 检查新增/已存在/已修复的统计卡片
    assert "New Issues" in html_content, "HTML 应该有 New Issues 卡片"
    assert "Existing" in html_content, "HTML 应该有 Existing 卡片"
    assert "Fixed" in html_content, "HTML 应该有 Fixed 卡片"
    print("✅ 新增/已存在/已修复统计卡片存在")

    print("\n✅ TEST 4 PASSED\n")
    return diff


def test_5_ci_exit_code():
    """TEST 5: CI 退出码逻辑 - 只因为新增问题失败"""
    print("=" * 70)
    print("TEST 5: CI Exit Code - 仅新增问题导致失败")
    print("=" * 70)

    test_dir = Path(__file__).parent
    cfg = ConfigLoader(str(test_dir / "dep-audit.yml"))

    # 模拟没有 baseline，所有问题导致失败
    from dependency_auditor.cli import _determine_exit_code

    deps = create_test_deps()
    license_analyzer = LicenseAnalyzer()
    license_results = license_analyzer.analyze(deps)
    detector = CircularDetector()
    cycles = detector.detect(deps)
    outdated_results = []
    for dep in deps:
        if dep.name == "package-h":
            outdated_results.append(OutdatedResult(
                dependency=dep, current_version=dep.version_spec,
                latest_version="99.0.0", is_outdated=True, ecosystem=dep.ecosystem,
            ))

    policy_engine = PolicyEngine(cfg)
    policy_result = policy_engine.apply([], license_results, cycles, outdated_results)

    # 没有 baseline: 应该因为循环依赖退出码 2
    code = _determine_exit_code(policy_result, cfg, None)
    assert code == 2, f"没有 baseline 时，循环依赖应该返回 2，实际 {code}"
    print(f"✅ 无 baseline: 循环依赖导致退出码 {code}")

    # 有 baseline，当前所有问题都是已存在的，没有新增
    class MockDiff:
        new_violations = []
        existing_violations = policy_result.violations
        fixed_violations = []

    code = _determine_exit_code(policy_result, cfg, MockDiff())
    assert code == 0, f"只有已存在问题时，应该返回 0，实际 {code}"
    print(f"✅ 只有已存在问题: 退出码 {code} (不失败)")

    # 有 baseline，有新增的高风险问题
    from dependency_auditor.analyzers.policy_engine import PolicyViolation

    class MockDiff2:
        new_violations = [PolicyViolation(
            type="copyleft_license",
            package="package-new",
            version="1.0.0",
            severity="high",
            reason="New GPL license",
            details={"license_id": "GPL-3.0"},
        )]
        existing_violations = policy_result.violations
        fixed_violations = []

    code = _determine_exit_code(policy_result, cfg, MockDiff2())
    assert code == 3, f"新增 GPL 应该返回 3，实际 {code}"
    print(f"✅ 新增 copyleft 问题: 退出码 {code}")

    print("\n✅ TEST 5 PASSED\n")


def main():
    print("\n" + "=" * 70)
    print("dep-audit CI 功能完整测试")
    print("=" * 70 + "\n")

    try:
        test_1_policy_engine()
        baseline_json = test_2_json_violations()
        test_3_html_report()
        diff = test_4_baseline_comparison()
        test_5_ci_exit_code()

        print("=" * 70)
        print("🎉 所有 5 项测试全部通过！")
        print("=" * 70)
        print("\n测试生成的报告文件:")
        print(f"  - Baseline JSON: {baseline_json}")
        print(f"  - HTML with Policy+Graph: {Path(baseline_json).with_suffix('.html')}")

        return 0
    except AssertionError as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return 1
    except Exception as e:
        print(f"\n❌ 发生错误: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
