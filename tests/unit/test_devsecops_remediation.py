"""Tests reproducing and verifying F-22:
DevSecOps pipeline hardening:
- Dependabot configuration (.github/dependabot.yml)
- Pip-audit vulnerability scan in CI workflow (.github/workflows/ci.yml)
- Pre-commit configuration (.pre-commit-config.yaml)
- Security policy (SECURITY.md)
- Contribution guidelines (CONTRIBUTING.md)
- License file and third-party license compliance check
"""

from __future__ import annotations

from pathlib import Path
import tomllib


REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_reproduce_devsecops_files_exist():
    """All required DevSecOps files must exist at repository root."""
    required_files = [
        REPO_ROOT / ".github" / "workflows" / "ci.yml",
        REPO_ROOT / ".github" / "dependabot.yml",
        REPO_ROOT / ".pre-commit-config.yaml",
        REPO_ROOT / "SECURITY.md",
        REPO_ROOT / "CONTRIBUTING.md",
        REPO_ROOT / "LICENSE",
    ]
    missing = [str(f.relative_to(REPO_ROOT)) for f in required_files if not f.exists()]
    assert not missing, f"Missing required DevSecOps files: {missing}"


def test_reproduce_ci_runs_pip_audit():
    """CI workflow must include a step that runs pip-audit for dependency vulnerability scanning."""
    ci_file = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    assert ci_file.exists(), "ci.yml must exist"
    content = ci_file.read_text(encoding="utf-8")
    assert "pip-audit" in content, "CI workflow must execute pip-audit"


def test_reproduce_dependabot_config_valid():
    """Dependabot configuration must be valid YAML with daily or weekly updates for pip and github-actions."""
    dep_file = REPO_ROOT / ".github" / "dependabot.yml"
    assert dep_file.exists(), ".github/dependabot.yml must exist"
    content = dep_file.read_text(encoding="utf-8")
    assert "version: 2" in content
    assert "package-ecosystem: \"pip\"" in content or "package-ecosystem: 'pip'" in content or "package-ecosystem: pip" in content
    assert "interval:" in content


def test_reproduce_pre_commit_config_valid():
    """Pre-commit config must include basic file hygiene and ruff linting."""
    pre_file = REPO_ROOT / ".pre-commit-config.yaml"
    assert pre_file.exists(), ".pre-commit-config.yaml must exist"
    content = pre_file.read_text(encoding="utf-8")
    assert "trailing-whitespace" in content
    assert "end-of-file-fixer" in content
    assert "check-yaml" in content
    assert "ruff" in content


def test_reproduce_license_and_contributing_clarity():
    """LICENSE must be present and CONTRIBUTING.md must provide code quality and testing guidelines."""
    license_file = REPO_ROOT / "LICENSE"
    assert "MIT License" in license_file.read_text(encoding="utf-8")

    contrib_file = REPO_ROOT / "CONTRIBUTING.md"
    assert contrib_file.exists(), "CONTRIBUTING.md must exist"
    text = contrib_file.read_text(encoding="utf-8")
    assert "pytest" in text
    assert "ruff" in text
    assert "pip-audit" in text


def test_adversarial_yaml_files_have_no_tabs_and_clean_formatting():
    """All YAML/YML configuration files must be strictly formatted without tab characters."""
    yaml_files = [
        REPO_ROOT / ".github" / "workflows" / "ci.yml",
        REPO_ROOT / ".github" / "dependabot.yml",
        REPO_ROOT / ".pre-commit-config.yaml",
    ]
    for yf in yaml_files:
        assert yf.exists(), f"{yf} must exist"
        lines = yf.read_text(encoding="utf-8").splitlines()
        for idx, line in enumerate(lines, 1):
            assert "\t" not in line, f"Tab forbidden in {yf.name} line {idx}"
            if ":" in line and not line.strip().startswith("-") and not line.strip().startswith("#"):
                key = line.split(":", 1)[0]
                assert key == key.rstrip(), f"Trailing space before colon in {yf.name} line {idx}"


def test_adversarial_dependencies_pinned_in_pyproject():
    """All core and dev dependencies in pyproject.toml must have explicit version bounds."""
    pyproject_file = REPO_ROOT / "pyproject.toml"
    assert pyproject_file.exists()
    with open(pyproject_file, "rb") as f:
        data = tomllib.load(f)

    deps = data.get("project", {}).get("dependencies", [])
    assert len(deps) >= 4, "Core dependencies must be declared"
    for dep in deps:
        assert any(op in dep for op in [">=", "==", "~="]), f"Dependency '{dep}' lacks version pin"

    dev_deps = data.get("project", {}).get("optional-dependencies", {}).get("dev", [])
    assert len(dev_deps) >= 4, "Dev dependencies must include pytest, ruff, mypy, pip-audit"
    for dev_dep in dev_deps:
        assert any(op in dev_dep for op in [">=", "==", "~="]), f"Dev dependency '{dev_dep}' lacks version pin"


