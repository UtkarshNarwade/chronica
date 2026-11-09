"""Test packaging, dependency segregation, and configuration integrity (T0-1)."""

import importlib
from pathlib import Path
import toml


def test_pyproject_toml_structure():
    """Verify pyproject.toml exists and properly declares dependencies and tooling."""
    root = Path(__file__).resolve().parent.parent.parent
    pyproject_path = root / "pyproject.toml"
    assert pyproject_path.exists(), "pyproject.toml must exist"

    with open(pyproject_path, "r", encoding="utf-8") as f:
        data = toml.load(f)

    project = data.get("project", {})
    assert project.get("name") == "chronica"
    assert "streamlit" in "".join(project.get("dependencies", []))
    assert "pytest" not in "".join(project.get("dependencies", []))

    dev_deps = project.get("optional-dependencies", {}).get("dev", [])
    assert any("pytest" in d for d in dev_deps)
    assert any("ruff" in d for d in dev_deps)
    assert any("mypy" in d for d in dev_deps)

    assert "ruff" in data.get("tool", {})
    assert "mypy" in data.get("tool", {})


def test_requirements_txt_excludes_dev_dependencies():
    """Verify runtime requirements.txt does not contain pytest or testing tools."""
    root = Path(__file__).resolve().parent.parent.parent
    req_path = root / "requirements.txt"
    assert req_path.exists(), "requirements.txt must exist"

    content = req_path.read_text(encoding="utf-8")
    assert "pytest" not in content, "pytest must not be listed in runtime requirements.txt"


def test_src_package_importability():
    """Verify editable package layout allows importing root src module."""
    mod = importlib.import_module("src.pipeline")
    assert hasattr(mod, "ForensicPipeline")


def test_ci_workflow_specification():
    """Verify GitHub Actions CI workflow file exists and defines test matrix (T0-2)."""
    root = Path(__file__).resolve().parent.parent.parent
    ci_path = root / ".github" / "workflows" / "ci.yml"
    assert ci_path.exists(), "CI workflow file .github/workflows/ci.yml must exist"

    content = ci_path.read_text(encoding="utf-8")
    assert "push:" in content
    assert "pull_request:" in content
    assert '"3.11"' in content or "'3.11'" in content
    assert '"3.12"' in content or "'3.12'" in content
    assert "ruff check" in content
    assert "mypy" in content
    assert "pytest" in content


def test_ci_workflow_yaml_syntax():
    """Adversarial check: ensure CI file has no tabs or corrupted multiline indentation."""
    root = Path(__file__).resolve().parent.parent.parent
    ci_path = root / ".github" / "workflows" / "ci.yml"
    lines = ci_path.read_text(encoding="utf-8").splitlines()
    for idx, line in enumerate(lines, 1):
        assert "\t" not in line, f"Tab character forbidden in YAML at line {idx}"
        # Validate colon key-value separator
        if ":" in line and not line.strip().startswith("-") and not line.strip().startswith("#"):
            key_part = line.split(":", 1)[0]
            assert key_part == key_part.rstrip(), f"Trailing whitespace before colon at line {idx}"


def test_dockerfile_and_streamlit_hardening():
    """Verify Dockerfile and hardened air-gapped Streamlit settings (T0-3)."""
    root = Path(__file__).resolve().parent.parent.parent
    dockerfile_path = root / "Dockerfile"
    assert dockerfile_path.exists(), "Dockerfile must exist"

    df_content = dockerfile_path.read_text(encoding="utf-8")
    assert "USER " in df_content, "Dockerfile must configure a non-root user"

    st_cfg_path = root / ".streamlit" / "config.toml"
    assert st_cfg_path.exists(), ".streamlit/config.toml must exist"

    with open(st_cfg_path, "r", encoding="utf-8") as f:
        cfg = toml.load(f)

    browser = cfg.get("browser", {})
    assert browser.get("gatherUsageStats") is False, "gatherUsageStats must be false"

    server = cfg.get("server", {})
    assert server.get("address") == "127.0.0.1", "server.address must be 127.0.0.1"
    assert server.get("address") != "0.0.0.0", "server.address must not bind to all interfaces"
    assert server.get("headless") is True, "server.headless must be true"

    client = cfg.get("client", {})
    assert client.get("showErrorDetails") is False, "client.showErrorDetails must be false"
    assert client.get("showErrorDetails") is not True, "showErrorDetails must never be true in production"


def test_plotly_installed_and_functional():
    """Verify plotly is installed and EntityGraphBuilder generates valid figures (T0-4)."""
    import plotly
    import plotly.graph_objects as go
    from src.forensic_tools import EntityGraphBuilder

    assert plotly.__version__ is not None
    builder = EntityGraphBuilder()
    fig = builder.build_plotly_graph([])
    assert isinstance(fig, go.Figure)




