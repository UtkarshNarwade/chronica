"""Headless Streamlit UI Verification Test using AppTest.

AIORI-3 PS-013 Invariant:
Every enterprise navigation module in app.py must execute cleanly with len(at.exception) == 0.
Every button and interactive control must execute with zero exceptions.
"""

from __future__ import annotations

from pathlib import Path
import pytest
from streamlit.testing.v1 import AppTest

APP_PY_PATH = str(Path(__file__).resolve().parent.parent.parent / "app.py")

ALL_MODULES = [
    "Security Overview",
    "Event Discovery & Timeline",
    "Threat Hunting & Topology",
    "Payload & IOC Analyzer",
    "Log Acquisition & Parsers",
    "Evidence Integrity & Ledger",
    "Clock-Skew Synchronization",
    "Diagnostics & Gap Taxonomy",
    "Forensic Reports & Export",
    "Synthetic Benchmark Suite",
    "Workspace & System Specs",
]


def test_headless_ui_all_modules_zero_errors():
    """Verify that every single module executes with ZERO exceptions via sidebar button navigation."""
    at = AppTest.from_file(APP_PY_PATH, default_timeout=30)
    at.run()

    # Initial launch must have 0 exceptions
    if at.exception:
        for exc in at.exception:
            print("INITIAL RUN EXCEPTION:", exc.value)
    assert len(at.exception) == 0, f"Exceptions on initial launch: {[e.value for e in at.exception]}"

    # Programmatically click every navigation button in the sidebar and assert 0 exceptions
    for mod in ALL_MODULES:
        btn = at.sidebar.button(key=f"nav_{mod}")
        assert btn is not None, f"Navigation button for '{mod}' missing from sidebar"
        btn.click().run()
        if at.exception:
            for exc in at.exception:
                print(f"EXCEPTION ON MODULE '{mod}':", exc.value)
        assert len(at.exception) == 0, f"Exceptions on module '{mod}': {[e.value for e in at.exception]}"
        assert at.session_state["nav_section"] == mod, f"Expected active module '{mod}', got '{at.session_state['nav_section']}'"


def test_headless_ui_interactive_actions_zero_errors():
    """Verify key button actions across modules execute with zero exceptions."""
    at = AppTest.from_file(APP_PY_PATH, default_timeout=30).run()
    assert len(at.exception) == 0

    # Test sync / refresh button
    if at.button(key="hud_sync_btn"):
        at.button(key="hud_sync_btn").click().run()
        assert len(at.exception) == 0

    # Test Payload Decoder recipe execution
    at.session_state["nav_section"] = "Payload & IOC Analyzer"
    at.run()
    assert len(at.exception) == 0
    if at.button(key="baker_exec_btn"):
        at.button(key="baker_exec_btn").click().run()
        assert len(at.exception) == 0

    # Test Evidence Integrity verification buttons
    at.session_state["nav_section"] = "Evidence Integrity & Ledger"
    at.run()
    assert len(at.exception) == 0
    if at.button(key="crypto_verify_btn"):
        at.button(key="crypto_verify_btn").click().run()
        assert len(at.exception) == 0
    if at.button(key="crypto_verify_chain_btn"):
        at.button(key="crypto_verify_chain_btn").click().run()
        assert len(at.exception) == 0

    # Test Synthetic Benchmark Suite scenario loaders and evaluator
    at.session_state["nav_section"] = "Synthetic Benchmark Suite"
    at.run()
    assert len(at.exception) == 0

    if at.button(key="load_scen_1_btn"):
        at.button(key="load_scen_1_btn").click().run()
        assert len(at.exception) == 0

    if at.button(key="load_scen_2_btn"):
        at.button(key="load_scen_2_btn").click().run()
        assert len(at.exception) == 0

    if at.button(key="load_scen_3_btn"):
        at.button(key="load_scen_3_btn").click().run()
        assert len(at.exception) == 0

    if at.button(key="benchmark_eval_btn"):
        at.button(key="benchmark_eval_btn").click().run()
        assert len(at.exception) == 0
