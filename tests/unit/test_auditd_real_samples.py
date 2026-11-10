"""Real-world Linux auditd parser verification tests (F-01).

Format documented in Red Hat Enterprise Linux 8/9 Security Guide - Understanding Audit Log Files,
and Linux audit-userspace documentation for type=USER_AUTH, USER_LOGIN, and SYSCALL records.
"""

from src.parsers.auditd_parser import AuditdParser


def test_auditd_real_user_auth_failed_inside_quoted_msg():
    """Reproduce F-01: res=failed inside msg='...' must be parsed as AUTH_FAIL, not AUTH_SUCCESS."""
    parser = AuditdParser()
    # Real auditd USER_AUTH record with msg='...' single-quoted sub-block
    line = (
        "type=USER_AUTH msg=audit(1728123457.123:45678): pid=3124 uid=0 auid=1000 ses=5 "
        "subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 "
        "msg='op=PAM:authentication acct=\"alice\" exe=\"/usr/sbin/sshd\" hostname=192.168.1.50 addr=192.168.1.50 terminal=ssh res=failed'"
    )
    rec = parser.parse_line(line, line_number=1)
    assert rec.parse_status == "SUCCESS"
    assert rec.username == "alice", f"Expected username 'alice', got '{rec.username}'"
    assert rec.severity == "AUTH_FAIL", f"Expected severity 'AUTH_FAIL' on res=failed, got '{rec.severity}'"


def test_auditd_subj_never_used_as_username():
    """Reproduce F-01: subj (SELinux security context) must never be assigned as username."""
    parser = AuditdParser()
    # SYSCALL line with subj and no acct/user
    line = (
        'type=SYSCALL msg=audit(1728123456.789:12345): arch=c000003e syscall=59 success=yes exit=0 '
        'uid=0 auid=4294967295 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 exe="/bin/cat"'
    )
    rec = parser.parse_line(line, line_number=1)
    assert rec.username is None or rec.username == "root", f"Username should not be SELinux context, got: {rec.username}"
    assert "subj" not in str(rec.username)


def test_auditd_real_user_auth_success():
    """Adversarial check: res=success inside msg='...' must evaluate to AUTH_SUCCESS with clean username."""
    parser = AuditdParser()
    line = (
        "type=USER_AUTH msg=audit(1728123458.555:45679): pid=3124 uid=0 auid=1000 ses=5 "
        "msg='op=PAM:authentication acct=\"charlie\" exe=\"/usr/sbin/sshd\" hostname=192.168.1.60 addr=192.168.1.60 terminal=ssh res=success'"
    )
    rec = parser.parse_line(line, line_number=1)
    assert rec.parse_status == "SUCCESS"
    assert rec.username == "charlie"
    assert rec.severity == "AUTH_SUCCESS"
    assert rec.src_ip == "192.168.1.60"


def test_auditd_numeric_res_codes():
    """Adversarial check: res=0 must map to AUTH_FAIL, res=1 to AUTH_SUCCESS."""
    parser = AuditdParser()
    fail_line = "type=USER_LOGIN msg=audit(1728123459.001:45680): pid=123 uid=0 auid=1000 msg='acct=\"alice\" res=0'"
    rec_fail = parser.parse_line(fail_line, line_number=1)
    assert rec_fail.severity == "AUTH_FAIL"
    assert rec_fail.username == "alice"

    succ_line = "type=USER_LOGIN msg=audit(1728123459.002:45681): pid=123 uid=0 auid=1000 msg='acct=\"alice\" res=1'"
    rec_succ = parser.parse_line(succ_line, line_number=2)
    assert rec_succ.severity == "AUTH_SUCCESS"

