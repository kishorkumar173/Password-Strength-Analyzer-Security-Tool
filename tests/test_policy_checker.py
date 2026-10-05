"""Unit tests for Policy Checker and Hashing Demonstration."""
from backend.services.policy_checker import PasswordPolicyChecker
from backend.services.hashing_demo import demonstrate_hashing, verify_demo_password

def test_policy_checker_pass():
    checker = PasswordPolicyChecker(min_length=12, reject_common=True)
    res = checker.evaluate("XyloPhone-Orchestra-9821!")
    assert res["status"] == "PASS"
    assert res["passed"] is True

def test_policy_checker_fail_length():
    checker = PasswordPolicyChecker(min_length=12)
    res = checker.evaluate("short")
    assert res["status"] == "FAIL"
    assert res["failed_count"] > 0

def test_policy_checker_fail_common():
    checker = PasswordPolicyChecker(min_length=8, reject_common=True)
    res = checker.evaluate("password123")
    assert res["status"] == "FAIL"

def test_hashing_demo_derivation_and_verify():
    test_pwd = "DemoTestSyntheticPassword#99"
    demo_out = demonstrate_hashing(test_pwd, iterations=10000)
    assert demo_out["salt_hex"] is not None
    assert len(demo_out["salt_hex"]) == 32  # 16 bytes in hex

    storage_str = demo_out["slow_hash"]["output"]
    verify_res = verify_demo_password(test_pwd, storage_str)
    assert verify_res["verified"] is True

    verify_wrong = verify_demo_password("WrongPassword123!", storage_str)
    assert verify_wrong["verified"] is False
