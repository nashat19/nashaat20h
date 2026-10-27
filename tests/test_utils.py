from osintx.models import TargetType
from osintx.utils import detect_type, mask, normalize_phone, truncate

def test_detect_email():
    assert detect_type("user@example.com") is TargetType.EMAIL

def test_detect_phone():
    assert detect_type("+9647701234567") is TargetType.PHONE

def test_detect_domain():
    assert detect_type("example.com") is TargetType.DOMAIN

def test_detect_username():
    assert detect_type("some_user") is TargetType.USERNAME

def test_detect_ip():
    assert detect_type("8.8.8.8") is TargetType.IP

def test_mask():
    assert mask("abcdefgh", 2) == "ab****gh"

def test_normalize_phone():
    assert normalize_phone("00964 770 123 4567") == "+9647701234567"

def test_truncate():
    assert truncate("a" * 200, 10).endswith("…")
