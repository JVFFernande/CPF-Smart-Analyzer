from cpf_analyzer.heuristics import suspicious_flags

def test_flags_wrong_length():
    flags = suspicious_flags("123")
    codes = {f.code for f in flags}
    assert "WRONG_LENGTH" in codes

def test_flags_repeated():
    flags = suspicious_flags("000.000.000-00")
    codes = {f.code for f in flags}
    assert "REPEATED_SEQUENCE" in codes