from cpf_analyzer.core import validate_cpf, calc_check_digits, generate_fake_cpf, only_digits

def test_calc_check_digits_known_example():
    # Exemplo: base 529982247 -> DV 25 (bem conhecido)
    assert calc_check_digits("529982247") == "25"

def test_validate_valid_cpf():
    ok, digits, reason = validate_cpf("529.982.247-25")
    assert ok is True
    assert digits == "52998224725"
    assert reason is None

def test_validate_repeated_invalid():
    ok, _, reason = validate_cpf("111.111.111-11")
    assert ok is False
    assert "Sequência repetida" in reason

def test_generate_fake_is_valid():
    cpf = generate_fake_cpf(formatted=True)
    ok, _, _ = validate_cpf(cpf)
    assert ok is True

def test_only_digits():
    assert only_digits("529.982.247-25") == "52998224725"