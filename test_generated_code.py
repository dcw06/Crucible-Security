import math
import pytest
from decimal import Decimal
from fractions import Fraction
from generated_code import safe_divide


class TestNormalDivision:
    def test_simple_positive_division(self):
        assert safe_divide(10, 2) == pytest.approx(5.0)

    def test_negative_numerator(self):
        assert safe_divide(-10, 2) == pytest.approx(-5.0)

    def test_negative_denominator(self):
        assert safe_divide(10, -2) == pytest.approx(-5.0)

    def test_both_negative(self):
        assert safe_divide(-10, -2) == pytest.approx(5.0)

    def test_non_evenly_divisible(self):
        assert safe_divide(7, 2) == pytest.approx(3.5)

    def test_zero_numerator(self):
        assert safe_divide(0, 5) == pytest.approx(0.0)

    def test_zero_numerator_fraction(self):
        assert safe_divide(Fraction(0, 5), 3) == pytest.approx(0.0)


class TestIntegerTypes:
    def test_two_ints(self):
        assert safe_divide(100, 4) == pytest.approx(25.0)

    def test_large_int(self):
        assert safe_divide(10**18, 10**9) == pytest.approx(1e9)

    def test_negative_ints(self):
        assert safe_divide(-50, 10) == pytest.approx(-5.0)


class TestFloatTypes:
    def test_two_floats(self):
        assert safe_divide(7.5, 2.5) == pytest.approx(3.0)

    def test_int_float_mix(self):
        assert safe_divide(10, 2.5) == pytest.approx(4.0)

    def test_float_int_mix(self):
        assert safe_divide(7.5, 3) == pytest.approx(2.5)

    def test_small_float(self):
        assert safe_divide(0.1, 0.2) == pytest.approx(0.5)


class TestStringInputs:
    def test_string_integers(self):
        assert safe_divide("15", "3") == pytest.approx(5.0)

    def test_string_floats(self):
        assert safe_divide("7.5", "2.5") == pytest.approx(3.0)

    def test_string_with_whitespace(self):
        # float() accepts leading/trailing whitespace
        assert safe_divide("  3  ", 2) == pytest.approx(1.5)

    def test_invalid_string_numerator(self):
        with pytest.raises(ValueError):
            safe_divide("abc", 5)

    def test_invalid_string_denominator(self):
        with pytest.raises(ValueError):
            safe_divide(5, "xyz")

    def test_empty_string(self):
        with pytest.raises(ValueError):
            safe_divide("", 2)

    def test_string_inf_raises(self):
        with pytest.raises(ValueError):
            safe_divide("inf", 2)

    def test_string_nan_raises(self):
        with pytest.raises(ValueError):
            safe_divide("nan", 2)


class TestDivisionByZero:
    def test_int_zero(self):
        with pytest.raises(ValueError):
            safe_divide(10, 0)

    def test_float_zero(self):
        with pytest.raises(ValueError):
            safe_divide(10, 0.0)

    def test_negative_float_zero(self):
        with pytest.raises(ValueError):
            safe_divide(10, -0.0)

    def test_string_zero(self):
        with pytest.raises(ValueError):
            safe_divide(10, "0")

    def test_string_zero_float(self):
        with pytest.raises(ValueError):
            safe_divide(10, "0.0")

    def test_string_negative_zero(self):
        with pytest.raises(ValueError):
            safe_divide(10, "-0")

    def test_string_zero_with_whitespace(self):
        with pytest.raises(ValueError):
            safe_divide(10, " 0 ")

    def test_decimal_zero(self):
        with pytest.raises(ValueError):
            safe_divide(10, Decimal("0"))

    def test_decimal_negative_zero(self):
        with pytest.raises(ValueError):
            safe_divide(10, Decimal("-0"))

    def test_fraction_zero(self):
        with pytest.raises(ValueError):
            safe_divide(10, Fraction(0))


class TestNaNInputs:
    def test_nan_numerator(self):
        with pytest.raises(ValueError):
            safe_divide(float("nan"), 2)

    def test_nan_denominator(self):
        with pytest.raises(ValueError):
            safe_divide(2, float("nan"))

    def test_decimal_nan_numerator(self):
        with pytest.raises(ValueError):
            safe_divide(Decimal("NaN"), 1)

    def test_decimal_nan_denominator(self):
        with pytest.raises(ValueError):
            safe_divide(1, Decimal("NaN"))


class TestInfiniteInputs:
    def test_inf_numerator(self):
        with pytest.raises(ValueError):
            safe_divide(float("inf"), 2)

    def test_inf_denominator(self):
        with pytest.raises(ValueError):
            safe_divide(2, float("inf"))

    def test_neg_inf_numerator(self):
        with pytest.raises(ValueError):
            safe_divide(float("-inf"), 2)

    def test_decimal_inf(self):
        with pytest.raises(ValueError):
            safe_divide(Decimal("Infinity"), 1)

    def test_decimal_neg_inf(self):
        with pytest.raises(ValueError):
            safe_divide(1, Decimal("-Infinity"))


class TestBooleanInputs:
    def test_true_numerator(self):
        with pytest.raises(ValueError):
            safe_divide(True, 2)

    def test_false_denominator(self):
        with pytest.raises(ValueError):
            safe_divide(1, False)

    def test_true_true(self):
        with pytest.raises(ValueError):
            safe_divide(True, True)

    def test_false_numerator(self):
        with pytest.raises(ValueError):
            safe_divide(False, 2)


class TestNoneAndInvalidTypes:
    def test_none_numerator(self):
        with pytest.raises(ValueError):
            safe_divide(None, 4)

    def test_none_denominator(self):
        with pytest.raises(ValueError):
            safe_divide(4, None)

    def test_list_input(self):
        with pytest.raises(ValueError):
            safe_divide([1, 2], 2)

    def test_dict_input(self):
        with pytest.raises(ValueError):
            safe_divide({}, 2)

    def test_object_input(self):
        with pytest.raises(ValueError):
            safe_divide(object(), 2)


class TestComplexNumbers:
    def test_complex_numerator(self):
        with pytest.raises(ValueError):
            safe_divide(2 + 3j, 1)

    def test_complex_denominator(self):
        with pytest.raises(ValueError):
            safe_divide(1, 2 + 3j)

    def test_pure_imaginary(self):
        with pytest.raises(ValueError):
            safe_divide(1j, 1)


class TestDecimalInputs:
    def test_two_decimals(self):
        assert safe_divide(Decimal("1.5"), Decimal("0.5")) == pytest.approx(3.0)

    def test_decimal_division(self):
        assert safe_divide(Decimal("10"), Decimal("4")) == pytest.approx(2.5)

    def test_negative_decimal(self):
        assert safe_divide(Decimal("-9"), Decimal("3")) == pytest.approx(-3.0)


class TestFractionInputs:
    def test_two_fractions(self):
        assert safe_divide(Fraction(1, 2), Fraction(1, 4)) == pytest.approx(2.0)

    def test_fraction_division(self):
        assert safe_divide(Fraction(3, 4), Fraction(1, 2)) == pytest.approx(1.5)

    def test_negative_fraction(self):
        assert safe_divide(Fraction(-1, 2), Fraction(1, 4)) == pytest.approx(-2.0)

    def test_zero_fraction_numerator(self):
        assert safe_divide(Fraction(0, 5), Fraction(1, 2)) == pytest.approx(0.0)


class TestMixedDecimalFraction:
    def test_fraction_over_decimal(self):
        assert safe_divide(Fraction(1, 3), Decimal("2")) == pytest.approx(1/6)

    def test_decimal_over_fraction(self):
        assert safe_divide(Decimal("1"), Fraction(1, 3)) == pytest.approx(3.0)

    def test_int_over_decimal(self):
        assert safe_divide(1, Decimal("4")) == pytest.approx(0.25)

    def test_int_over_fraction(self):
        assert safe_divide(2, Fraction(1, 2)) == pytest.approx(4.0)

    def test_decimal_over_int(self):
        assert safe_divide(Decimal("10"), 4) == pytest.approx(2.5)


class TestOverflow:
    def test_large_float_division_overflow(self):
        # 1e308 / 1e-308 = 1e616, overflows float to inf -> ValueError
        with pytest.raises(ValueError):
            safe_divide(1e308, 1e-308)

    def test_huge_int_over_tiny_float(self):
        with pytest.raises(ValueError):
            safe_divide(10**400, 1e-10)

    def test_huge_exact_division_overflow(self):
        # Exact int/Fraction division producing a value too large for float
        with pytest.raises(ValueError):
            safe_divide(10**400, Fraction(1, 10**400))