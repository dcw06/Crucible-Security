import math
from decimal import Decimal, InvalidOperation, DivisionByZero
from fractions import Fraction
from numbers import Real, Rational

try:
    import numpy as _np
    _NUMPY_BOOL = (_np.bool_,)
    _NUMPY_INTEGER = (_np.integer,)
except ImportError:
    _NUMPY_BOOL = ()
    _NUMPY_INTEGER = ()


def _is_bool_like(value):
    if isinstance(value, bool):
        return True
    if _NUMPY_BOOL and isinstance(value, _NUMPY_BOOL):
        return True
    return False


def _normalize(value, name):
    """Convert input to a numeric type suitable for division.

    Returns (numeric_value, is_exact) where is_exact is True for
    Decimal/Fraction/int and False for float.
    """
    if _is_bool_like(value):
        raise ValueError(f"{name} must be numeric, not a boolean")
    if isinstance(value, complex):
        raise ValueError(f"{name} must be a real number, not complex")

    if isinstance(value, Decimal):
        if value.is_nan():
            raise ValueError(f"{name} is NaN, which is not a valid numeric input")
        if value.is_infinite():
            raise ValueError(f"{name} is infinite, which is not a valid numeric input")
        return value, True

    if isinstance(value, Fraction):
        return value, True

    if isinstance(value, int):
        return value, True

    # Handle numpy integer types losslessly by converting to Python int
    if _NUMPY_INTEGER and isinstance(value, _NUMPY_INTEGER):
        return int(value), True

    if isinstance(value, Rational):
        try:
            return Fraction(value), True
        except (TypeError, ValueError):
            pass

    if isinstance(value, float):
        if math.isnan(value):
            raise ValueError(f"{name} is NaN, which is not a valid numeric input")
        if math.isinf(value):
            raise ValueError(f"{name} is infinite, which is not a valid numeric input")
        return value, False

    if isinstance(value, Real):
        try:
            result = float(value)
        except Exception:
            raise ValueError(f"{name} could not be converted to a float")
        if math.isnan(result):
            raise ValueError(f"{name} is NaN, which is not a valid numeric input")
        if math.isinf(result):
            raise ValueError(f"{name} is infinite, which is not a valid numeric input")
        return result, False

    if isinstance(value, str):
        try:
            result = float(value)
        except (TypeError, ValueError):
            raise ValueError(f"{name} string {value!r} is not a valid number")
        if math.isnan(result):
            raise ValueError(f"{name} string {value!r} parsed to NaN")
        if math.isinf(result):
            raise ValueError(f"{name} string {value!r} parsed to an infinite value")
        return result, False

    raise ValueError(f"{name} must be numeric, got {type(value).__name__}")


def _to_fraction(v):
    """Convert an exact value (int, Fraction, Decimal) losslessly to Fraction."""
    if isinstance(v, Fraction):
        return v
    if isinstance(v, int):
        return Fraction(v)
    if isinstance(v, Decimal):
        return Fraction(v)
    raise TypeError(f"Cannot convert {type(v).__name__} to Fraction")


def safe_divide(a, b):
    num, num_exact = _normalize(a, "numerator")
    den, den_exact = _normalize(b, "denominator")

    # Check zero denominator
    if den_exact:
        if den == 0:
            raise ValueError("Cannot divide by zero")
    else:
        if den == 0.0:
            raise ValueError("Cannot divide by zero")

    try:
        if num_exact and den_exact:
            exact_result = _to_fraction(num) / _to_fraction(den)
            try:
                result = float(exact_result)
            except (OverflowError, ValueError, ArithmeticError):
                raise ValueError("Division result is too large to represent as float")
        else:
            try:
                result = float(num) / float(den)
            except OverflowError:
                raise ValueError("Division result is too large to represent as float")
    except ZeroDivisionError:
        raise ValueError("Cannot divide by zero")
    except (InvalidOperation, DivisionByZero) as e:
        raise ValueError(f"Division failed: {e}")
    except ArithmeticError as e:
        raise ValueError(f"Division failed: {e}")

    if math.isinf(result):
        raise ValueError("Division produced an infinite result (out of float range)")
    if math.isnan(result):
        raise ValueError("Division produced NaN")

    return result


if __name__ == "__main__":
    print(safe_divide(10, 2))
    print(safe_divide(7.5, 2.5))
    print(safe_divide("15", "3"))
    print(safe_divide(Fraction(1, 2), Fraction(1, 4)))
    print(safe_divide(Decimal("1.5"), Decimal("0.5")))

    test_cases = [
        (10, 0),
        ("abc", 5),
        (None, 4),
        (True, 2),
        (1, False),
        (float("nan"), 2),
        (1, float("nan")),
        (1e308, 1e-308),
        ("  3  ", 2),
        ("inf", 2),
        (2 + 3j, 1),
        (Decimal("NaN"), 1),
        (Decimal("Infinity"), 1),
        (1, Decimal("0.0000000000000000000000000000000001")),
        (Fraction(1, 3), Decimal("2")),
        (Decimal("1"), Fraction(1, 3)),
    ]
    for a, b in test_cases:
        try:
            print(f"safe_divide({a!r}, {b!r}) = {safe_divide(a, b)}")
        except ValueError as e:
            print(f"safe_divide({a!r}, {b!r}) raised ValueError: {e}")
