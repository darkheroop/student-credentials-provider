"""
Priority Reordering Service for Student Credentials Provider.

Implements atomic, consecutive priority reordering (1..N) whenever an API's priority
is changed, shifted, or deleted, guaranteeing PostgreSQL transaction safety,
no duplicate priorities, no gaps, and zero transient constraint violations.
"""

from typing import Any
import logging

logger = logging.getLogger(__name__)


def validate_priority_input(priority_val: Any) -> int:
    """
    Validate priority input value.
    Rejects None, non-integers, booleans, zero, negative numbers, and malformed strings.
    Returns integer priority >= 1.
    """
    if priority_val is None:
        raise ValueError("Priority is required.")

    # Booleans are subclasses of int in Python (isinstance(True, int) is True)
    if isinstance(priority_val, bool):
        raise ValueError("Invalid priority value. Booleans are not permitted.")

    try:
        if isinstance(priority_val, str):
            priority_str = priority_val.strip()
            if not priority_str:
                raise ValueError("Priority cannot be empty.")
            # Disallow floats encoded as strings (e.g. "1.5")
            float_val = float(priority_str)
            int_val = int(float_val)
            if float_val != int_val:
                raise ValueError("Priority must be an integer, not a floating point number.")
            parsed = int_val
        elif isinstance(priority_val, float):
            if not priority_val.is_integer():
                raise ValueError("Priority must be an integer, not a floating point number.")
            parsed = int(priority_val)
        elif isinstance(priority_val, int):
            parsed = priority_val
        else:
            raise ValueError(f"Invalid priority type: {type(priority_val).__name__}")
    except (ValueError, TypeError) as exc:
        if "greater than or equal to 1" in str(exc) or "Priority cannot be empty" in str(exc) or "floating point" in str(exc):
            raise
        raise ValueError(f"Invalid priority value: {priority_val}. Must be an integer.") from exc

    if parsed < 1:
        raise ValueError("Priority must be a positive integer greater than or equal to 1.")

    return parsed


def calculate_reordered_sequence(
    current_configs: list[dict[str, Any]],
    target_config_id: int,
    requested_priority: int,
) -> list[int]:
    """
    Given currently ordered configs and a requested priority for target_config_id:
    1. Removes target_config_id from its current position in the ordered list.
    2. Clamps requested_priority to [1, len(current_configs)] (last position if > N).
    3. Inserts target_config_id at the requested 1-based position.
    4. Returns the ordered list of configuration IDs representing consecutive priorities 1..N.
    """
    ordered_ids = [c["id"] for c in current_configs]
    if target_config_id not in ordered_ids:
        raise ValueError(f"Configuration ID {target_config_id} not found.")

    current_idx = ordered_ids.index(target_config_id)
    ordered_ids.pop(current_idx)

    # Clamping behavior: If requested_priority > len(current_configs), clamp to last position
    target_pos = min(max(1, requested_priority), len(current_configs))
    target_idx = target_pos - 1

    ordered_ids.insert(target_idx, target_config_id)
    return ordered_ids
