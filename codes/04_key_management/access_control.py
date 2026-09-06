from datetime import datetime, time


# Parameters: user_roles (list[str] or set[str]), object_allowed_roles (list[str] or set[str]) -> Output: bool
def rbac(user_roles, object_allowed_roles):
    return bool(set(user_roles) & set(object_allowed_roles))


# Parameters: user_attributes (dict), object_attributes (dict), environment (datetime) -> Output: bool
def abac(user_attributes, object_attributes, environment):
    # Example policy: employee may access an internal object during business hours.
    role_ok = user_attributes.get("role") in object_attributes.get("allowed_roles", [])
    classification_ok = (
        user_attributes.get("clearance", 0)
        >= object_attributes.get("classification", 0)
    )
    hour = environment.hour
    time_ok = 9 <= hour <= 17

    return role_ok and classification_ok and time_ok


# Parameters: subject_level (int), object_level (int) -> Output: bool
def bell_lapadula_read(subject_level, object_level):
    return subject_level >= object_level


# Parameters: subject_level (int), object_level (int) -> Output: bool
def bell_lapadula_write(subject_level, object_level):
    return subject_level <= object_level


# Parameters: subject_clearance (int), object_classification (int) -> Output: bool
def mac(subject_clearance, object_classification):
    return subject_clearance >= object_classification


# Parameters: now (datetime or time), start (datetime or time), end (datetime or time) -> Output: bool
def time_based_access(now, start, end):
    return start <= now <= end


# Parameters: trust (float), sensitivity (float), risk (float) -> Output: float
def probabilistic_access(trust, sensitivity, risk):
    # Simple educational scoring function.
    score = 0.6 * trust + 0.3 * (1 - sensitivity) + 0.1 * (1 - risk)
    return max(0.0, min(1.0, score))


if __name__ == "__main__":
    print("RBAC:", rbac(["employee", "manager"], ["manager"]))
    print("Bell-LaPadula read:", bell_lapadula_read(3, 2))
    print("Bell-LaPadula write:", bell_lapadula_write(3, 2))
    print("MAC:", mac(3, 2))
    print("Probabilistic access score:",
          probabilistic_access(0.9, 0.4, 0.2))
