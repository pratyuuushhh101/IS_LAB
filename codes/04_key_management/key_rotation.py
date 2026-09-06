from datetime import datetime, timedelta


# Parameters: number_of_keys (int), period_days (float) -> Output: float
def rotation_rate(number_of_keys, period_days):
    return number_of_keys / period_days


# Parameters: created_at (datetime), lifetime_days (float) -> Output: datetime
def expiry_time(created_at, lifetime_days):
    return created_at + timedelta(days=lifetime_days)


if __name__ == "__main__":
    n = int(input("Number of keys: "))
    days = float(input("Rotation period in days: "))

    created = datetime.now()
    lifetime = float(input("Key lifetime in days: "))

    print("Rotation rate:", rotation_rate(n, days), "keys/day")
    print("Created:", created)
    print("Expiry:", expiry_time(created, lifetime))
