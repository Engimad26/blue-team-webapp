from pathlib import Path
import yaml

from .rules.common import make_alert

SIGMA_FOLDER = Path(__file__).parent.parent / "sigma_rules"


# ----------------------------------------------------
# Rule Loader
# ----------------------------------------------------

def load_sigma_rules():
    rules = []

    if not SIGMA_FOLDER.exists():
        return rules

    for file in SIGMA_FOLDER.glob("*.yml"):

        try:
            with open(file, "r", encoding="utf-8") as f:
                rule = yaml.safe_load(f)

            if not isinstance(rule, dict):
                continue

            rule["_filename"] = file.name
            rules.append(rule)

        except Exception as e:
            print(f"[Sigma] Failed loading {file.name}: {e}")

    return rules


# ----------------------------------------------------
# Helpers
# ----------------------------------------------------

def normalize_event(event):
    """
    Convert every event key to lowercase so matching
    becomes case-insensitive.
    """

    return {
        str(k).lower(): str(v)
        for k, v in event.items()
    }


def split_field(field):

    if "|" not in field:
        return field.lower(), "contains"

    left, right = field.split("|", 1)

    return left.lower(), right.lower()


# ----------------------------------------------------
# Operators
# ----------------------------------------------------

def operator_contains(actual, expected):
    actual = str(actual).lower()
    expected = str(expected).lower()
    return expected in actual


def operator_equals(actual, expected):
    actual = str(actual).lower()
    expected = str(expected).lower()
    return actual == expected


def operator_startswith(actual, expected):
    actual = str(actual).lower()
    expected = str(expected).lower()
    return actual.startswith(expected)


def operator_endswith(actual, expected):
    actual = str(actual).lower()
    expected = str(expected).lower()
    return actual.endswith(expected)


def operator_contains_any(actual, expected):
    actual = str(actual).lower()

    if not isinstance(expected, list):
        expected = [expected]

    return any(str(item).lower() in actual for item in expected)


def operator_contains_all(actual, expected):
    actual = str(actual).lower()

    if not isinstance(expected, list):
        expected = [expected]

    return all(str(item).lower() in actual for item in expected)


def operator_regex(actual, expected):
    import re

    actual = str(actual)

    return re.search(str(expected), actual, re.IGNORECASE) is not None

OPERATORS = {
    "contains": operator_contains,
    "equals": operator_equals,
    "startswith": operator_startswith,
    "endswith": operator_endswith,
    "contains_any": operator_contains_any,
    "contains_all": operator_contains_all,
    "re": operator_regex,
}
# ----------------------------------------------------
# Selection Matching
# ----------------------------------------------------

def match_field(event, field, expected):

    field, operator = split_field(field)

    actual = event.get(field, "")

    func = OPERATORS.get(operator)

    if func is None:
        return False

    return func(actual, expected)

def match_selection(event, selection):

    if not isinstance(selection, dict):
        return False

    for field, expected in selection.items():

        if not match_field(event, field, expected):
            return False

    return True


def evaluate_detection(event, detection):

    """
    Evaluate every selection in the detection block.

    Example:

    detection:
    selection:
    EventID: "4104"
    CommandLine|contains: powershell

    filter:
    User: SYSTEM

    Returns:

    {
        "selection": True,
        "filter": False
    }
    """

    results = {}

    for name, value in detection.items():

        if name == "condition":
            continue

        results[name] = match_selection(event, value)

    return results
# ----------------------------------------------------
# Condition Parser
# ----------------------------------------------------

def evaluate_condition(results, condition):

    condition = condition.strip()

    # condition: selection
    if condition in results:
        return results[condition]

    # selection1 and selection2
    if " and " in condition:

        parts = [p.strip() for p in condition.split(" and ")]

        value = True

        for part in parts:

            if part.startswith("not "):

                name = part[4:].strip()

                value = value and (not results.get(name, False))

            else:

                value = value and results.get(part, False)

        return value

    # selection1 or selection2
    if " or " in condition:

        parts = [p.strip() for p in condition.split(" or ")]

        value = False

        for part in parts:

            if part.startswith("not "):

                name = part[4:].strip()

                value = value or (not results.get(name, False))

            else:

                value = value or results.get(part, False)

        return value

    # not selection
    if condition.startswith("not "):

        name = condition[4:].strip()

        return not results.get(name, False)

    return False
# ----------------------------------------------------
# Sigma Engine
# ----------------------------------------------------

def run_sigma(events):

    alerts = []

    rules = load_sigma_rules()

    for event in events:

        event_ci = normalize_event(event)

        for rule in rules:

            detection = rule.get("detection", {})

            if not detection:
                continue

            # Evaluate every selection block
            results = evaluate_detection(event_ci, detection)

            # Read Sigma condition
            condition = detection.get("condition", "selection")

            # Does the rule match?
            if not evaluate_condition(results, condition):
                continue

            mitre = rule.get("mitre", {})

            alerts.append(
                make_alert(
                    timestamp=event.get("timestamp", ""),
                    source="Sigma",
                    rule=rule.get("title", "Sigma Rule"),
                    mitre=mitre.get("id", ""),
                    tactic=mitre.get("tactic", ""),
                    technique=mitre.get("technique", ""),
                    score=90,
                    message=rule.get(
                        "description",
                        f"Matched Sigma rule '{rule.get('title','Sigma Rule')}'"
                    ),
                    ip=event.get("ip", ""),
                    user=event.get("user", ""),
                    host=event.get("host", ""),
                    evidence={
                        "rule_file": rule.get("_filename", ""),
                        "event": event,
                    },
                )
            )

    return alerts