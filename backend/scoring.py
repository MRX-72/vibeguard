# Each finding removes a share of the remaining "safety", so counts add up with
# diminishing returns: one Critical = 55, two = 80, one High = 25.
WEIGHT = {"Critical": 0.55, "High": 0.25, "Medium": 0.08, "Low": 0.02}
# A finding we couldn't confirm moves the grade half as much (§16: confidence is part of the score).
CONFIDENCE = {"Confirmed reachable": 1.0, "Likely": 1.0, "Needs review": 0.5}
GRADES = [(5, "A"), (25, "B"), (45, "C"), (70, "D"), (100, "F")]


def risk_score(findings):
    safe = 1.0
    for f in findings:
        if not f.is_false_positive:
            safe *= 1 - WEIGHT[f.severity] * CONFIDENCE[f.confidence]
    return round(100 * (1 - safe))


def grade(score):
    return next(g for limit, g in GRADES if score <= limit)
