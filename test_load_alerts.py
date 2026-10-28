from engine.database import load_alerts

alerts = load_alerts()

print("Loaded", len(alerts), "alerts")

for alert in alerts:
    print(alert)