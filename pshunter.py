#intial database for the program

import json
import sqlite3


from tahelegonus import show_splash 
show_splash()

# Load the events
with open("scaryevent.json", "r") as file:
    events = json.load(file)

# Create the database
connection = sqlite3.connect("events.db")
cursor = connection.cursor()

# Create table
cursor.execute("""
CREATE TABLE IF NOT EXISTS events (
    event_id INTEGER,
    timestamp TEXT,
    user TEXT,
    action TEXT,
    computer_name TEXT,
    registry_path TEXT,
    image_path TEXT,
    source TEXT,
    level TEXT
)
""")

# Insert events
for event in events:
    cursor.execute("""
        INSERT INTO events (
            event_id,
            timestamp,
            user,
            action,
            computer_name,
            registry_path,
            image_path,
            source,
            level
            location,       
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event.get("event_id"),
        event.get("timestamp"),
        event.get("user"),
        event.get("action"),
        event.get("computer_name"),
        event.get("registry_path"),
        event.get("image_path"),
        event.get("source"),
        event.get("level"),
        event.get("location"),
    ))

connection.commit()
connection.close()

print("Events have been saved!")
print("TAHELEGONUS is running....\nteehee")
