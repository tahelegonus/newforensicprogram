# threat detecting SOC code for the program it will be getting updated and modified alot!!

import sqlite3 
import pandas as pd 

#connnect the database 
connection = sqlite3.connect("events.db")

#load the events into a dataframe
df = pd.read_sql(
    "SELECT * FROM events",
    connection
)
print("All Events: ")
print(df)

print("\nEvent Counts: ")
print(df["event_id"].value_counts())


#eventid meanings 

EVENTS = {
   4624: "Succesful Logon...",
   4625: "Failed Logon...",
   4688: "New Process Created...",
   4720: "User Account Created...", 
   4657: "Registry Value Modified...",
   4672: "Special Privileges assigned to new logon.... gasp",
   4698: "Schduled task created...",
   4728: "Member added to a secuirty enabed global group... gasp",
   5156: "Windows Filtering Patform allowed a connection...",
   5157: "Windows Filtering Platform blocked a connection...", 
   6416: "Extenal device recongized... gasp",
   7045: "Service Installed...",
   1116: "Malware Detected by Microsoft Defender....:O",
   1102: "Security audit log created..."
}

print("\nEvent Meanings: ")
for event_id in df["event_id"]:
    print("f{event_id}: {EVENTS.get(event_id), 'Uknown Event....')}")

#detection rule 1 --> multiple failed logins
    failed = df[df["event_id"] == 4625]
    if len(failed) >= 5: 
        print("ALERT!: Multiple failed logins detected...\n*gasps and mouth covers*")
      #detection rule 2 --> new users created 
        new_users = df[df["event_id"] == 4720]

        if not new_users.empty: 
            print("ALERT!: New user Account created...\n*gasps and mouth covers*")
            print("new users")
            #user deleted! gasp... mouth cover 
    deleted = df[df["event_id"] == 4726] 
    if not deleted.empty: 
        print("ALERT!: User accounr deleted")

        #process creation 
        processes = df[df["event_id"]] == 4688
        print("Processes creted: {len(processes)}")
        
        #admin log in 
        admins = df[df["user"] == "Administrator"]
        if not admins.empty: 
            print("Administrator account logged in.")

     #event ids occuring often 
        print(df["event_id"].value_counts())
            
    #logons by user 
            
    logons = df[df["event_id"] == 4624]
     
    print(logons.groupby("user".size()))

    #events from one computer 
    print(df.groupby("computer_name").size)

    #detecting suspicious image paths 

    if "mimikatz.exe" in event_id["image_path"].lower():
        print ("ALERT!: Mimikatz detected")

     #powershell
    if "powershell.exe" in event_id["image_path"].lower():
        print("Powershell execution detected")
    #command promt
    if event_id["image_path"].lower().endswith("cmd.exe"):
        print("Command Prompt Launched")
     #executbales from unknown/unusal locations 
    path = event_id["image_path"].lower 
    if "users\\public" in path: 
        print("Executable launched from public folder")
    #executables from temp direcotries 

    path = event_id["image_path"].lower()
    if "\\temp\\" in path:
        print("Executable launched from temp directory")

    #exe from downloads
    path = event_id[ "imapage_path"].lower
    if"\\downlaods\\" in path:
        print("Executable launched from downloads ") 
    #exe from app data 
    path = event_id[ "imapage_path"].lower
    if"\\appdata\\" in path:
        print("Executable launched from AppData ") 
    #exe from public folder 
    path = event_id[ "imapage_path"].lower
    if"\\users\\public\\" in path:
        print("Executable launched from AppData ")
    #exe from suspicious directories 
    path = event_id["image_path"].lower
    suspicious_dirs = [

        "\\users\\public\\",
        "\\temp\\",
        "\\downloads\\",
        "\\appdata",
    ]

    if any( d in path for d in suspicious_dirs):
        print ("Executable launched from suspicious direcotry: {path}")
    #executable with double extension

    import re 
    filename = event_id["imagepath"].lower()
    if re.search(r"\.(pdf|doc|docx|xls|xlsx|jpg|png)\.exe$", filename):
        print("possible masquerding executable")       
    #exe with random looking file name 
    import re 
    name = event_id["image_path"].lower()
    if re.fullmatch("[a-z0-9]{10,}\.exe", name):
        print("Random looking exe name...??")
                           
    #exe launched from zip extraction folder 

    path = event_id["image_path"].lower()
    if ".zip" in path or "\\extracted\\" in path:
        print("Executable launched from extracted archive")
    #exe launched from user profile
    
    path = event_id["image_path"].lower()
    if path.startswith("c:\\users\\") and "\\program files\\" not in path:
        print("Executable launched from user profile")
    
   #executable from removable drive
    path = event_id["image_path"].lower()
    if path.startswith(("e\\", "f:\\", "g:\\")):
      print("Executable launched from removable drive")
   #executable hidden in appdata locations  
    path = event_id["image_path"].lower()
    locations =[
    "\\appdata\\roming\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\local\\"
    ]
    if any (loc in path for loc in locations):
        print("Executable launched from hidden user application data.") 

   #unassigned exe outside program files 
    path = event_id["image_path"].lower()

    trusted = [
     "c:\\windows\\",
     "c:\\programfiles\\",
     "c:\\programfiles (x86)\\"
    ]
    if not any (path.startswith(p) for p in trusted):
        print("Executable running ouside trusted installation directories")
   
   #script launched with downloads
    path = event_id["image_path"].lower()
    extensions = (".ps1", ".vbs", ".js", ".hta", ".bat", ".cmd")
    if "\\downloads\\" in path and path.endswith(extensions):
        print("Script executed from downloads")
   #executable with suspicious file name
    name = event_id["image_path"].lower()

suspicious = [
    "update.exe",
    "invoice.exe",
    "payment.exe",
    "scan.exe",
    "document.exe",
    "chrome_update.exe"
    ]
if name in suspicious:
    print("Suspicious executable name")

   #executable in one drive
    path = event["image_path"]()

if "\\onedrive\\" in path:
    print("Executable launched from one drive")


    #timestamps 
#from  datetime import datetime

from datetime import datetime 
hour = datetime.fromtimestamp(event_id["timestamp"]).hour

if hour <5 or hour >23:
    print ("Executable launched during unusal hours")

#timestamps out of normal busniess hours 
from datetime import datetime 

time = datetime.strptime(event_id["timestanmp"],"%Y-%m-%d %H:%M:%S")

if time.hour < 8 or time.hour > 18:
    print("After-hours activity") 
#log clearing 
if event["event_id"]==1102:
    print("Security logs were cleared" )

#detect ransomeware indicators 

if "encryptor .exe" in event["image_path"].lower():
    print("Possible Ransomeware")

if event ["action"] == "ransomeware_execution":
    print("Possible ransomeware exe3cution")

#risk scoring 


risk = 0

if event["level"] == "Critical":
    risk += 10

if event["event_id"] == 4688:
    risk += 3

if "powershell.exe" in event["image_path"].lower():
    risk += 5

if "mimikatz" in event["image_path"].lower():
    risk += 20

if "currentversion\\run" in event["registry_path"].lower():
    risk += 15

print(risk)

#detect malware execution: 
bad_words = [
    "mimikatz",
    "encryptor",
    "dumplsass",
    "procdump",
    "invoice.exe"
]

path = event_id["image_path"].lower()

for word in bad_words:
    if word in path:
        print("Known suspicious executable")

###if event["parent_process"]== "winword.exe\"
