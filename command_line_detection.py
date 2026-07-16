import os

from command_line import (
#execution/ powershell T1059.001
ENCODED_COMMAND_PATTERNS,
POWERSHELL_EVASION_FLAGS,
POWERSHELL_KEYWORDS,
POWERSHELL_PATTERNS,
SUSPICIOUS_POWERSHELL_FUNCTIONS,
COMMAND_SHELL_KEYWORDS,
OBFUSCATION_KEYWORDS,
OBFUSCATION_PATTERNS,
#persistance
PERSISTENCE_KEYWORDS,
PERSISTENCE_PATTERNS,
SCHTASK_PATTERNS,
SCHEDULED_TASK_KEYWORDS,
SCHEDULED_TASK_PATTERNS,
SERVICE_PATTERNS,
#downloads/network activity
DOWNLOAD_KEYWORDS,
DOWNLOAD_PATTERNS,
NETWORK_KEYWORDS,
#LOLBINS
LOLBIN_PATTERNS,
LOLBIN_EXECUTABLES,
MSHTA_PATTERNS,
RUNDLL32_PATTERNS,
REGSVR32_PATTERNS,
CERTUTIL_PATTERNS,
INSTALLUTIL_PATTERNS,
MSBUILD_PATTERNS,
MSHTA_KEYWORDS,
RUNDLL32_KEYWORDS,
CERTUTIL_KEYWORDS,
BITSADMIN_KEYWORDS,
#registry
REGISTRY_KEYWORDS,
RUN_KEY_PATTERNS,
#windows management instrumentation(wmi)
WMI_KEYWORDS,
WMI_PATTERNS,
#defender/defense evasion
DEFENDER_TAMPERING_PATTERNS,
DEFENDER_PATTERNS,
DEFENSE_EVASION_KEYWORDS,
#credential access
CREDENTIAL_PATTERNS,
#lateral movemnet
LATERAL_MOVEMENT_KEYWORDS,
#file operations
FILE_OPERATION_KEYWORDS,
#process injection
PROCESS_INJECTION_KEYWORDS,
CERTUTIL_PATTERNS,
MSHTA_PATTERNS

)

#helper 
def add_detection(detections, name, *evidence):

    detections.append({

        "detection": name,

        "evidence": [

            e for e in evidence
            if e

        ]
    })
#helper
def normalize_path(path):

    if not path:
        return ""

    return path.lower().replace("/", "\\")
  
#keyword matcher helper 

def contains_keyword(command_line, keywords):

    command = command_line.lower()

    for keyword in keywords:

        if keyword.lower() in command:

            return keyword

    return None






    #classification helpers --> 

    #encoded command patterns 
def is_encoded_command(command_line):

    pattern = contains_keyword(command_line, ENCODED_COMMAND_PATTERNS)

    if pattern:

        return {
            "matched": True,
            "type": "Encoded Command",
            "confidence": "High",
            "match": pattern,
            "reason": f"Encoded command pattern '{pattern}' detected."
        }

    return {
        "matched": False,
        "type": "Encoded Command",
        "confidence": None,
        "match": None,
        "reason": None
    }

    #powershell keyword, behaviors, patterns
def is_powershell(command_line):

    pattern = contains_keyword(command_line, POWERSHELL_PATTERNS)

    if pattern:

        return {
            "matched": True,
            "type": "PowerShell",
            "confidence": "High",
            "reason": f"Matched PowerShell pattern '{pattern}'."
        }

    evasion = contains_keyword(command_line, POWERSHELL_EVASION_FLAGS)

    if evasion:

        return {
            "matched": True,
            "type": "PowerShell",
            "confidence": "Medium",
            "reason": f"PowerShell evasion flag '{evasion}' detected."
        }

    keyword = contains_keyword(command_line, POWERSHELL_KEYWORDS)

    if keyword:

        return {
            "matched": True,
            "type": "PowerShell",
            "confidence": "Low",
            "reason": f"PowerShell keyword '{keyword}' detected."
        }

    return {
        "matched": False,
        "type": "PowerShell",
        "confidence": None,
        "reason": None
    }

#download behavior, patterns and keywwords 

def is_download(command_line):

    pattern = contains_keyword(command_line, DOWNLOAD_PATTERNS)

    if pattern:

        return {
            "matched": True,
            "type": "Download",
            "confidence": "High",
            "match": pattern,
            "reason": f"Download pattern '{pattern}' detected."
        }

    keyword = contains_keyword(command_line, DOWNLOAD_KEYWORDS)

    if keyword:

        return {
            "matched": True,
            "type": "Download",
            "confidence": "Medium",
            "match": keyword,
            "reason": f"Download keyword '{keyword}' detected."
        }

    return {
        "matched": False,
        "type": "Download",
        "confidence": None,
        "match": None,
        "reason": None
    }

#network keywords 

def is_network(command_line):

    keyword = contains_keyword(command_line, NETWORK_KEYWORDS)

    if keyword:

        return {
            "matched": True,
            "type": "Network",
            "confidence": "Medium",
            "match": keyword,
            "reason": f"Network indicator '{keyword}' detected."
        }

    return {
        "matched": False,
        "type": "Network",
        "confidence": None,
        "match": None,
        "reason": None
    }
#registry keywords + patterns

def is_registry(command_line):

    pattern = contains_keyword(command_line, RUN_KEY_PATTERNS)

    if pattern:

        return {
            "matched": True,
            "type": "Registry",
            "confidence": "High",
            "match": pattern,
            "reason": f"Registry persistence pattern '{pattern}' detected."
        }

    keyword = contains_keyword(command_line, REGISTRY_KEYWORDS)

    if keyword:

        return {
            "matched": True,
            "type": "Registry",
            "confidence": "Medium",
            "match": keyword,
            "reason": f"Registry keyword '{keyword}' detected."
        }

    return {
        "matched": False,
        "type": "Registry",
        "confidence": None,
        "match": None,
        "reason": None
    }
#persistance keywords + patterns 

def is_persistence(command_line):

    pattern = contains_keyword(command_line, PERSISTENCE_PATTERNS)

    if pattern:

        return {
            "matched": True,
            "type": "Persistence",
            "confidence": "High",
            "match": pattern,
            "reason": f"Persistence pattern '{pattern}' detected."
        }

    keyword = contains_keyword(command_line, PERSISTENCE_KEYWORDS)

    if keyword:

        return {
            "matched": True,
            "type": "Persistence",
            "confidence": "Medium",
            "match": keyword,
            "reason": f"Persistence keyword '{keyword}' detected."
        }

    return {
        "matched": False,
        "type": "Persistence",
        "confidence": None,
        "match": None,
        "reason": None
    }

#defender tampering patterns and keywords/evasion
def is_defender_tampering(command_line):

    pattern = contains_keyword(command_line, DEFENDER_PATTERNS)

    if pattern:

        return {
            "matched": True,
            "type": "Defender Tampering",
            "confidence": "High",
            "match": pattern,
            "reason": f"Defender tampering pattern '{pattern}' detected."
        }

    keyword = contains_keyword(command_line, DEFENSE_EVASION_KEYWORDS)

    if keyword:

        return {
            "matched": True,
            "type": "Defender Tampering",
            "confidence": "Medium",
            "match": keyword,
            "reason": f"Defense evasion keyword '{keyword}' detected."
        }

    return {
        "matched": False,
        "type": "Defender Tampering",
        "confidence": None,
        "match": None,
        "reason": None
    }

#obsfucation for behavior, patterns, and keywords 

def is_obfuscation(command_line):

    pattern = contains_keyword(command_line, OBFUSCATION_PATTERNS)

    if pattern:

        return {
            "matched": True,
            "type": "Obfuscation",
            "confidence": "High",
            "match": pattern,
            "reason": f"Obfuscation pattern '{pattern}' detected."
        }

    keyword = contains_keyword(command_line, OBFUSCATION_KEYWORDS)

    if keyword:

        return {
            "matched": True,
            "type": "Obfuscation",
            "confidence": "Medium",
            "match": keyword,
            "reason": f"Obfuscation keyword '{keyword}' detected."
        }

    return {
        "matched": False,
        "type": "Obfuscation",
        "confidence": None,
        "match": None,
        "reason": None
    }
#download behaviors, patterns and keywords 

def is_download(command_line):

    pattern = contains_keyword(command_line, DOWNLOAD_PATTERNS)

    if pattern:

        return {
            "matched": True,
            "type": "Download",
            "confidence": "High",
            "reason": f"Matched download pattern '{pattern}'."
        }

    keyword = contains_keyword(command_line, DOWNLOAD_KEYWORDS)

    if keyword:

        return {
            "matched": True,
            "type": "Download",
            "confidence": "Medium",
            "reason": f"Matched download keyword '{keyword}'."
        }

    return {
        "matched": False,
        "type": "Download",
        "confidence": None,
        "reason": None
    }

#schduled task patterns and keywords 

def is_scheduled_task(command_line):

    pattern = contains_keyword(command_line, SCHEDULED_TASK_PATTERNS)

    if pattern:

        return {
            "matched": True,
            "type": "Scheduled Task",
            "confidence": "High",
            "match": pattern,
            "reason": f"Scheduled task pattern '{pattern}' detected."
        }

    keyword = contains_keyword(command_line, SCHEDULED_TASK_KEYWORDS)

    if keyword:

        return {
            "matched": True,
            "type": "Scheduled Task",
            "confidence": "Medium",
            "match": keyword,
            "reason": f"Scheduled task keyword '{keyword}' detected."
        }

    return {
        "matched": False,
        "type": "Scheduled Task",
        "confidence": None,
        "match": None,
        "reason": None
    }

#service creation(persistnace keywords, sevice patterns)

def is_service(command_line):

    pattern = contains_keyword(command_line, SERVICE_PATTERNS)

    if pattern:

        return {
            "matched": True,
            "type": "Service Creation",
            "confidence": "High",
            "match": pattern,
            "reason": f"Service creation pattern '{pattern}' detected."
        }

    keyword = contains_keyword(command_line, PERSISTENCE_KEYWORDS)

    if keyword:

        return {
            "matched": True,
            "type": "Service Creation",
            "confidence": "Medium",
            "match": keyword,
            "reason": f"Persistence keyword '{keyword}' detected."
        }

    return {
        "matched": False,
        "type": "Service Creation",
        "confidence": None,
        "match": None,
        "reason": None
    }


#wmi behaviors, keywwords, patterns
def is_wmi(command_line):

    pattern = contains_keyword(command_line, WMI_PATTERNS)

    if pattern:

        return {
            "matched": True,
            "type": "WMI",
            "confidence": "High",
            "reason": f"Matched WMI pattern '{pattern}'."
        }

    keyword = contains_keyword(command_line, WMI_KEYWORDS)

    if keyword:

        return {
            "matched": True,
            "type": "WMI",
            "confidence": "Medium",
            "reason": f"Matched WMI keyword '{keyword}'."
        }

    return {
        "matched": False,
        "type": "WMI",
        "confidence": None,
        "reason": None
    }


#bits admin keywords
def is_bitsadmin(command_line):

    keyword = contains_keyword(command_line, BITSADMIN_KEYWORDS)

    if keyword:

        return {
            "matched": True,
            "type": "BITSAdmin",
            "confidence": "Medium",
            "match": keyword,
            "reason": f"BITSAdmin keyword '{keyword}' detected."
        }

    return {
        "matched": False,
        "type": "BITSAdmin",
        "confidence": None,
        "match": None,
        "reason": None
    }
#rundll32 patterns and keywords
def is_rundll32(command_line):

    pattern = contains_keyword(command_line, RUNDLL32_PATTERNS)

    if pattern:

        return {
            "matched": True,
            "type": "Rundll32",
            "confidence": "High",
            "match": pattern,
            "reason": f"Rundll32 abuse pattern '{pattern}' detected."
        }

    keyword = contains_keyword(command_line, RUNDLL32_KEYWORDS)

    if keyword:

        return {
            "matched": True,
            "type": "Rundll32",
            "confidence": "Medium",
            "match": keyword,
            "reason": f"Rundll32 keyword '{keyword}' detected."
        }

    return {
        "matched": False,
        "type": "Rundll32",
        "confidence": None,
        "match": None,
        "reason": None
    }


#MSHTA patterns and keywords


def is_mshta(command_line):

    pattern = contains_keyword(command_line, MSHTA_PATTERNS)

    if pattern:

        return {
            "matched": True,
            "type": "MSHTA",
            "confidence": "High",
            "match": pattern,
            "reason": f"MSHTA execution pattern '{pattern}' detected."
        }

    keyword = contains_keyword(command_line, MSHTA_KEYWORDS)

    if keyword:

        return {
            "matched": True,
            "type": "MSHTA",
            "confidence": "Medium",
            "match": keyword,
            "reason": f"MSHTA keyword '{keyword}' detected."
        }

    return {
        "matched": False,
        "type": "MSHTA",
        "confidence": None,
        "match": None,
        "reason": None
    }


#commandshell keywords
def is_command_shell(command_line):

    keyword = contains_keyword(command_line, COMMAND_SHELL_KEYWORDS)

    if keyword:

        return {
            "matched": True,
            "type": "Command Shell",
            "confidence": "Medium",
            "match": keyword,
            "reason": f"Command shell indicator '{keyword}' detected."
        }

    return {
        "matched": False,
        "type": "Command Shell",
        "confidence": None,
        "match": None,
        "reason": None
    }

#file operation keywords 
def is_file_operation(command_line):
 
    keyword = contains_keyword(command_line, FILE_OPERATION_KEYWORDS)

    if keyword:

        return {
            "matched": True,
            "type": "File Operation",
            "confidence": "Medium",
            "match": keyword,
            "reason": f"File operation '{keyword}' detected."
        }

    return {
        "matched": False,
        "type": "File Operation",
        "confidence": None,
        "match": None,
        "reason": None
    }

#lateral movement keywords
def is_lateral_movement(command_line):


    keyword = contains_keyword(command_line, LATERAL_MOVEMENT_KEYWORDS)

    if keyword:

        return {
            "matched": True,
            "type": "Lateral Movement",
            "confidence": "Medium",
            "match": keyword,
            "reason": f"Lateral movement command '{keyword}' detected."
        }

    return {
        "matched": False,
        "type": "Lateral Movement",
        "confidence": None,
        "match": None,
        "reason": None
    }

#credential patterns
def is_credential_access(command_line):

    keyword = contains_keyword(command_line, CREDENTIAL_PATTERNS)

    if keyword:

        return {
            "matched": True,
            "type": "Credential Access",
            "confidence": "Medium",
            "match": keyword,
            "reason": f"Credential access indicator '{keyword}' detected."
        }

    return {
        "matched": False,
        "type": "Credential Access",
        "confidence": None,
        "match": None,
        "reason": None
    }
#regsvr32
def is_regsvr32(command_line):

    command_line = command_line.lower()

    for pattern in REGSVR32_PATTERNS:

        if pattern in command_line:

            return {
                "matched": True,
                "type": "Regsvr32",
                "reason": f"Regsvr32 pattern '{pattern}' detected."
            }

    return {
        "matched": False,
        "type": "Regsvr32",
        "reason": None
    }
#install util
def is_installutil(command_line):

    command_line = command_line.lower()

    for pattern in INSTALLUTIL_PATTERNS:

        if pattern in command_line:

            return {
                "matched": True,
                "type": "InstallUtil",
                "reason": f"InstallUtil pattern '{pattern}' detected."
            }

    return {
        "matched": False,
        "type": "InstallUtil",
        "reason": None
    }

#msbuild 

def is_msbuild(command_line):

    command_line = command_line.lower()

    for pattern in MSBUILD_PATTERNS:

        if pattern in command_line:

            return {
                "matched": True,
                "type": "MSBuild",
                "reason": f"MSBuild pattern '{pattern}' detected."
            }

    return {
        "matched": False,
        "type": "MSBuild",
        "reason": None
    }

#check powershell functions 

def is_suspicious_powershell(command_line):

    command_line = command_line.lower()

    for function in SUSPICIOUS_POWERSHELL_FUNCTIONS:

        if function.lower() in command_line:

            return {
                "matched": True,
                "type": "Suspicious PowerShell",
                "reason": f"PowerShell function '{function}' detected."
            }

    return {
        "matched": False,
        "type": "Suspicious PowerShell",
        "reason": None
    }

#process injection

def is_process_injection(command_line):

    command_line = command_line.lower()

    for keyword in PROCESS_INJECTION_KEYWORDS:

        if keyword.lower() in command_line:

            return {
                "matched": True,
                "type": "Process Injection",
                "reason": f"Process injection keyword '{keyword}' detected."
            }

    return {
        "matched": False,
        "type": "Process Injection",
        "reason": None
    }
def is_certutil(command_line):

    command_line = command_line.lower()

    for pattern in CERTUTIL_PATTERNS:

        if pattern.lower() in command_line:

            return {
                "matched": True,
                "type": "Certutil",
                "reason": f"Certutil pattern '{pattern}' detected."
            }

    for keyword in CERTUTIL_KEYWORDS:

        if keyword.lower() in command_line:

            return {
                "matched": True,
                "type": "Certutil",
                "reason": f"Certutil keyword '{keyword}' detected."
            }

    return {
        "matched": False,
        "type": "Certutil",
        "reason": None
    }





def detect_command_line(command_line):

        detections = []
        powershell = is_powershell(command_line)
        encoded = is_encoded_command(command_line)
        download = is_download(command_line)
        network = is_network(command_line)
        registry = is_registry(command_line)
        persistence = is_persistence(command_line)
        defender = is_defender_tampering(command_line)
        obfuscation = is_obfuscation(command_line)
        scheduled_task = is_scheduled_task(command_line)
        service = is_service(command_line)
        wmi = is_wmi(command_line)
        bitsadmin = is_bitsadmin(command_line)
        certutil = is_certutil(command_line)
        rundll32 = is_rundll32(command_line)
        mshta = is_mshta(command_line)
        credential = is_credential_access(command_line)
        lateral = is_lateral_movement(command_line)
        shell = is_command_shell(command_line)
        file_operation = is_file_operation(command_line)
        regsvr32 = is_regsvr32(command_line)
        installutil = is_installutil(command_line)
        process_injection = is_process_injection(command_line)
        suspicious_powershell = is_suspicious_powershell(command_line)
        msbuild = is_msbuild(command_line)

#individual technique detctions 
        if encoded["matched"]:
            add_detection(
                detections,
                "Encoded Command",
                encoded["reason"]
                )

        if obfuscation["matched"]:
            add_detection(
                detections,
                "Command Obfuscation",
                obfuscation["reason"]
                )

        if defender["matched"]:
            add_detection(
                detections,
                "Microsoft Defender Tampering",
                defender["reason"]
            )

        if credential["matched"]:
            add_detection(
                detections,
                "Credential Access",
                credential["reason"]
            )

        if lateral["matched"]:
            add_detection(
                detections,
                "Lateral Movement",
                lateral["reason"]
            )
        # powershell detections

        # encoded powershell
        if powershell["matched"] and encoded["matched"]:
            add_detection(
                detections,
                "Encoded PowerShell Execution",
                powershell["reason"],
                encoded["reason"]
            )

        # powershell downloader
        if powershell["matched"] and download["matched"]:
            add_detection(
                detections,
                "PowerShell Download Activity",
                powershell["reason"],
                download["reason"]
            )

        # powershell network activity
        if powershell["matched"] and network["matched"]:
            add_detection(
                detections,
                "PowerShell Network Activity",
                powershell["reason"],
                network["reason"]
            )

        # obfuscated powershell
        if powershell["matched"] and obfuscation["matched"]:
            add_detection(
                detections,
                "Obfuscated PowerShell",
                powershell["reason"],
                obfuscation["reason"]
            )

        # powershell credential access
        if powershell["matched"] and credential["matched"]:
            add_detection(
                detections,
                "PowerShell Credential Access",
                powershell["reason"],
                credential["reason"]
            )
    # persistence detections
    # registry persistence
        if registry["matched"] and persistence["matched"]:
            add_detection(
                detections,
                "Registry Persistence",
                registry["reason"],
                persistence["reason"]
            )

        # scheduled task persistence
        if scheduled_task["matched"] and persistence["matched"]:
            add_detection(
                detections,
                "Scheduled Task Persistence",
                scheduled_task["reason"],
                persistence["reason"]
            )

        # service persistence
        if service["matched"] and persistence["matched"]:
            add_detection(
                detections,
                "Service Persistence",
                service["reason"],
                persistence["reason"]
            )
        # execution detections
        # wmi command execution
        if wmi["matched"] and shell["matched"]:
            add_detection(
                detections,
                "WMI Command Execution",
                wmi["reason"],
                shell["reason"]
            )
        # certutil download
        if certutil["matched"] and download["matched"]:
            add_detection(
                detections,
                "Certutil Download",
                certutil["reason"],
                download["reason"]
            )

        # bitsadmin download
        if bitsadmin["matched"] and download["matched"]:
            add_detection(
                detections,
                "BITSAdmin Download",
                bitsadmin["reason"],
                download["reason"]
            )

        # mshta remote script execution
        if mshta["matched"] and network["matched"]:
            add_detection(
                detections,
                "MSHTA Remote Script Execution",
                mshta["reason"],
                network["reason"]
            )

        # obfuscated rundll32 execution
        if rundll32["matched"] and obfuscation["matched"]:
            add_detection(
                detections,
                "Obfuscated Rundll32 Execution",
                rundll32["reason"],
                obfuscation["reason"]
            )

        # downloaded file written to disk
        if download["matched"] and file_operation["matched"]:
            add_detection(
                detections,
                "Downloaded File Written To Disk",
                download["reason"],
                file_operation["reason"]
            )
        # correlated attacker behaviors
        # suspicious powershell payload downloader
        if (
            powershell["matched"]
            and encoded["matched"]
            and download["matched"]
        ):
            add_detection(
                detections,
                "Suspicious PowerShell Payload Downloader",
                powershell["reason"],
                encoded["reason"],
                download["reason"]
            )

        # highly suspicious mshta execution
        if (
            mshta["matched"]
            and network["matched"]
            and obfuscation["matched"]
        ):
            add_detection(
                detections,
                "Highly Suspicious MSHTA Execution",
                mshta["reason"],
                network["reason"],
                obfuscation["reason"]
            )
            # certutil payload download
        if (
            certutil["matched"]
            and download["matched"]
            and file_operation["matched"]
           ):
            add_detection(
                detections,
                "Certutil Payload Download",
                certutil["reason"],
                download["reason"],
                file_operation["reason"]
            )

    

        # scheduled task executes powershell
        if scheduled_task["matched"] and powershell["matched"]:
            add_detection(
                detections,
                "Scheduled Task Executes PowerShell",
                scheduled_task["reason"],
                powershell["reason"]
            )

        
        # wmi executes powershell
        if wmi["matched"] and powershell["matched"]:
            add_detection(
                detections,
                "WMI Executes PowerShell",
                wmi["reason"],
                powershell["reason"]
            )

        # encoded wmi execution
        if wmi["matched"] and encoded["matched"]:
            add_detection(
                detections,
                "Encoded WMI Execution",
                wmi["reason"],
                encoded["reason"]
            )

# powershell defender tampering
        if defender["matched"] and powershell["matched"]:
            add_detection(
                detections,
                "PowerShell Defender Tampering",
                defender["reason"],
                powershell["reason"]
            )

        # powershell credential access
        if credential["matched"] and powershell["matched"]:
            add_detection(
                detections,
                "PowerShell Credential Access",
                credential["reason"],
                powershell["reason"]
            )

        # obfuscated payload download
        if download["matched"] and obfuscation["matched"]:
            add_detection(
                detections,
                "Obfuscated Payload Download",
                download["reason"],
                obfuscation["reason"]
            )

        # encoded powershell download
        if (
            powershell["matched"]
            and encoded["matched"]
            and download["matched"]
        ):
            add_detection(
                detections,
                "Encoded PowerShell Download",
                powershell["reason"],
                encoded["reason"],
                download["reason"]
            )

        # encoded powershell network activity
        if (
            powershell["matched"]
            and encoded["matched"]
            and network["matched"]
        ):
            add_detection(
                detections,
                "Encoded PowerShell Network Activity",
                powershell["reason"],
                encoded["reason"],
                network["reason"]
            )

# powershell download + obfuscation
        if (
            powershell["matched"]
            and download["matched"]
            and obfuscation["matched"]
        ):
            add_detection(
                detections,
                "Obfuscated PowerShell Payload Download",
                powershell["reason"],
                download["reason"],
                obfuscation["reason"]
            )

        # mshta remote execution
        if mshta["matched"] and network["matched"]:
            add_detection(
                detections,
                "MSHTA Remote Script Execution",
                mshta["reason"],
                network["reason"]
            )

        # certutil payload download
        if certutil["matched"] and download["matched"]:
            add_detection(
                detections,
                "Certutil Payload Download",
                certutil["reason"],
                download["reason"]
            )

        # bitsadmin payload download
        if bitsadmin["matched"] and download["matched"]:
            add_detection(
                detections,
                "BITSAdmin Payload Download",
                bitsadmin["reason"],
                download["reason"]
            )

        # rundll32 + obfuscation
        if rundll32["matched"] and obfuscation["matched"]:
            add_detection(
                detections,
                "Obfuscated Rundll32 Execution",
                rundll32["reason"],
                obfuscation["reason"]
            )

        # rundll32 + network
        if rundll32["matched"] and network["matched"]:
            add_detection(
                detections,
                "Rundll32 Network Activity",
                rundll32["reason"],
                network["reason"]
            )
        # regsvr32 remote script execution
        if regsvr32["matched"] and network["matched"]:
            add_detection(
                detections,
                "Regsvr32 Remote Script Execution",
                regsvr32["reason"],
                network["reason"]
            )

        # regsvr32 + obfuscation
        if regsvr32["matched"] and obfuscation["matched"]:
            add_detection(
                detections,
                "Obfuscated Regsvr32 Execution",
                regsvr32["reason"],
                obfuscation["reason"]
            )

        # regsvr32 payload download
        if regsvr32["matched"] and download["matched"]:
            add_detection(
                detections,
                "Regsvr32 Payload Download",
                regsvr32["reason"],
                download["reason"]
            )

        # installutil download activity
        if installutil["matched"] and download["matched"]:
            add_detection(
                detections,
                "InstallUtil Download Activity",
                installutil["reason"],
                download["reason"]
            )

        # installutil network activity
        if installutil["matched"] and network["matched"]:
            add_detection(
                detections,
                "InstallUtil Network Activity",
                installutil["reason"],
                network["reason"]
            )

        # msbuild network activity
        if msbuild["matched"] and network["matched"]:
            add_detection(
                detections,
                "MSBuild Network Activity",
                msbuild["reason"],
                network["reason"]
            )

        # msbuild payload download
        if msbuild["matched"] and download["matched"]:
            add_detection(
                detections,
                "MSBuild Payload Download",
                msbuild["reason"],
                download["reason"]
            )

        # suspicious powershell function
        if suspicious_powershell["matched"] and powershell["matched"]:
            add_detection(
                detections,
                "Suspicious PowerShell Function",
                suspicious_powershell["reason"],
                powershell["reason"]
            )

        # encoded suspicious powershell
        if (
            suspicious_powershell["matched"]
            and powershell["matched"]
            and encoded["matched"]
        ):
            add_detection(
                detections,
                "Encoded Suspicious PowerShell",
                suspicious_powershell["reason"],
                powershell["reason"],
                encoded["reason"]
            )

        # powershell process injection
        if process_injection["matched"] and powershell["matched"]:
            add_detection(
                detections,
                "PowerShell Process Injection",
                process_injection["reason"],
                powershell["reason"]
            )

        # process injection with credential access
        if (
            process_injection["matched"]
            and credential["matched"]
        ):
            add_detection(
                detections,
                "Credential Theft via Process Injection",
                process_injection["reason"],
                credential["reason"]
            )

        # encoded process injection
        if (
            process_injection["matched"]
            and encoded["matched"]
        ):
            add_detection(
                detections,
                "Encoded Process Injection",
                process_injection["reason"],
                encoded["reason"]
            )

        # defender tampering with process injection
        if (
            defender["matched"]
            and process_injection["matched"]
        ):
            add_detection(
                detections,
                "Defense Evasion with Process Injection",
                defender["reason"],
                process_injection["reason"]
            )
        # suspicious powershell functions
        if suspicious_powershell["matched"]:
            add_detection(
                detections,
                "Suspicious PowerShell Function",
                suspicious_powershell["reason"]
            )

        # regsvr32 activity
        if regsvr32["matched"]:
            add_detection(
                detections,
                "Regsvr32 Activity",
                regsvr32["reason"]
            )

        # installutil activity
        if installutil["matched"]:
            add_detection(
                detections,
                "InstallUtil Activity",
                installutil["reason"]
            )

        # msbuild activity
        if msbuild["matched"]:
            add_detection(
                detections,
                "MSBuild Activity",
                msbuild["reason"]
            )

        # process injection
        if process_injection["matched"]:
            add_detection(
                detections,
                "Process Injection Activity",
                process_injection["reason"]
            )        



        


        return {
           "detections": detections,
            "classification": {
            "powershell": powershell,
            "encoded": encoded,
            "download": download,
            "network": network,
            "registry": registry,
            "persistence": persistence,
            "defender": defender,
            "obfuscation": obfuscation,
            "scheduled_task": scheduled_task,
            "service": service,
            "wmi": wmi,
            "bitsadmin": bitsadmin,
            "certutil": certutil,
            "rundll32": rundll32,
            "mshta": mshta,
            "credential": credential,
            "lateral": lateral,
            "command_shell": shell,
            "file_operation": file_operation,
            "regsvr32": regsvr32,
            "installutil": installutil,
            "msbuild": msbuild,
            "suspicious_powershell": suspicious_powershell,
            "process_injection": process_injection
        }
    }    
    
