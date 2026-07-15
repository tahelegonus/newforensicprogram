import os

from parent_process import (
    EXPECTED_PARENT_PROCESSES,
    OFFICE_PARENT_PROCESSES,
    BROWSER_PARENT_PROCESSES,
    SCRIPT_PARENT_PROCESSES
)

from image_path import (
    WINDOWS_LOLBIN_PATHS,
    WINDOWS_SUSPICIOUS_PATHS,
    WINDOWS_HIGH_RISK_PATHS,
    FAKE_WINDOWS_NAMES,
    WINDOWS_SYSTEM_EXECUTABLES,
    KNOWN_SERVICE_PATHS,
    WINDOWS_ENVIRONMENT_VARIABLES
    
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



#expected parent process 

def is_expected_parent(parent_process):

    filename = os.path.basename(parent_process).lower()

    if filename in EXPECTED_PARENT_PROCESSES:

        return {
            "matched": True,
            "type": "Expected Parent",
            "reason": EXPECTED_PARENT_PROCESSES[filename]["description"]
        }

    return {
        "matched": False,
        "type": "Expected Parent",
        "reason": None
    }

#office parent process

def is_office_parent(parent_process):

    filename = os.path.basename(parent_process).lower()

    if filename in OFFICE_PARENT_PROCESSES:

        return {
            "matched": True,
            "type": "Office Application",
            "reason": f"Office application '{filename}' launched the process."
        }

    return {
        "matched": False,
        "type": "Office Application",
        "reason": None
    }

#browser parent process 


def is_browser_parent(parent_process):

    filename = os.path.basename(parent_process).lower()

    if filename in BROWSER_PARENT_PROCESSES:

        return {
            "matched": True,
            "type": "Browser",
            "reason": f"Browser process '{filename}' launched the process."
        }

    return {
        "matched": False,
        "type": "Browser",
        "reason": None
    }


#script parent process 
def is_script_parent(parent_process):

    filename = os.path.basename(parent_process).lower()

    if filename in SCRIPT_PARENT_PROCESSES:

        return {
            "matched": True,
            "type": "Script Interpreter",
            "reason": f"Script interpreter '{filename}' launched the process."
        }

    return {
        "matched": False,
        "type": "Script Interpreter",
        "reason": None
    }

#from image path 


def is_lolbin(parent_process):


    filename = os.path.basename(parent_process).lower()

    if filename in WINDOWS_LOLBIN_PATHS:

        return {
            "matched": True,
            "type": "LOLBin",
            "reason":WINDOWS_LOLBIN_PATHS[filename]["description"]
    }
    return{ 
        "matched": False,
        "type": "LOLBin",
        "reason": None
    }


def is_fake_windows_name(parent_process):
    filename = os.path.basename(parent_process).lower()

    if filename in FAKE_WINDOWS_NAMES:

        return {
            "matched": True,
            "type": "Fake Windows Name",
            "reason": (
                f"Filename '{filename}' resembles the legitimate Windows "
                f"file '{FAKE_WINDOWS_NAMES[filename]}'."
            )
        }

    return {
        "matched": False,
        "type": "Fake Windows Name",
        "reason": None
    }


def is_system_executable(parent_process):

    filename = os.path.basename(parent_process).lower()

    return {
        "matched": filename in WINDOWS_SYSTEM_EXECUTABLES,
        "type": "System Executable",
        "reason": (
            f"Known Windows system executable '{filename}' detected."
            if filename in WINDOWS_SYSTEM_EXECUTABLES
            else None
        )
    }


def is_suspicious_path(parent_process):

    parent_process = normalize_path(parent_process)

    for name, info in WINDOWS_SUSPICIOUS_PATHS.items():

        if info["path"].lower() in parent_process:

            return {
                "matched": True,
                "type": "Suspicious Path",
                "name": name,
                "reason": info["reason"]
            } 
        
    return{
            "matched": False,
            "type": "Suspicious Path",
            "reason": None
        }

def is_high_risk_path(parent_process):

    parent_process = normalize_path(parent_process)

    for name, info in WINDOWS_HIGH_RISK_PATHS.items():

        if info["path"].lower() in parent_process:

            return {
                "matched": True,
                "type": "High Risk Path",
                "name": name,
                "reason": info["reason"]
            }
        
    return{

        "matched": False,
        "type": "High Risk Path",
        "reason": None
        }

def is_known_service_path(parent_process):  

    parent_process = normalize_path(parent_process)

    for path, info in KNOWN_SERVICE_PATHS.items():

        if path.lower() in parent_process:

            return {
                "matched": True,
                "type": "Known Service Path",
                "name": path,
                "reason": info["reason"]
            }

    return {
        "matched": False,
        "type": "Known Service Path",
        "reason": None
    } 

def is_environment_variable_path(parent_process): 

    parent_process = normalize_path(parent_process)

    for variable, info in WINDOWS_ENVIRONMENT_VARIABLES.items():

        if variable.lower() in parent_process:

            return {
                "matched": True,
                "type": "Environment Variable",
                "name": variable,
                "reason": info["reason"]
            }

    return {
        "matched": False,
        "type": "Environment Variable",
        "reason": None
    }



#detection engine 
def detect_parent_process(parent_process):
        
        detections = []

        expected = is_expected_parent(parent_process)

        office = is_office_parent(parent_process)

        browser = is_browser_parent(parent_process)

        script = is_script_parent(parent_process)

        lolbin = is_lolbin(parent_process)

        fake = is_fake_windows_name(parent_process)

        suspicious_path = is_suspicious_path(parent_process)

        high_risk = is_high_risk_path(parent_process)

        system = is_system_executable(parent_process)
    


        if fake["matched"]:

            add_detection(
                detections,
                "Possible Parent Process Masquerading",
                fake["reason"]
            )

        if suspicious_path["matched"]:

            add_detection(
            detections,
             "Parent Process Running From Suspicious Directory",
            suspicious_path["reason"]
    )
        
        return {
            "classification": {
            "expected_parent": expected,
            "office_parent": office,
            "browser_parent": browser,
            "script_parent": script,
            "lolbin": lolbin,
            "system_executable": system,
            "high_risk_path": high_risk,
            "suspicious_path": suspicious_path,
            "fake_name": fake
}
    }
