import os

from process_name import WINDOWS_CORE_PROCESSES

from image_path import (
    WINDOWS_LOLBIN_PATHS,
    FAKE_WINDOWS_NAMES,
    WINDOWS_SYSTEM_EXECUTABLES,
    WINDOWS_SCRIPT_EXTENSIONS,
    WINDOWS_COMMON_INSTALLERS
)


#helpers

def add_detection(detections, name, *evidence):

    detections.append({
        "detection": name,
        "evidence": [e for e in evidence if e]
    })


#helpers
def is_core_process(process_name):

    filename = os.path.basename(process_name).lower()

    if filename in WINDOWS_CORE_PROCESSES:
        return {
            "matched": True,
            "type": "Core Process",
            "reason": WINDOWS_CORE_PROCESSES[filename]["description"]
        }

    return {
        "matched": False,
        "type": "Core Process",
        "reason": None
    }

#lolbin from image paths 
def is_lolbin(process_name):

    filename = os.path.basename(process_name).lower()

    if filename in WINDOWS_LOLBIN_PATHS:
        return {
            "matched": True,
            "type": "LOLBin",
            "reason": WINDOWS_LOLBIN_PATHS[filename]["description"]
        }

    return {
        "matched": False,
        "type": "LOLBin",
        "reason": None
    }

#fake windows names from image paths 
def is_fake_windows_name(process_name):

    filename = os.path.basename(process_name).lower()

    if filename in FAKE_WINDOWS_NAMES:
        return {
            "matched": True,
            "type": "Masquerading",
            "reason": f"Filename '{filename}' resembles a legitimate Windows process."
        }

    return {
        "matched": False,
        "type": "Masquerading",
        "reason": None
    }

#exectuables from image paths
def is_system_executable(process_name):

    filename = os.path.basename(process_name).lower()

    if filename in WINDOWS_SYSTEM_EXECUTABLES:
        return {
            "matched": True,
            "type": "System Executable",
            "reason": f"'{filename}' is a known Windows system executable."
        }

    return {
        "matched": False,
        "type": "System Executable",
        "reason": None
    }

#script extensions from image paths
def is_script(process_name):

    extension = os.path.splitext(process_name)[1].lower()

    if extension in WINDOWS_SCRIPT_EXTENSIONS:
        return {
            "matched": True,
            "type": "Script",
            "reason": f"Script extension '{extension}' detected."
        }

    return {
        "matched": False,
        "type": "Script",
        "reason": None
    }

#common installers from image paths
def is_installer(process_name):

    extension = os.path.splitext(process_name)[1].lower()

    if extension in WINDOWS_COMMON_INSTALLERS:
        return {
            "matched": True,
            "type": "Installer",
            "reason": f"Installer extension '{extension}' detected."
        }

    return {
        "matched": False,
        "type": "Installer",
        "reason": None
    }


#detection engine

def detect_process_name(process_name):

    detections = []

    core = is_core_process(process_name)
    lolbin = is_lolbin(process_name)
    fake = is_fake_windows_name(process_name)
    system = is_system_executable(process_name)
    script = is_script(process_name)
    installer = is_installer(process_name)

    #
    #stand alone detections

    if fake["matched"]:
        add_detection(
            detections,
            "Possible Windows Process Masquerading",
            fake["reason"]
        )

    #
    # returning detections and classifcations

    return {
        "detections": detections,
        "classification": {
            "core_process": core,
            "lolbin": lolbin,
            "system_executable": system,
            "script": script,
            "installer": installer
        }
    }
