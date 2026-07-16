import os

from parent_process import (
    EXPECTED_PARENT_PROCESSES,
    OFFICE_PARENT_PROCESSES,
    BROWSER_PARENT_PROCESSES
)

from image_path import (
    WINDOWS_LOLBIN_PATHS,
    WINDOWS_SUSPICIOUS_PATHS,
    WINDOWS_HIGH_RISK_PATHS,
    WINDOWS_SYSTEM_EXECUTABLES,
    FAKE_WINDOWS_NAMES
)



EXPECTED_PARENT_PROCESSES = {

    "explorer.exe": {
        "description": "Windows Explorer commonly launches user applications."
    },

    "services.exe": {
        "description": "Service Control Manager launches Windows services."
    },

    "wininit.exe": {
        "description": "Windows initialization process."
    },

    "winlogon.exe": {
        "description": "Windows logon process."
    },

    "taskhostw.exe": {
        "description": "Windows Task Host."
    },

    "svchost.exe": {
        "description": "Windows Service Host."
    }

}

OFFICE_PARENT_PROCESSES = {

    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "onenote.exe"

}

BROWSER_PARENT_PROCESSES = {

    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "iexplore.exe"

}

SCRIPT_PARENT_PROCESSES = {

    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe"

}
