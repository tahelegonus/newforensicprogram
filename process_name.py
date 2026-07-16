import os 

from image_path import WINDOWS_LOLBIN_PATHS
from image_path import FAKE_WINDOWS_NAMES
from image_path import DECEPTIVE_FILENAMES


WINDOWS_CORE_PROCESSES = {

    "lsass.exe": {
        "description": "Local Security Authority Subsystem Service."
    },

    "winlogon.exe": {
        "description": "Windows Logon Process."
    },

    "csrss.exe": {
        "description": "Client/Server Runtime Subsystem."
    },

    "services.exe": {
        "description": "Service Control Manager."
    },

    "svchost.exe": {
        "description": "Windows Service Host."
    },

    "explorer.exe": {
        "description": "Windows Explorer."
    },

    "spoolsv.exe": {
        "description": "Print Spooler."
    },

    "dwm.exe": {
        "description": "Desktop Window Manager."
    },

    "runtimebroker.exe": {
        "description": "Runtime Broker."
    }
}
