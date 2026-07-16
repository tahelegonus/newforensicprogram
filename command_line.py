
#T1027
ENCODED_COMMAND_PATTERNS = {

    "-enc",
    "-encodedcommand",
    "frombase64string",
    "[convert]::frombase64string",
}
#T1059.001
POWERSHELL_EVASION_FLAGS ={

    "-nop",
    "-noprofile",
    "-ep bypass",
    "-executionpolicy bypass",
    "-windowstyle hidden",
    "-w hidden",
    "-noninteractive"
},
#T1105

#REGISTRY PERSISTANCE (T1547)

RUN_KEY_PATTERNS = {


    "currentversion\\run",
    "currentversion\\runonce",
    "reg add hkcu",
    "reg add hklm"
}

#schduled task persistance (T1053)

SCHTASK_PATTERNS = {


    "schtasks /create",

    "/sc onlogon",
    "/sc onstart",
    "/ru system"
}

#T1218.004
INSTALLUTIL_PATTERNS = {

    "installutil /logfile=",
    "installutil /logtoconsole",
    "installutil /u",
    "installutil /installstate",
    "installutil.exe"


}

#LOLBin abuse and how they are abused 

LOLBIN_PATTERNS = {

    "mshta http",
    "rundll32 javascript:",
    "regsvr32 /i:http",
    "installutil /logfile=",
    "msbuild",
    "rundll32",
    "regsvr32",
    "mshta",
    "installutil",
    "msbuild",
    "certutil",
    "bitsadmin",
    "forfiles",
    "cmstp",
    "odbcconf",
    "control",
    "hh",
    "desktopimgdownldr",
    "verclsid",
    "regasm",
    "regsvcs"

}

LOLBIN_EXECUTABLES = {

    "bitsadmin.exe",
    "certutil.exe",
    "cmstp.exe",
    "control.exe",
    "desktopimgdownldr.exe",
    "forfiles.exe",
    "hh.exe",
    "installutil.exe",
    "msbuild.exe",
    "mshta.exe",
    "odbcconf.exe",
    "regasm.exe",
    "regsvcs.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "verclsid.exe"
}


MMSBUILD_PATTERNS = {

    "msbuild.exe",
    "msbuild ",
    "msbuild /target",
    "msbuild /property",
    "msbuild /p:",
    "msbuild .csproj",
    "msbuild .proj"
}


#WMI execution 


#defender tampering 

DEFENDER_TAMPERING_PATTERNS = {

    "set-mppreference",
    "add-mppreference",
    "-disablebehaviormonitoring",
    "disablerealtimemonitoring"
}


DOWNLOAD_KEYWORDS = {

    "invoke-webrequest",
    "invoke-restmethod",
    "downloadfile",
    "start-bitstransfer", 
    "curl",
    "wget",
    "bitsadmin",
    "certutil",
    "urlcache"
}

NETWORK_KEYWORDS = {

    "http://",
    "https://",
    "ftp://",
    "\\\\",
    ".com",
    ".net",
    ".org",
    "webclient",
    "\\server\share"
}

REGISTRY_KEYWORDS = {

    "reg add",
    "reg delete",
    "reg query",
    "reg export",
    "reg import",
    "hkcu\\",
    "hklm\\",
    "hkcr\\",
    "hku\\",
    "currentversion\\run",
    "currentversion\\runonce"
}

PERSISTENCE_KEYWORDS = { 
"currentversion\\run",
"currentversion\\runonce",
"startup",
"schtasks",
"sc create",
"new-service",
"winlogon",
"userinit"

}

DEFENSE_EVASION_KEYWORDS = { 

    "set-mppreference",
    "add-mppreference",
    "disablebehaviormonitoring",
    "disablerealtimemonitoring",
    "disableantispyware",
    "excludeprocess",
    "exclusionpath",
    "exclusionextension",
    "Set-MpPreference",
    "Add-MpPreference"

}

OBFUSCATION_KEYWORDS = {


    "^",
    "'",
    "$(",
    "${",
    "%%",
    "!",
    "char",
    "join",
    "iex",
    "invoke-expression",
    "FromBase64String",
    "[char]",


}

SCHEDULED_TASK_KEYWORDS = {

    "schtasks",
    "/create",
    "/change",
    "/delete",
    "/sc",
    "/tn",
    "/tr",
    "/ru",
    "/f"

}

WMI_KEYWORDS = {

    "wmic",
    "win32_process",
    "process call create",
    "wmic process",
    "invoke-wmimethod",
    "get-wmiobject",
    "wmic process call create"
}

BITSADMIN_KEYWORDS = {

    "bitsadmin",
    "/transfer",
    "/create",
    "addfile",
    "/resume",
    "/complete"
}

#T1197
BITSADMIN_PATTERNS ={

    "bitsadmin /transfer",
    "bitsadmin /create",
    "bitsadmin /addfile",
    "bitsadmin /setnotifycmdline",
    "bitsadmin /resume",
    "bitsadmin /complete",
    "bitsadmin /cancel",
    "bitsadmin /reset"

}


CERTUTIL_KEYWORDS = {

    "certutil",
    "urlcache",
    "-split",
    "-f",
    "-decode",
    "-decodehex",
    "-encode"
}

#T1105/T1140
CERTUTIL_PATTERNS = {

    "certutil -urlcache",
    "certutil -verifyctl",
    "certutil -decode",
    "certutil -decodehex",
    "certutil -encode",
    "certutil -split",
    "certutil -f",
    "certutil -ping"


}

RUNDLL32_KEYWORDS = {

    "rundll32",
    "javascript:",
    "shell32.dll",
    "url.dll",
    "advpack.dll",
    "zipfldr.dll"

}

MSHTA_KEYWORDS = {

    "mshta",
    "http://",
    "https://",
    ".hta",
    "vbscript:",
    "javascript:"
}

POWERSHELL_KEYWORDS = {

    "powershell",
    "pwsh",
    "-nop",
    "-noprofile",
    "-ep",
    "-executionpolicy",
    "-windowstyle",
    "-noninteractive",
    "-command",
    "-file"
}

POWERSHELL_KEYWORDS = {

    "powershell",
    "pwsh",
    "-nop",
    "-enc"

}

POWERSHELL_PATTERNS = {

    "powershell -enc",
    "powershell -nop",
    "powershell invoke-webrequest"

}

#T1105 ingress tool transfer
DOWNLOAD_PATTERNS = {


    "invoke-webrequest http",
    "invoke-restmethod http",
    "downloadfile(",
    "curl http",
    "wget http",
    "certutil -urlcache",
    "bitsadmin /transfer",
    "invoke-webrequest",
    "invoke-restmethod",
    "start-bitstransfer",
    "bitsadmin /transfer",
    "certutil -urlcache",
    "curl http",
    "wget http"
}

PERSISTENCE_PATTERNS = {

    "reg add hkcu",

    "reg add hklm",

    "currentversion\\run",

    "currentversion\\runonce",

    "schtasks /create",

    "sc create"

}
DEFENDER_PATTERNS = {

    "set-mppreference",

    "add-mppreference",

    "-disablerealtimemonitoring",

    "-disablebehaviormonitoring",

    "-disableioavprotection"

}

#T1218.001 rundll32
RUNDLL32_PATTERNS = {

    "rundll32 javascript:",

    "rundll32 url.dll",

    "rundll32 advpack.dll",

    "rundll32 shell32.dll"

}
REGSVR32_PATTERNS = {

    "regsvr32 /i:http",

    "regsvr32 /s",

    "regsvr32 /u"

}
WMI_PATTERNS = {

    "wmic process call create",

    "wmic shadowcopy",

    "invoke-wmimethod"

}
SCHEDULED_TASK_PATTERNS = {

    "schtasks /create",

    "/sc onlogon",

    "/sc onstart",

    "/ru system",

    "/f",
}


SERVICE_PATTERNS = {

    "sc create",

    "sc config",

    "new-service"

}
CREDENTIAL_PATTERNS = {

    "sekurlsa",

    "lsass",

    "comsvcs.dll"

}
OBFUSCATION_PATTERNS = {

    "invoke-expression",

    "iex(",

    "frombase64string",

    "[char]",

    "[convert]::frombase64string"

}

LATERAL_MOVEMENT_KEYWORDS = {

"psexec",
"winrs",
"Enter-PSSession",
"Invoke-Command"


}

COMMAND_SHELL_KEYWORDS = {

    "cmd.exe",

    "/c",

    "/k",

    "&&",

    "||",

    "|"

}

FILE_OPERATION_KEYWORDS = {

    "copy",

    "move",

    "del",

    "erase",

    "rename",

    "attrib",

    "xcopy",

    "robocopy"

}

PROCESS_INJECTION_KEYWORDS = {

    "virtualalloc",

    "writeprocessmemory",

    "createremotethread",

    "ntmapviewofsection"

}


SUSPICIOUS_POWERSHELL_FUNCTIONS = {

    "invoke-expression",

    "invoke-command",

    "invoke-webrequest",

    "invoke-restmethod",

    "invoke-wmimethod",

    "downloadstring",

    "downloadfile",

    "start-process"

}

#T1218.005
MSHTA_PATTERNS = {

    "mshta http://",
    "mshta https://",
    "mshta vbscript:",
    "mshta javascript:",
    "mshta about:",
    "mshta file://",
    ".hta",
    ".hta "
}
CERTUTIL_PATTERNS = {

    "certutil -urlcache",

    "certutil -decode",

    "certutil -decodehex",

    "certutil -encode"

}
BITSADMIN_PATTERNS = {

    "bitsadmin /transfer",

    "bitsadmin /create",

    "bitsadmin /addfile",

    "bitsadmin /resume"

}
MSHTA_PATTERNS = {

    "mshta http",

    "mshta https",

    "mshta vbscript:",

    "mshta javascript:"

}
