import os 


from image_path import (
    WINDOWS_EXPECTED_PATHS,
    WINDOWS_SUSPICIOUS_PATHS,
    WINDOWS_HIGH_RISK_PATHS,
    WINDOWS_SYSTEM_EXECUTABLES,
    WINDOWS_SYSTEM_FILES,
    WINDOWS_LOLBIN_PATHS,
    FAKE_WINDOWS_NAMES,
    DECEPTIVE_FILENAMES,
    ARCHIVE_EXTENSIONS,
    SHORTCUT_EXTENSIONS,
    DRIVER_EXTENSIONS,
    DLL_EXTENSIONS,
    OFFICE_DOCUMENTS_EXTENSIONS,
    WINDOWS_ENVIRONMENT_VARIABLES,
    KNOWN_SERVICE_PATHS,
    WINDOWS_EXECUTABLE_EXTENSIONS,
    WINDOWS_SCRIPT_EXTENSIONS,
    WINDOWS_COMMON_INSTALLERS,
    DOUBLE_EXTENSION_PATTERNS,
    MEDIA_EXTENSIONS,
    SUSPICIOUS_DOCUMENT_KEYWORDS,
    DOCUMENT_EXTENSIONS
)


#helper 
def normalize_path(path):
    if not path:
        return ""

    return path.lower().replace("/", "\\")

#helper

def add_detection(detections, name, *evidence):

    detections.append({

        "detection": name,

        "evidence": [
            e for e in evidence
            if e
        ]
    })


#expected files
def is_expected_path(image_path):

    image_path = normalize_path(image_path)

    for name, info in WINDOWS_EXPECTED_PATHS.items():

        if image_path.startswith(info["path"].lower()):

            return {
                "matched": True,
                "type": "Expected Path",
                "name": name,
                "reason": info["reason"]
            }

    return {
        "matched": False,
        "type": "Expected Path",
        "reason": "Path is not a standard Windows executable location."
    }
#deceptive file names
def has_deceptive_filename(image_path):

    filename = os.path.basename(image_path).lower()

    for name in DECEPTIVE_FILENAMES:

        if name in filename:

            return {
                "matched": True,
                "type": "Deceptive Filename",
                "reason": f"Filename resembles '{name}'."
            }

    return {
        "matched": False,
        "type": "Deceptive Filename",
        "reason": None
    }

#windows system files 
def is_system_file(image_path):

    filename = os.path.basename(image_path).lower()

    return {
        "matched": filename in WINDOWS_SYSTEM_FILES,
        "type": "System File",
        "reason": "Matches a known Windows system file."
            if filename in WINDOWS_SYSTEM_FILES
            else None
    }
#windows executable extenstions 
def is_executable(image_path):

    extension = os.path.splitext(image_path)[1].lower()

    return {
        "matched": extension in WINDOWS_EXECUTABLE_EXTENSIONS,
        "type": "Executable",
        "reason": f"Executable extension '{extension}' detected."
            if extension in WINDOWS_EXECUTABLE_EXTENSIONS
            else None
    }


#suspicious path 
def is_suspicious_path(image_path):

    image_path = normalize_path(image_path)

    for name, info in WINDOWS_SUSPICIOUS_PATHS.items():

        if info["path"].lower() in image_path:

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
            
#high risk path 
def is_high_risk_path(image_path):

    image_path = normalize_path(image_path)

    for name, info in WINDOWS_HIGH_RISK_PATHS.items():

        if info["path"].lower() in image_path:

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



#script 
def is_script(image_path):

    extension = os.path.splitext(image_path)[1].lower()

    return {
    "matched": extension in WINDOWS_SCRIPT_EXTENSIONS,
    "type": "Script",
    "reason": f"Script extension '{extension}' detected."
        if extension in WINDOWS_SCRIPT_EXTENSIONS
        else None
}
#installer 
def is_installer(image_path):

    extension = os.path.splitext(image_path)[1].lower()

    return {
        "matched": extension in WINDOWS_COMMON_INSTALLERS,
        "type": "Installer",
        "reason": (
        f"Installer extension  '{extension}' detected."
        if extension in WINDOWS_COMMON_INSTALLERS
        else None
        )
    }

#system executable
def is_system_executable(image_path):

    filename = os.path.basename(image_path).lower()

    return {
        "matched": filename in WINDOWS_SYSTEM_EXECUTABLES,
        "type": "System Executable",
        "reason": (
            f"Known Windows system executable '{filename}' detected."
            if filename in WINDOWS_SYSTEM_EXECUTABLES
            else None
        )
    }

#LOLBin

def is_lolbin(image_path):

    filename = os.path.basename(image_path).lower()

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


#fake windows name 
def has_fake_windows_name(image_path):

    filename = os.path.basename(image_path).lower()

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


#double extension

def has_double_extension(image_path):

    filename = os.path.basename(image_path).lower()

    for pattern in DOUBLE_EXTENSION_PATTERNS:

        if filename.endswith(pattern):

            return {
                "matched": True,
                "type": "Double Extension",
                "reason": 
                    f"Filename '{filename}' uses a double extension."   
               }

    return{
        "matched": False,
        "type": "Double Extension",
        "reason": None
        }
#archive extensions 
def is_archive(image_path):

    extension = os.path.splitext(image_path)[1].lower()

    return {
        "matched": extension in ARCHIVE_EXTENSIONS,
        "type": "Archive",
        "reason": (
            f"Archive extension '{extension}' detected."
            if extension in ARCHIVE_EXTENSIONS
            else None
        )
    }


#shortcut extensions 

def is_shortcut(image_path):

    extension = os.path.splitext(image_path)[1].lower()

    return {
        "matched": extension in SHORTCUT_EXTENSIONS,
        "type": "Shortcut",
        "reason": (
            f"Shortcut extension '{extension}' detected."
            if extension in SHORTCUT_EXTENSIONS
            else None
        )
    }
#driver extensions
def is_driver(image_path): 
    extension = os.path.splitext(image_path)[1].lower()

    return {
        "matched": extension in DRIVER_EXTENSIONS,
        "type": "Driver",
        "reason": (
            f"Driver extension' {extension}' detected."
            if extension in DRIVER_EXTENSIONS
            else None
        )
    }

#dll extensions 


def is_dll(image_path): 

    extension = os.path.splitext(image_path)[1].lower()

    return {
        "matched": extension in DLL_EXTENSIONS,
        "type": "Dynamic Link Library",
        "reason": (
            f"Dynamic Link Library' {extension}' detected."
            if extension in DLL_EXTENSIONS
            else None
        )
    }
#enviornment variables

def is_environment_variable_path(image_path):

    image_path = normalize_path(image_path)

    for variable, info in WINDOWS_ENVIRONMENT_VARIABLES.items():

        if variable.lower() in image_path:

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


#known service paths
def is_known_service_path(image_path):

    image_path = normalize_path(image_path)

    for path, info in KNOWN_SERVICE_PATHS.items():

        if path.lower() in image_path:

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




#office document extensins
def is_office_document(image_path): 
   
    extension = os.path.splitext(image_path)[1].lower()

    return {
        "matched": extension in OFFICE_DOCUMENTS_EXTENSIONS,
        "type": "Office Document Extension",
        "reason": (
            f"Office Document Extension '{extension}' detected."
            if extension in DLL_EXTENSIONS
            else None
        )
    } 

#media extensions
def is_has_media_extension(image_path):

    extension = os.path.splitext(image_path)[1].lower()

    if extension in MEDIA_EXTENSIONS:

        return {
            "matched": True,
            "type": "Media File",
            "reason": f"Media file extension '{extension}' detected."
        }

    return {
        "matched": False,
        "type": "Media File",
        "reason": None
    }

#suspicious document keywords

def has_suspicious_document_keywords(image_path):

    filename = os.path.basename(image_path).lower()

    for keyword in SUSPICIOUS_DOCUMENT_KEYWORDS:

        if keyword in filename:

            return {
                "matched": True,
                "type": "Suspicious Document Keyword",
                "reason": f"Filename contains suspicious keyword '{keyword}'."
            }

    return {
        "matched": False,
        "type": "Suspicious Document Keyword",
        "reason": None
    }


#document extensions

def is_document_extension(image_path):

    extension = os.path.splitext(image_path)[1].lower()

    if extension in DOCUMENT_EXTENSIONS:

        return {
            "matched": True,
            "type": "Document",
            "reason": f"Document extension '{extension}' detected."
        }

    return {
        "matched": False,
        "type": "Document",
        "reason": None
    }




    
def detect_image_path(image_path):

        detections = []

        expected = is_expected_path(image_path)
        suspicious = is_suspicious_path(image_path)
        high_risk = is_high_risk_path(image_path)
        executable = is_executable(image_path)
        script = is_script(image_path)
        installer = is_installer(image_path)
        system_executable = is_system_executable(image_path)
        system_file = is_system_file(image_path)
        lolbin = is_lolbin(image_path)
        fake_name = has_fake_windows_name(image_path)
        deceptive_name = has_deceptive_filename(image_path)
        double_extension = has_double_extension(image_path)
        archive = is_archive(image_path)
        shortcut = is_shortcut(image_path)
        driver = is_driver(image_path)
        dll = is_dll(image_path)
        environment_variable = is_environment_variable_path(image_path)
        service_path = is_known_service_path(image_path)
        media = is_has_media_extension(image_path)
        suspicious_doc_keywords = has_suspicious_document_keywords(image_path)
        document_extensions = is_document_extension(image_path)

        


        
        if(
            high_risk["matched"]
            and executable["matched"]
            ):
            add_detection(
                detections,
                "High Risk Directory Execution",
                high_risk["reason"]
                )
            
        if (
            fake_name["matched"]
            and not expected["matched"]
            ):
            add_detection(
                detections,
                "Possible Windows Masquerading",
                fake_name["reason"],
                expected["reason"]
                )
            
        if (    
            deceptive_name["matched"]
                and suspicious["matched"]
            ):
                add_detection(
                    detections,
                    "Possible Fake Software Updater",
                    deceptive_name["reason"],
                    suspicious["reason"]
                
                )

        if (
            lolbin["matched"]
            and suspicious["matched"]
            ):
            add_detection(
                detections,
                "LOLBin Executed from Suspicious Directory",
                lolbin["reason"],
                suspicious["reason"]

                )

        if (
            system_executable["matched"]
            and not expected["matched"]
            ):
            add_detection(
                detections,
                "Windows Executable Outside Expected Directory",
                system_executable["reason"],
                expected["reason"]
                )
            

        if (
            system_file["matched"]
            and not expected["matched"]
            ):
            add_detection(
                detections,
                "Windows System File Outside Expected Directory",
                system_file["reason"],
                expected["reason"]
                )

        if (
            double_extension["matched"]
            and executable["matched"]
            ):
            add_detection(
                detections,
                "Disguised Executable",
                double_extension["reason"]
                )

        if (
            script["matched"]
            and suspicious["matched"]
            ):
            add_detection(
                detections,
                    "Script Executed From User-Writable Directory",
                    script["reason"],
                    suspicious["reason"]
                )

        if (
                installer["matched"]
                and suspicious["matched"]
            ):
            add_detection(
                detections,
                "Installer Executed From Suspicious Directory",
                installer["reason"],
                suspicious["reason"]
                )
            
        if (
                installer["matched"]
                and high_risk["matched"]
            ):
            add_detection(
                detections,
                "Installer located in High Risk Direcotry From Suspicious Directory",
                installer["reason"],
                suspicious["reason"]
                )    

        if (
            script["matched"]
            and high_risk["matched"]
            ):
            add_detection(
                detections,
                "Script Executed From High Risk Directory",
                script["reason"],
                high_risk["reason"]
                )

        if (
            fake_name["matched"]
            and suspicious["matched"]
            and executable["matched"]
            ):
            add_detection(
                detections,
                "Possible Windows Binary Masquerading",
                fake_name["reason"],
                suspicious["reason"]
                )

        if (
            deceptive_name["matched"]
            and high_risk["matched"]
            ):
            add_detection(
                detections,
                "Possible Malicious Software Updater",
                deceptive_name["reason"],
                high_risk["reason"]
                )

        if (
            double_extension["matched"]
            and suspicious["matched"]
            ):
            add_detection(
                detections,
                "Disguised Executable in User Directory",
                double_extension["reason"],
                suspicious["reason"]
                )

        if (
            lolbin["matched"]
            and script["matched"]
            ):
            add_detection(
                detections,
                "LOLBin Used To Execute Script",
                lolbin["reason"],
                script["reason"]
                )

        if (
            lolbin["matched"]
            and high_risk["matched"]
            ):
            add_detection(
                detections,
                "LOLBin Executed From High Risk Directory",
                lolbin["reason"],
                high_risk["reason"]
                )
        if (
            not expected["matched"]
            and suspicious["matched"]
            and fake_name["matched"]
            and executable["matched"]
            ):
            add_detection(
                detections,
                "High Confidence Masquerading Attempt",
                expected["reason"],
                suspicious["reason"],
                fake_name["reason"]
                )

        if (
            executable["matched"]
            and suspicious["matched"]
            and not expected["matched"]
            ):
            add_detection(
                detections,
                "Possible Persistence Executable",
                suspicious["reason"],
                expected["reason"]
                )
                
        if (
            not expected["matched"]
            and suspicious["matched"]
            and fake_name["matched"]
            and double_extension["matched"]
            ):
            add_detection(
                detections,
                "Multiple Indicators of Malicious Execution",
                expected["reason"],
                suspicious["reason"],
                fake_name["reason"],
                double_extension["reason"]
                )
        if (
            dll["matched"]
            and suspicious["matched"]
        ):
            add_detection(
                detections, 
                "DLL Located in user-writeable directory",
                dll["reason"],
                suspicious["reason"]
            )
        if (
            dll["matched"]
            and high_risk["matched"]
        ):
            add_detection(
                detections, 
                "DLL Located in high-risk directory",
                dll["reason"],
                suspicious["reason"]
            )    

        if (
            driver["matched"]
            and not expected ["matched"]
        ):
            add_detection(
                detections,
                "Driver Outside Expected System Directory",
                driver["reason"],
                expected["reason"]
            )

        if (
            driver["matched"]
            and suspicious["matched"]
        ):
            add_detection(
                detections,
                "Driver Located in User-Writeable Directory",
                suspicious["reason"]
            )    

        if (
            shortcut["matched"]
            and suspicious["matched"]
        ):
            add_detection(
                detections,
                "Shortcut Located in User Writeable Directory",
                shortcut["reason"],
                suspicious["reason"]
            )

        if(
            archive["matched"]
            and suspicious["matched"]
        ):
            add_detection(
                detections,
                "Archive Located in User-Writeable Directory",
                archive["reason"],
                suspicious["reason"]
            )

        if(
            environment_variable ["matched"]
            and executable["matched"]
        ):
            add_detection(
                detections,
                "Executable using Eviroment Variable Path",
                environment_variable["reason"],
                executable["reason"]
            )   

        if(
            environment_variable["matched"]
            and script["matched"]

        ): add_detection(
            detections,
            "Script Using Enviroment Variable Path",
            environment_variable["reason"],
            script["reason"]
        )
            

        if(
            environment_variable["matched"]
            and fake_name["matched"]
        ): 
            add_detection(
                detections,
                "Masquerading Executable Using Enviornment Variable Path",
                environment_variable["reason"],
                fake_name["reason"]
            )   

        if(
             environment_variable["matched"]
            and lolbin["matched"]
        ): 
            add_detection(
                detections,
                "LOLBin Using Environment Variable Path",
                environment_variable["reason"],
                lolbin["reason"]
            )

        if(
            environment_variable["matched"]
            and fake_name["matched"]
            and executable["matched"]
        ): 
            add_detection(
                detections,
                "Executable Using Environment Variable with Windows Masquerading",
                environment_variable["reason"],
                fake_name["reason"]
            )     


        if(
             system_executable["matched"]
            and not service_path["matched"]
        ): 
            add_detection(
                detections,
                "Windows Executable Outside Known Service Directory",
                system_executable["reason"],
                service_path["reason"],
                expected["reason"]
            )    
        if(
             fake_name["matched"]
            and not service_path["matched"]
        ): 
            add_detection(
                detections,
                "Possible Fake Windows Service Executable",
                fake_name["reason"],
                expected["reason"]
            ) 
        if(
             lolbin["matched"]
            and not service_path["matched"]
        ): 
            add_detection(
                detections,
                "LOLBin Outside Expected System Directory",
                lolbin["reason"],
                expected["reason"]
            )

        if(
             system_executable["matched"]
            and suspicious["matched"]
        ): 
            add_detection(
                detections,
                "System Executable Located in User Writable Directory",
                system_executable["reason"],
                suspicious["reason"]
            )   

        if(
             fake_name["matched"]
            and suspicious["matched"]
            and not service_path["matched"]
        ): 
            add_detection(
                detections,
                "High Confidence Windows Masquerading",
                fake_name["reason"],
                suspicious["reason"],
                expected["reason"]
            )
            
        if(
             fake_name["matched"]
            and high_risk["matched"]
        ): 
            add_detection(
                detections,
                "Masquerading Executable in High-Risk Directory",
                fake_name["reason"],
                high_risk["reason"],
            )  

        if (
            lolbin["matched"]
            and fake_name["matched"]
        ): 
            add_detection(
                detections,
                "Masquerading LOLBin",
                lolbin["reason"],
                fake_name["reason"]
            )
        if (
            lolbin["matched"]
            and script["matched"]
            and environment_variable["matched"]
        ): 
            add_detection(
                detections,
                "LOLBin Executing Script from Environment Varible Path",
                lolbin["reason"],
                script["reason"],
                environment_variable["reason"]
            )    
        if (
            lolbin["matched"]
            and fake_name["matched"]
        ): 
            add_detection(
                detections,
                "Masquerading LOLBin",
                lolbin["reason"],
                fake_name["reason"]
            )    
        if (
            lolbin["matched"]
            and fake_name["matched"]
        ): 
            add_detection(
                detections,
                "Masquerading LOLBin",
                lolbin["reason"],
                fake_name["reason"]
            )
        if (
            lolbin["matched"]
            and fake_name["matched"]
        ): 
            add_detection(
                detections,
                "Masquerading LOLBin",
                lolbin["reason"],
                fake_name["reason"]
            )

        if(
            media["matched"]
            and double_extension["matched"]
        ):
            add_detection(
                detections,
                "Media File Masquerading as Executable",
                media["reason"],
                double_extension["reason"]
            )

        if(
            media["matched"]
            and deceptive_name["matched"]
        ):
            add_detection(
                detections,
                "Deceptive Media Filename",
                media["reason"],
                deceptive_name["reason"]
            )

        if(
            suspicious_doc_keywords["matched"]
            and executable["matched"]
        ):
            add_detection(
                detections,
                "Executable Masquerading as Document",
                suspicious_doc_keywords["reason"],
                executable["reason"]
            )

        if(
            suspicious_doc_keywords["matched"]
            and script["matched"]
        ):
            add_detection(
                detections,
                "Script Disguided as Document",
                suspicious_doc_keywords["reason"],
                script["reason"]
            ) 

        if(
            document_extensions["matched"]
            and double_extension["matched"]
        ):
            add_detection(
                detections,
                "Document Double Extension",
                document_extensions["reason"],
                double_extension["reason"]
            )    

          #general high confidence windows names, deceptive, double extensions

        if (
            suspicious_doc_keywords["matched"]
            and executable["matched"]
            and double_extension["matched"]
        ):
            add_detection(
            detections,
            "High Confidence Social Engineering Filename",
            suspicious_doc_keywords["reason"],
            executable["reason"],
            double_extension["reason"]
    )

        



        



    
            
        return detections
