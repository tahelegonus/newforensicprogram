#loading screen code! :) 


from rich.console import Console 
from rich.panel import Panel 
from rich.text import Text 
from rich.progress import Progress, SpinnerColumn, TextColumn
import time
from datetime import datetime
from rich.spinner import Spinner
import json 
import os

def load_json_files(folder="configs"):
    loaded_files = {}

    if not os.path.exists(folder):
        return loaded_files

    for file in os.listdir(folder):
        if file.endswith(".json"):
            path = os.path.join(folder, file)

            with open(path, "r", encoding="utf-8") as f:
                loaded_files[file] = json.load(f)

    return loaded_files

logo = Text()
logo.append("⊹₊ ⋆ ", style="yellow")
logo.append("TAHELEGONUS", style="bold bright_magenta")
logo.append(" ⊹₊ ⋆", style="yellow")



console = Console()


def show_splash(): 
    
            banner = r""" 
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⣤⡾⡿⠻⠛⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡴⠛⠉⠙⣟⣷⡷⠶⠚⠛⠛⠛⠛⠛⠲⠶⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⠋⠀⢀⡴⠞⠙⡁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⢿⣖⣦⠶⠶⠶⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡼⠉⠀⣰⠏⠁⠀⠸⢿⠟⡀⠄⣀⡀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠙⣧⡀⣀⣠⣨⣷⢤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠉⠀⢰⠇⠀⠀⠀⠀⠀⠌⢤⠼⣟⠁⠈⠀⢸⣿⣿⠆⠀⠀⠀⠀⠈⣿⢟⡹⣍⣿⠀⠉⠳⣄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠇⢀⣀⣿⣀⣀⣀⣂⠀⠀⠈⠐⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⡽⠿⠶⠟⠃⠀⠋⠓⢹⡆⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡴⠾⠛⠉⠉⠉⠀⠀⠈⠉⠙⠓⠶⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡾⠋⠁⠀⣀⠴⠀⠀⠀⠀⠀⣾⠁⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠈⠙⢦⡀⠀⠀⠀⠀⠀⢀⣼⠛⠀⠀⡠⠞⠁⠀⠀⠀⠀⠀⣸⠇⠀⠀⠀⠀⠀ 
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣠⣰⠏⠀⠀⠀⠀⠑⠂⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⣾⠃⠀⣠⠋⠀⠀⠀⠀⠀⠀⠀⢠⡟
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⡟⠦⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣄⡀⠀⠀⠀⠀⠀⣾⡆⠀⠀⢸⡇⢀⡞⠁⠀⠀⠀⠀⠀⠀⠀⣠⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⢾⣣⡦⡀⡀⠀⢀⠀⠀⠀⠀⠀⠀⢠⡾⡏⠷⣈⢹⣦⠀⠀⠀⢰⣗⡀⠀⠀⣸⡆⢨⠀⠀⠀⡠⠄⠀⠀⣠⡶⠋⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠉⠛⣦⣤⠀⠀⠀⠀⢠⡟⢰⡝⢳⢨⢸⡏⠀⠀⣴⣴⣿⠛⣥⠀⣿⢹⣦⣤⠀⠘⡔⣥⣴⡞⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⠛⠒⠒⠚⣧⣐⣹⣒⣴⠿⠒⠛⠛⠉⠁⠘⠻⠿⠾⠃⠀⠀⠉⠉⠛⠙⠉⠁⠀⠀
        
"""
          
            console.print(
                 Panel.fit(
                    Text(banner, style="bright_magenta"),
                    title=" TAHELEGONUS ",
                    subtitle="v1.0.0",
                    border_style="bright_magenta",
                    padding = (2,2),         
        ),
        justify="center",
)
            
            console.print(Text("Author: tahelegonus", style="bold bright_magenta")
)

            console.print(
                   Text(
                        "Engine: teddybear = JSON + pandas + hayabusa", 
                        style="bold bright_magenta"
                   )
)
            
            console.print(
               Text(
                   f"Started: {datetime.now():%Y-%m-%d %H:%M:%S}",
                   style="bold bright_magenta",
    )
)
        
with Progress(
    SpinnerColumn(spinner_name="moon"),
    TextColumn("[progress.description]{task.description}"),
    transient=True,
) as progress:

    task = progress.add_task(
        "awakening... ᶻ 𝗓 𐰁 .ᐟ",
        total=None
    )

    progress.update(
        task,
        description="loading configs...ʕ•ﻌ•ʔ"
    )

    configs = load_json_files()

    time.sleep(0.5)

    progress.update(
        task,
        description="checking json files...ʕ•ﻌ•ʔ"
    )
    time.sleep(0.7)

    progress.update(
        task,
        description="loading teddybear engine...ʕ•ﻌ•ʔ"
    )
    time.sleep(0.7)

    progress.update(
        task,
        description="Ready!"
    )
    time.sleep(0.5)
console.print(
    Text(
        f"✓ Loaded {len(configs)} JSON files",
        style="bold bright_magenta"
    )
)
if __name__ == "__main__":
    show_splash()

