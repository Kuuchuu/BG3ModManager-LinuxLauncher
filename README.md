# BG3ModManager-LinuxLauncher
### Linux Launcher and non-Steam game adder for [BG3ModManager](https://github.com/LaughingLeader/BG3ModManager)

Run without arguments to launch BG3ModManager. Must first be setup using --setup flag.

**Dependencies:**
 - [BG3ModManager](https://github.com/LaughingLeader/BG3ModManager)
 - Python3
 - wine
 - winetricks
 - Python Packages (for non-Steam game shortcut support):
     - vdf
     - pefile

**Installation:**
 - EXIT STEAM!
 - Put "[linux.py](https://raw.githubusercontent.com/Kuuchuu/BG3ModManager-LinuxLauncher/main/linux.py)" in the same directory as "BG3ModManager.exe"
 - Using a terminal run the python script with the "--setup" flag (optionally include the "--steam" flag)

**Flags:**

 - "--setup"
     - Setup the WINEPREFIX and settings.json.
       - You will need to click through the dotNET installers as they pop up.
 - "--steam"
     - Add to Steam as a non-Steam game.
     - **Requires `pip install vdf pefile`**

Both flags can be passed simultaneously.