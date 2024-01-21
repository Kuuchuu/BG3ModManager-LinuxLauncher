#!/usr/bin/env python3
# Requires pip install vdf pefile
import argparse
import getpass
import json
import os
import shutil
import socket
import subprocess
import sys
try:
    import vdf
    import pefile
except ImportError:
    print("Please `pip install vdf pefile` for adding to Steam")

user = getpass.getuser() #getlogin()
script_path = os.path.abspath(__file__)
prefix_location = f"/home/{user}/.local/share/wineprefixes/BG3MM/"

class DbgOutput:
    def __init__(self):
        self.data = []
    def write(self, s):
        self.data.append(s)
    def flush(self):
        pass
    def get_contents(self):
        return ''.join(self.data)
debug = False
dbgoutput = DbgOutput()

def clean_dbgOut(dbgOut):
    lines = dbgOut.split('\n')
    if not lines:
        return ''

    processed = []
    prev_line = lines[0]
    count = 1

    for current_line in lines[1:]:
        if current_line == prev_line:
            count += 1
        else:
            if count > 1:
                processed.append(f"{prev_line}    [x{count}]")
            else:
                processed.append(prev_line)
            count = 1
        prev_line = current_line

    # Handle the last line(s)
    if count > 1:
        processed.append(f"{prev_line}    [x{count}]")
    else:
        processed.append(prev_line)

    return '\n'.join(processed)

def termbin():
    global debug
    if not debug:
        return
    notify("Uploading debug output to termbin.com...")
    sys.stdout = sys.__stdout__
    sys.stderr = sys.__stderr__
    upload = clean_dbgOut(dbgoutput.get_contents())
    host = "termbin.com"
    port = 9999
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.sendall(upload.encode())
    response = s.recv(1024).decode().strip()
    s.close()
    print(f"{upload}\n\n")
    notify(f"Debug output uploaded to: {response}")
    return response

def run_command(cmd):
    print(f'Running {cmd}')
    result = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = result.stdout.decode('utf-8')
    print(output)

def notify(message):
    print(message)
    try:
        subprocess.run(["notify-send", "BG3MM Linux Setup", message])
    except Exception as e:
        print(e)

def setup_wineprefix():
    # Create WINEPREFIX if it doesn't exist
    print("Checking if WINEPREFIX exists...")
    if not os.path.exists(prefix_location):
        print("Creating WINEPREFIX...")
        os.makedirs(prefix_location)
        print(f"{prefix_location} created, running wineboot.")
        run_command(f"WINEPREFIX={prefix_location} wineboot")
    print("Installing dotnet472 if necessary.  This may take some time.")
    run_command(f"WINEPREFIX={prefix_location} winetricks -q dotnet472")
    print("Installing d3dcompiler_47 if necessary...")
    run_command(f"WINEPREFIX={prefix_location} winetricks -q d3dcompiler_47")

def update_settings():
    print("Updating settings.json...")
    
    settings_data = {
        "GameDataPath": f"Z:\\home\\{user}\\.steam\\steam\\steamapps\\common\\Baldurs Gate 3\\Data",
        "GameExecutablePath": f"Z:\\home\\{user}\\.steam\\steam\\steamapps\\common\\Baldurs Gate 3\\bin\\bg3.exe",
        "DocumentsFolderPathOverride": f"Z:\\home\\{user}\\.steam\\steam\\steamapps\\compatdata\\1086940\\pfx\\drive_c\\users\\steamuser\\AppData\\Local\\Larian Studios\\Baldur's Gate 3\\",
    }
    
    settings_path = "Data/settings.json"
    
    # If settings.json doesn't exist, create it
    print("Checking if settings.json exists...")
    if not os.path.exists("Data/"):
        print("'Data' directory does not exist, creating...")
        os.makedirs("Data")
    if not os.path.exists(settings_path):
        print("Creating settings.json...")
        with open(settings_path, "w") as f:
            json.dump(settings_data, f, indent=2)
    else:
        # If it exists, update the required fields
        print("Updating settings.json...")
        with open(settings_path, "r") as f:
            existing_data = json.load(f)

        for key, value in settings_data.items():
            existing_data[key] = value

        with open(settings_path, "w") as f:
            json.dump(existing_data, f, indent=2)

def extract_icon(exe_path, resource_type_id, resource_id_value, output_path):
    try:
        pe = pefile.PE(exe_path)
    except Exception as e:
        notify(f"Couldn't read {exe_path}. `pip install vdf pefile` if you have't already!")
        print(e)
        print('Icon extraction failed.')
        return

    # Check if DIRECTORY_ENTRY_RESOURCE is present
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        notify("No resources found!")
        return

    # Go through resources and find the desired one
    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if resource_type.id == resource_type_id:  # Check the resource type ID
            for resource_id in resource_type.directory.entries:
                if resource_id.id == resource_id_value:  # Check the resource ID
                    data = pe.get_data(resource_id.directory.entries[0].data.struct.OffsetToData, resource_id.directory.entries[0].data.struct.Size)
                    with open(output_path, 'wb') as out_file:
                        out_file.write(data)
                    return
    notify(f"Resource with type ID {resource_type_id} and ID {resource_id_value} not found!")

def add_to_steam():
    extract_icon("BG3ModManager.exe", 3, 1, "bg3mm.png")
    icon_path = os.path.join(os.path.dirname(script_path), "bg3mm.png")
    steam_dir = os.path.expanduser("~/.steam/steam/userdata/")

    # Find the appropriate user directory (assuming only one user)
    user_dirs = [d for d in os.listdir(steam_dir) if d.isdigit()]
    if not user_dirs:
        notify("Couldn't find the Steam user directory. Exiting.")
        return
    shortcuts_file = os.path.join(steam_dir, user_dirs[0], "config/shortcuts.vdf")

    with open(shortcuts_file, 'rb') as f:
        try:
            shortcuts = vdf.binary_loads(f.read())
        except Exception as e:
            notify(f"Couldn't read {shortcuts_file}. `pip install vdf pefile` if you have't already!")
            print(e)
            print('Add to Steam failed.')
            return
    
    new_entry = {
        'appname': 'BG3 Mod Manager - Linux',
        'Exe': f'{script_path}',
        'StartDir': f'{os.path.dirname(script_path)}',
        'icon': f'{icon_path}',
        'ShortcutPath': '',
        'LaunchOptions': '',
        'IsHidden': False,
        'AllowDesktopConfig': True,
        'AllowOverlay': True,
        'openvr': False,
        'Devkit': False,
        'DevkitGameID': '',
        'LastPlayTime': 0,
        'tags': {'0': 'BG3'}
    }

    # Add BG3MM to the shortcuts
    try:
        shortcuts['shortcuts'][str(len(shortcuts['shortcuts']))] = new_entry
    except Exception as e:
        notify(f"Couldn't add {script_path} as 'BG3 Mod Manager - Linux' to Steam as a non-Steam game.")
        print(e)
        print('Add to Steam failed.')
        return

    # Save the shortcuts file
    try:
        with open(shortcuts_file, 'wb') as f:
            print(f'Backing up {shortcuts_file} to {shortcuts_file}.bkup...')
            shutil.copy(shortcuts_file, f"{shortcuts_file}.bkup")
            f.write(vdf.binary_dumps(shortcuts))
            notify(f"Added {script_path} as 'BG3 Mod Manager - Linux' to Steam as a non-Steam game.")
    except Exception as e:
        notify(f"Couldn't save {shortcuts_file}.")
        print(e)
        print('Add to Steam failed.')
        return

def main():
    parser = argparse.ArgumentParser(description="Setup and launch BG3 Mod Manager.")
    parser.add_argument("--setup", action="store_true", help="Setup the WINEPREFIX and settings.json.")
    parser.add_argument("--steam", action="store_true", help="Add to Steam as a non-Steam game.")
    parser.add_argument("--clean", action="store_true", help=f"Removes the WINEPREFIX '{prefix_location}'. Can be used with --setup for a fresh install.")
    parser.add_argument("--debug", action="store_true", help="Uploads all output to an unlisted paste on termbin.com with a 1 month expiration date. Provides the URL to the user.")
    args = parser.parse_args()
    if args.debug:
        notify("BG3 Mod Manager linux.py running! - DEBUG mode enabled.")
        print("Output is now being captured and will upload to termbin and print to stdout when the script exits.")
        global debug
        debug = True
        sys.stdout = dbgoutput
        sys.stderr = dbgoutput
    if args.clean:
        try:
            shutil.rmtree(prefix_location)
            notify(f"Removed WINEPREFIX '{prefix_location}'.")
        except Exception as e:
            notify(f"Couldn't remove WINEPREFIX '{prefix_location}'.")
            print(e)
    if args.setup:
        setup_wineprefix()
        update_settings()
    if args.steam:
        add_to_steam()
    if not args.setup and not args.steam:
        print("Checking if WINEPREFIX exists...")
        if not os.path.exists(f"{prefix_location}"):
            notify("WINEPREFIX doesn't exist. Please run with --setup flag to create it.")
            termbin()
            return
        run_command(f"WINEPREFIX={prefix_location} wine BG3ModManager.exe")
    termbin()

if __name__ == "__main__":
    os.chdir(os.path.dirname(script_path))
    main()
