#!/usr/bin/env python3
# Requires pip install vdf pefile
import os
import json
import subprocess
import argparse
try:
    import vdf
    import pefile
except ImportError:
    print("Please 'pip install vdf pefile' for adding to Steam")

user = os.getlogin()
prefix_location = f"/home/{user}/.local/share/wineprefixes/BG3MM/"

def run_command(cmd):
    print('Running wine')
    subprocess.run(cmd, shell=True, check=True)

def setup_wineprefix():
    # Create WINEPREFIX if it doesn't exist
    print("Checking if WINEPREFIX exists...")
    if not os.path.exists(f"{prefix_location}"):
        print("Creating WINEPREFIX...")
        run_command(f"WINEPREFIX={prefix_location} winecfg")
    print("Installing dotnet472 if necessary...")
    # run_command(f"WINEPREFIX=/home/{user}/.BG3MM/ winetricks --force dotnet472")
    run_command(f"WINEPREFIX={prefix_location} winetricks dotnet472")

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
        print(f"Couldn't read {exe_path}. 'pip install vdf pefile' if you have't already!")
        print(e)
        print('Exiting.')
        return

    # Check if DIRECTORY_ENTRY_RESOURCE is present
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        print("No resources found!")
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
    print(f"Resource with type ID {resource_type_id} and ID {resource_id_value} not found!")

def add_to_steam():
    script_path = os.path.abspath(__file__)
    extract_icon("BG3ModManager.exe", 3, 1, "bg3mm.png")
    icon_path = os.path.join(os.path.dirname(script_path), "bg3mm.png")
    steam_dir = os.path.expanduser("~/.steam/steam/userdata/")

    # Find the appropriate user directory (assuming only one user)
    user_dirs = [d for d in os.listdir(steam_dir) if d.isdigit()]
    if not user_dirs:
        print("Couldn't find the Steam user directory. Exiting.")
        return
    shortcuts_file = os.path.join(steam_dir, user_dirs[0], "config/shortcuts.vdf")

    with open(shortcuts_file, 'rb') as f:
        try:
            shortcuts = vdf.binary_loads(f.read())
        except Exception as e:
            print(f"Couldn't read {shortcuts_file}. 'pip install vdf pefile' if you have't already!")
            print(e)
            print('Exiting.')
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
        print(f"Couldn't add {script_path} as 'BG3 Mod Manager - Linux' to Steam as a non-Steam game.")
        print(e)
        print('Exiting.')
        return

    # Save the shortcuts file
    try:
        with open(shortcuts_file, 'wb') as f:
            f.write(vdf.binary_dumps(shortcuts))
            print(f"Added {script_path} as 'BG3 Mod Manager - Linux' to Steam as a non-Steam game.")
    except Exception as e:
        print(f"Couldn't save {shortcuts_file}.")
        print(e)
        print('Exiting.')
        return

def main():
    parser = argparse.ArgumentParser(description="Setup and launch BG3 Mod Manager.")
    parser.add_argument("--setup", action="store_true", help="Setup the WINEPREFIX and settings.json.")
    parser.add_argument("--steam", action="store_true", help="Add to Steam as a non-Steam game.")
    args = parser.parse_args()
    if args.setup:
        setup_wineprefix()
        update_settings()
    if args.steam:
        add_to_steam()
    if not args.setup and not args.steam:
        print("Checking if WINEPREFIX exists...")
        if not os.path.exists(f"{prefix_location}"):
            print("WINEPREFIX doesn't exist. Please run with --setup flag to create it.")
            return
        run_command(f"WINEPREFIX={prefix_location} wine BG3ModManager.exe")

if __name__ == "__main__":
    main()
