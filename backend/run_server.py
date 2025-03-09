import os
import shutil
import subprocess

def main():
    
    # Check if the env folder exists and delete it if present
    if os.path.exists("env"):
        print("Removing existing virtual environment...")
        shutil.rmtree("env")
    else:
        print("No existing virtual environment found. Proceeding...")
    
    # Create a new virtual environment
    print("Creating a new virtual environment...")
    subprocess.run(["python3", "-m", "venv", "env"], check=True)
    
    # Activate the virtual environment
    activate_script = os.path.join("env", "bin", "activate")
    print("Activating virtual environment...")
    subprocess.run(["bash", "-c", f"source {activate_script} && pip install -r requirements.txt"], check=True)
    
    # Run main.py with sudo
    print("Running main.py with sudo...")
    subprocess.run(["sudo", f"./env/bin/python", "main.py","-i", "wlan1"], check=True)

if __name__ == "__main__":
    main()
