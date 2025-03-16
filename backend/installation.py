import os
import subprocess
import secrets

def main():
    try:
        # Check if the env folder exists and create it if not present
        if not os.path.exists("env"):
            # Create a new virtual environment
            print("Creating a new virtual environment...")
            subprocess.run(["python3", "-m", "venv", "env"], check=True)
            
        # Installing requirements
        activate_script = os.path.join("env", "bin", "activate")
        print("Installing requirements...")
        subprocess.run(["bash", "-c", f"source {activate_script} && pip install -r requirements.txt"], check=True)
        
        # Creating .env file 
        print("Creating .env file...")
        jwt_key = secrets.token_hex(20)
        # Write jwt_key to the .env file
        subprocess.run(["bash", "-c", f"echo 'JWT_KEY={jwt_key}' > .env"], check=True)
        
    except Exception as e:
        print(f"Error while installation: {e}")

if __name__ == "__main__":
    main()
    print('The installation completed!\n'
          'to run the server type:\n'
          'sudo ./env/bin/python main.py -i YOUR_INTERFACE')