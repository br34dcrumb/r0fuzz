import subprocess
import time
import sys
import os
import argparse

def run_server(server_path, library_path):
    env = os.environ.copy()
    env['LD_PRELOAD'] = library_path

    while True:
        try:
            process = subprocess.Popen([server_path], env=env)            
            process.wait()
            
            if process.returncode != 0:
                print(f"Server crashed or exited with an error. Restarting in 2 seconds...")
                time.sleep(2)
        
        except KeyboardInterrupt:
            print("Script interrupted by user. Exiting...")
            sys.exit(0)
        
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            time.sleep(2)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run a server process with a preloaded library.")
    parser.add_argument("--server", required=True, help="Path to the server executable.")
    parser.add_argument("--library", required=True, help="Path to the library.")
    
    args = parser.parse_args()
    
    run_server(args.server, args.library)