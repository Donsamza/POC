import subprocess
import sys
import os

def main():
    print("Starting application...")
    print("Access at: http://localhost:8501")
    print()
    print("Press Ctrl+C to stop")
        
    try:
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", "app.py",
            "--server.port", "8501",
            "--server.address", "localhost"
        ])
    except KeyboardInterrupt:
        print("\nApplication stopped by user")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
