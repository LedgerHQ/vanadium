import re
import argparse

def parse_log_and_calculate_durations(log_file):
    # Regular expression to match timestamp and phase
    pattern = r'\[(\d+\.\d+)\]\s+(.+)'
    
    # Lists to store timestamps and phases
    timestamps = []
    phases = []
    
    # Read and parse log file
    try:
        with open(log_file, 'r') as file:
            for line in file:
                match = re.match(pattern, line.strip())
                if match:
                    timestamp = float(match.group(1))
                    phase = match.group(2)
                    timestamps.append(timestamp)
                    phases.append(phase)
    
        # Calculate and print durations
        print("Phase Durations:")
        for i in range(1, len(timestamps)):
            duration = timestamps[i] - timestamps[i-1]
            phase_transition = f"{phases[i-1]} to {phases[i]}"
            print(f"{phase_transition}: {duration:.3f} seconds")
    
    except FileNotFoundError:
        print(f"Error: The file '{log_file}' was not found.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Calculate phase durations from a log file.")
    parser.add_argument(
        "log_file",
        nargs="?",
        default="print.log",
        help="Path to the log file (default: print.log)",
    )
    args = parser.parse_args()
    parse_log_and_calculate_durations(args.log_file)


if __name__ == "__main__":
    main()
