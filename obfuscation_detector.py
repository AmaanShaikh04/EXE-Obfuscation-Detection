import os  # Module to interact with the file system (directories, file paths)
import pefile  # Library to parse and analyze Portable Executable (PE) files (i.e., .exe files)
import math  # Provides mathematical functions like logarithms for entropy calculation
from datetime import datetime  # Module to work with dates and times for log file naming
import sys  # (Currently unused) Could be used for redirecting output or handling command-line arguments

# Function to calculate the Shannon entropy of binary data
def calculate_entropy(data):
    """
    Calculate the Shannon entropy for a given binary data section.
    Entropy is a measure of randomness, which helps identify obfuscated or packed sections.
    High entropy often means the section contains compressed or encrypted data.
    
    Parameters:
        data (bytes): Binary data from a section of the executable.
    
    Returns:
        float: The calculated entropy value (0 to 8).
    """
    if not data:
        # Return 0 if the data is empty
        return 0.0
    
    # Initialize a list to hold the frequency of each byte (256 possible values)
    frequency = [0] * 256
    
    # Count occurrences of each byte in the data
    for byte in data:
        frequency[byte] += 1
    
    # Initialize the entropy value to 0
    entropy = 0.0
    
    # Calculate entropy using Shannon's formula: H(X) = - Σ p(x) log2(p(x))
    for f in frequency:
        if f > 0:
            # Calculate the probability of each byte's occurrence
            p_x = f / len(data)
            # Accumulate entropy by multiplying probability by log2(probability)
            entropy -= p_x * math.log2(p_x)
    
    # Return the final calculated entropy value
    return entropy

# Function to handle both terminal printing and log file writing
def log_message(message, log_file):
    """
    Log a message by printing it to the terminal and writing it to the log file.
    
    Parameters:
        message (str): The message to log.
        log_file (file object): The log file where the message will be written.
    """
    print(message)  # Output the message to the terminal
    log_file.write(message + "\n")  # Write the message to the log file and add a newline

# Function to check a given .exe file for obfuscated sections based on entropy
def check_obfuscation(file_path, log_file):
    """
    Analyze a .exe file for potential obfuscation by checking the entropy of its sections.
    High entropy indicates potential packing or encryption.
    
    Parameters:
        file_path (str): Path to the .exe file to analyze.
        log_file (file object): Log file where the analysis results will be written.
    """
    try:
        # Load the PE (Portable Executable) file using pefile library
        pe = pefile.PE(file_path)
        
        # Initialize a list to store the names of suspicious sections
        suspicious_sections = []
        
        # Log the start of the analysis for the current file
        log_message(f"\nAnalyzing {file_path}...", log_file)
        
        # Loop through each section in the PE file to analyze its entropy
        for section in pe.sections:
            # Get the raw data of the section and calculate its entropy
            entropy = calculate_entropy(section.get_data())
            
            # Get the section name and decode it to a readable format (strip null bytes)
            section_name = section.Name.decode().strip('\x00')
            
            # Log the section name and its calculated entropy
            log_message(f"  Section {section_name}: Entropy = {entropy:.2f}", log_file)
            
            # If the entropy is higher than 7.5, it's considered suspicious
            if entropy > 7.5:
                suspicious_sections.append(section_name)
        
        # After checking all sections, report whether any suspicious sections were found
        if suspicious_sections:
            # Log the suspicious sections and mark the file as "Dangerous"
            log_message(f"  Suspicious sections in {file_path}: {', '.join(suspicious_sections)}", log_file)
            log_message("  Status: Dangerous", log_file)
        else:
            # Log that no obfuscation was detected and mark the file as "Non dangerous"
            log_message(f"  No obfuscation detected in {file_path}.", log_file)
            log_message("  Status: Non dangerous", log_file)
    
    except Exception as e:
        # If an error occurs (e.g., invalid file format), log the error message
        log_message(f"Error processing {file_path}: {e}", log_file)

# Function to scan a directory for .exe files and check each one for obfuscation
def scan_directory(directory_path):
    """
    Scan a directory for .exe files and analyze each one for obfuscation.
    
    Parameters:
        directory_path (str): Path to the directory containing .exe files.
    """
    # Get a list of all .exe files in the specified directory
    exe_files = [f for f in os.listdir(directory_path) if f.endswith('.exe')]
    
    # If no .exe files are found, notify the user and exit the function
    if not exe_files:
        print(f"No EXE files found in {directory_path}.")
        return

    # Create a directory for storing log files, if it doesn't exist
    log_directory = "Logs"
    if not os.path.exists(log_directory):
        os.makedirs(log_directory)
    
    # Create a timestamp to include in the log file name (e.g., Log_2024-10-21_14-30-00.txt)
    current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file_name = f"Log_{current_time}.txt"
    log_file_path = os.path.join(log_directory, log_file_name)
    
    # Open the log file in write mode
    with open(log_file_path, "w") as log_file:
        # Log the start of the scan and the directory being analyzed
        log_message(f"Log started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", log_file)
        log_message(f"Scanning directory: {directory_path}\n", log_file)
        
        # For each .exe file in the directory, perform the obfuscation check
        for exe_file in exe_files:
            file_path = os.path.join(directory_path, exe_file)
            check_obfuscation(file_path, log_file)

        # Log the end of the scan
        log_message(f"\nLog ended at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", log_file)
    
    # Notify the user where the log file has been saved
    print(f"Log saved to {log_file_path}")

# Main entry point for the script
if __name__ == "__main__":
    # Define the directory where .exe files to check are located
    exe_directory = "EXE Files to Check"
    
    # Check if the directory exists
    if os.path.exists(exe_directory):
        # If the directory exists, scan it for .exe files
        scan_directory(exe_directory)
    else:
        # If the directory does not exist, print an error message
        print(f"Directory '{exe_directory}' does not exist.")
