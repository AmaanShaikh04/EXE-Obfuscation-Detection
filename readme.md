# Obfuscated EXE File Detector

This tool helps analyze `.exe` files for signs of obfuscation by calculating the entropy of their sections. High entropy values may indicate that the file has been packed or encrypted, which can be a sign of potential danger.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Entropy Threshold](#entropy-threshold)
- [Log File Format](#log-file-format)
- [Customization](#customization)

## Features

- Scans all `.exe` files in a specified directory.
- Calculates the Shannon entropy for each section within the `.exe` files.
- Identifies sections with high entropy, suggesting possible obfuscation.
- Generates a detailed log file of the analysis results.
- Terminal output mirrors the log file content for easy tracking.

## Installation

1. Clone this repository or download the script file.
2. Make sure you have Python installed on your system (Python 3.x recommended).
3. Install the required `pefile` library, if you haven't already:

    ```
   pip install pefile
    ```

4. Place your `.exe` files in the folder named `EXE Files to Check`, located in the same directory as the script.

## Usage

1. Open a terminal or command prompt.
2. Navigate to the directory containing the script.
3. Run the script using the following command:

    ```
   python obfuscation_detector.py
    ```

4. The tool will scan the specified directory and create a log file in the `Logs` folder.

## How It Works

- **Entropy Calculation**: The tool computes the Shannon entropy for each section of the `.exe` files. Sections with high entropy (above 7.5) may indicate potential obfuscation.
  
- **Logging**: All analysis results, including file names, obfuscated sections, and status (Dangerous/Non-dangerous), are logged into a timestamped file.

## Entropy Threshold

The default entropy threshold is set at **7.5**. This value is commonly used in the field for detecting obfuscated files. Files exceeding this threshold are flagged as potentially dangerous. You can adjust this value based on your specific analysis needs.

## Log File Format

Log files are named using the format `Log_CurrentDate_CurrentTime.txt` and contain the following information:

```
Log started at YYYY-MM-DD HH:MM:SS
Scanning directory: path/to/directory

Analyzing path/to/file.exe...
  Section .text: Entropy = X.XX
  Section .data: Entropy = Y.YY
  Suspicious sections in path/to/file.exe: .text
  Status: Dangerous

Log ended at YYYY-MM-DD HH:MM:SS
```

## Customization

- **Adjustable Entropy Threshold**: Modify the threshold value in the code to increase or decrease detection sensitivity.
- **Enhanced Logging**: You can expand the log file to include additional details, such as section sizes or PE file metadata.
