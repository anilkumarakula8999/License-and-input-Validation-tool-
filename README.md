📘 License & Input Validation Tool (v1.4)

A Python Tkinter-based desktop application that validates MNO Input Files (.inp) and Partner License Files (.txt) used in SIM data generation.
This tool helps telecom data generation teams reduce manual effort, avoid mistakes, and automate file validation.

🚀 Features
✔ ICCID Validation

Extracts Start ICCID from Input File (Line 25)

Compares with License ICCID (Line 1)

✔ Product Code Validation

Supported mapping:

Product	Code
JAVA	0030
NATIVE	2022

Extracts Product Code from License Key at positions 21–24.

✔ Quantity Validation

Reads input quantity (Line 5)

Compares with license quantity (Line 2)

✔ Error Handling

Provides detailed mismatch messages:

Expected vs Actual

Missing or invalid fields

Wrong ICCID, quantity, or product code

Invalid license key length

✔ Auto Report Generation

A validation report is automatically generated:
📄 <input_filename>_validation_report.txt

The report includes:

ICCID comparison

Product name + product code

Quantity comparison

All validation errors

✔ Simple Tkinter GUI

Browse Input File

Browse License File

Validate

Clear fields

Live result window

🛠 Tech Stack

Python 3

Tkinter GUI

Regex

Datetime

OS module

📂 Supported File Types
File Type	Format	Purpose
.inp	MNO Input	Contains ICCID range, product name, quantity
.txt	License File	Contains ICCID, quantity, license key
📌 Usage
Step 1 — Select Input File

Choose the .inp file from MNO.

Step 2 — Select License File

Choose the .txt license file from partner.

Step 3 — Validate

The app checks:

ICCID match

Quantity match

Product → Product Code mapping

Product code from license key

Step 4 — Get Report

A report is saved in the same folder as input file.

📄 Sample Validation Report
Vodafone License Validation Report (Version 1.4)
===============================================

Report Generated On: 2025-11-26 10:18:20

Input File ICCID Start: 8991101200000000001
License File ICCID:     8991101200000000001

Product Type: JAVA
Expected Product Code: 0030
Actual Product Code:   0030

Quantity from Input File: 5000
Quantity in License File: 5000

Validation Successful — No errors found.

🧪 Installation

Install Tkinter (usually pre-installed with Python):

pip install tk


Clone the repository:

git clone https://github.com/anilkumarakula8999/License-and-input-Validation-tool-


Run the tool:

python license_validator.py
