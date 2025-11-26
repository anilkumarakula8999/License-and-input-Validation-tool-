📘 Vodafone License Validation Tool (v1.4)

A Python Tkinter-based desktop application that validates Vodafone SIM license files against MNO input files.
This tool automates manual comparisons during SIM data generation and ensures accuracy before sending files to production.

🚀 Features
✔ ICCID Validation

Extracts Start ICCID from Input File (Line 25)

Compares with License ICCID (Line 1)

✔ Product Code Validation

Maps product type to product code:

JAVA → 0030

NATIVE → 2022

Extracts product code from License Key (characters 21–24) and verifies it.

✔ Quantity Validation

Reads input quantity (Line 5)

Compares with license quantity (Line 2)

✔ Error Reporting

Shows detailed mismatch information:

Expected vs Actual values

Missing fields

Invalid ICCID, product code, or quantity

✔ Auto Report Generation

Generates a validation report:

<filename>_validation_report.txt


Report contains all extracted values + all mismatches.

✔ User-Friendly GUI

Browse buttons for file selection

Real-time validation messages

Clean Tkinter interface

🛠 Tech Stack

Python 3

Tkinter (GUI)

Regex

OS / Datetime modules

📂 Supported File Formats
File Type	Format	Example
Input File	.inp	Contains ICCID range, product name, quantity
License File	.txt	Contains ICCID, quantity, and license key
📌 How to Use

Open the application.

Select Input File (.inp).

Select License File (.txt).

Click Validate.

View results on the screen.

Report file will be auto-saved next to the input file.

🧪 Validations Performed
Validation	Input File	License File	Output
Start ICCID	Line 25	Line 1	Match / Error
Product Type	Line 16	Derived from Key	Match / Error
Quantity	Line 5	Line 2	Match / Error
Product Code	Mapped	Extracted from Key	Match / Error
📄 Sample Report Output
Vodafone License Validation Report (Version 1.4)
================================================

Report Generated On: 2025-11-26 10:15:22

Input File ICCID Start: 8991101200000000001
License File ICCID: 8991101200000000001

Product Type: JAVA
Expected Product Code: 0030
Actual Product Code: 0030

Total Quantity: 5000
License Quantity: 5000

Validation Successful. No errors found.

📦 Installation
pip install tk


Clone the repository:

git clone https://github.com/anilkumarakula8999/ansible


Run the tool:

python validation_tool.py
