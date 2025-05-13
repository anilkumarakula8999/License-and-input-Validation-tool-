import tkinter as tk
from tkinter import filedialog, messagebox
import os
import re

# Function to extract input data from the input file
def extract_input_data(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"The file {file_path} does not exist.")
    with open(file_path, 'r') as f:
        lines = f.readlines()
    iccid_range_line = lines[24]
    iccids = re.findall(r'\d{19}', iccid_range_line)
    start_iccid, end_iccid = iccids if len(iccids) == 2 else (None, None)
    product_line = lines[15]
    product_match = re.search(r'SENSORISE_SS_(\w+)', product_line)
    product_name = product_match.group(1).upper() if product_match else None
    return start_iccid, product_name

# Function to extract license data from the license file
def extract_license_data(file_path):
    with open(file_path, 'r') as f:
        lines = f.readlines()
    license_iccid = re.search(r'ICCID:(\d{19})', lines[0])
    license_iccid = license_iccid.group(1) if license_iccid else None
    key_line = lines[2].strip()
    product_code = None
    if "0030" in key_line:
        product_code = "0030"
    elif "2022" in key_line:
        product_code = "2022"
    if product_code == "0030" and "0030" not in key_line:
        raise ValueError("License key mismatched: 0030 not found in the license key")
    return license_iccid, product_code

# Function to validate input data and generate a report
def validate_and_generate_report():
    try:
        if not input_file_path.get() or not license_file_path.get():
            messagebox.showwarning("Missing File", "Please select both Input and License files.")
            return
        input_start_iccid, input_product = extract_input_data(input_file_path.get())
        license_iccid, license_code = extract_license_data(license_file_path.get())
        if input_start_iccid is None or input_product is None or license_iccid is None or license_code is None:
            messagebox.showerror("Product Type Mismatched", "Failed to validate the extracted data. Please check the file content and try again.")
            return
        
        errors = []
        expected_codes = {'NATIVE': '2022', 'JAVA': '0030'}
        expected_code = expected_codes.get(input_product, None)

        # Display comparison results in the UI
        comparison_results.delete(1.0, tk.END)  # Clear any previous results
        comparison_results.insert(tk.END, f"Comparing ICCID and Product for Validation:\n\n")
        comparison_results.insert(tk.END, f"Input ICCID: {input_start_iccid}\n")
        comparison_results.insert(tk.END, f"License ICCID: {license_iccid}\n")
        comparison_results.insert(tk.END, f"Product: {input_product}\n")
        comparison_results.insert(tk.END, f"Expected Code: {expected_code}\n")
        comparison_results.insert(tk.END, f"License Code: {license_code}\n\n")

        if input_start_iccid != license_iccid:
            errors.append(f"ICCID mismatch! Input: {input_start_iccid}, License: {license_iccid}")
            comparison_results.insert(tk.END, f"Error: ICCID mismatch! Input: {input_start_iccid}, License: {license_iccid}\n")
        
        if license_code != expected_code:
            if license_code is None:
                errors.append(f"Product code mismatch! Expected: {expected_code}, but found none in the license.")
                comparison_results.insert(tk.END, f"Error: Product code mismatch! Expected: {expected_code}, but found none in the license.\n")
            else:
                errors.append(f"Product code mismatch! Expected: {expected_code}, but found: {license_code}")
                comparison_results.insert(tk.END, f"Error: Product code mismatch! Expected: {expected_code}, but found: {license_code}\n")
        
        if errors:
            messagebox.showerror("Product Type Mismatched", "\n".join(errors))
            return
        
        report_content = (
            f"ICCID Start: {input_start_iccid}\n"
            f"Product: {input_product}\n"
            f"Expected Code: {expected_code}\n"
            f"License Code: {license_code}\n"
        )
        with open("license_validation_report.txt", "w") as report_file:
            report_file.write(report_content)
            if errors:
                report_file.write("\nErrors:\n" + "\n".join(errors))
        if not errors:
            messagebox.showinfo("Validation Successful", "License validation completed successfully. Report generated.")
    except ValueError as e:
        messagebox.showerror("License Key Mismatched", str(e))

# Function to browse for the input file
def browse_input_file():
    file_path = filedialog.askopenfilename(filetypes=[("Input Files", "*.inp")])
    if file_path:
        input_file_path.set(file_path)
        input_file_display.set(os.path.basename(file_path))

# Function to browse for the license file
def browse_license_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file_path:
        license_file_path.set(file_path)
        license_file_display.set(os.path.basename(file_path))

# Function to clear the fields
def clear_fields():
    input_file_path.set("")
    license_file_path.set("")
    input_file_display.set("")
    license_file_display.set("")
    comparison_results.delete(1.0, tk.END)

# UI Setup
root = tk.Tk()
root.title("Madhan Kotte")  # Changed title to "Madhan Kotte"
root.geometry("600x400")
root.configure(padx=20, pady=20)

input_file_path = tk.StringVar()
license_file_path = tk.StringVar()
input_file_display = tk.StringVar()
license_file_display = tk.StringVar()

tk.Label(root, text="Madhan Kotte", font=("Helvetica", 16, "bold")).pack(pady=10)

# Input File
input_frame = tk.Frame(root)
input_frame.pack(fill="x", pady=5)

tk.Label(input_frame, text="Input File:", width=15, anchor="w").pack(side="left")
tk.Entry(input_frame, textvariable=input_file_display, state='readonly', width=40).pack(side="left", padx=5)
tk.Button(input_frame, text="Browse", command=browse_input_file).pack(side="left")

# License File
license_frame = tk.Frame(root)
license_frame.pack(fill="x", pady=5)

tk.Label(license_frame, text="License File:", width=15, anchor="w").pack(side="left")
tk.Entry(license_frame, textvariable=license_file_display, state='readonly', width=40).pack(side="left", padx=5)
tk.Button(license_frame, text="Browse", command=browse_license_file).pack(side="left")

# Comparison Results (Text Widget)
comparison_results = tk.Text(root, height=10, width=70, wrap=tk.WORD)
comparison_results.pack(pady=10)

# Buttons Frame (for placing Validate and Clear buttons side by side)
buttons_frame = tk.Frame(root)
buttons_frame.pack(pady=20)

# Validate Button
tk.Button(buttons_frame, text="Validate", command=validate_and_generate_report, font=("Arial", 12)).pack(side="left", padx=10)

# Clear Button
tk.Button(buttons_frame, text="Clear", command=clear_fields, font=("Arial", 12), bg="lightgray").pack(side="left", padx=10)

root.mainloop()
