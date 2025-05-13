import tkinter as tk
from tkinter import filedialog, messagebox
import os
import re
from datetime import datetime  # Import datetime for timestamp

def extract_input_data(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"The file {file_path} does not exist.")
    with open(file_path, 'r') as f:
        lines = f.readlines()

    # Extract ICCID range
    iccid_range_line = lines[24]
    iccids = re.findall(r'\d{19}', iccid_range_line)
    start_iccid, end_iccid = iccids if len(iccids) == 2 else (None, None)

    # Extract Quantity
    qty_line = lines[4]
    qty_match = re.search(r'\d+', qty_line)
    quantity = int(qty_match.group()) if qty_match else None

    # Extract Product Name
    product_line = lines[15]
    product_match = re.search(r'SENSORISE_SS_(\w+)', product_line)
    product_name = product_match.group(1).upper() if product_match else None

    return start_iccid, end_iccid, quantity, product_name

def extract_license_data(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"The file {file_path} does not exist.")
    with open(file_path, 'r') as f:
        lines = f.readlines()

    # Extract License ICCID
    license_iccid_line = lines[0]
    license_iccid_match = re.search(r'ICCID:(\d{19})', license_iccid_line)
    license_iccid = license_iccid_match.group(1) if license_iccid_match else None

    # Extract License KEY
    key_line = lines[2].strip()
    key_match = re.search(r'KEY:([A-F0-9]+)', key_line)
    license_key = key_match.group(1) if key_match else None

    return license_iccid, license_key

def validate_and_generate_report():
    try:
        if not input_file_path.get() or not license_file_path.get():
            messagebox.showwarning("Missing File", "Please select both Input and License files.")
            return
        
        input_start_iccid, input_end_iccid, input_quantity, input_product = extract_input_data(input_file_path.get())
        license_iccid, license_key = extract_license_data(license_file_path.get())

        if None in (input_start_iccid, input_end_iccid, input_quantity, input_product, license_iccid, license_key):
            messagebox.showerror("Validation Error", "Failed to extract required information from files.")
            return

        errors = []
        comparison_results.delete(1.0, tk.END)
        comparison_results.insert(tk.END, f"Validation Details:\n\n")

        # 1. Start ICCID match
        if input_start_iccid != license_iccid:
            errors.append(f"Start ICCID mismatch!\nInput: {input_start_iccid}\nLicense: {license_iccid}\n")
        else:
            comparison_results.insert(tk.END, "Start ICCID match: OK\n")

        # 2. KEY Structure validation
        last_13_digits = input_start_iccid[-13:]
        expected_iccid_part = last_13_digits + 'F'

        expected_qty_minus_1 = input_quantity - 1
        expected_qty_str = f"{expected_qty_minus_1:06d}"  # Always 6 digits with leading zeros

        product_codes = {'NATIVE': '2022', 'JAVA': '0030'}
        expected_product_code = product_codes.get(input_product, None)

        if not expected_product_code:
            errors.append(f"Unknown Product Type: {input_product}")
        
        if not (license_key.startswith(expected_iccid_part) and
                expected_qty_str in license_key and
                expected_product_code in license_key):
            errors.append(f"KEY validation failed!\nExpected ICCID Part: {expected_iccid_part}\n"
                          f"Expected Qty (Qty-1): {expected_qty_str}\n"
                          f"Expected Product Code: {expected_product_code}\n"
                          f"Actual KEY: {license_key}\n")
        else:
            comparison_results.insert(tk.END, "License KEY structure match: OK\n")

        # 3. Product Code Verification
        if expected_product_code not in license_key:
            errors.append(f"Product code mismatch!\nExpected: {expected_product_code}\nFound in KEY: {license_key}\n")

        # Add timestamp for the report
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Report generation
        save_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text Files", "*.txt")],
                                                 title="Save Report As")
        if not save_path:
            return

        with open(save_path, 'w') as report_file:
            report_file.write("License Validation Report\n")
            report_file.write("=========================\n\n")
            report_file.write(f"Report Generated On: {timestamp}\n\n")
            report_file.write(f"Input Start ICCID: {input_start_iccid}\n")
            report_file.write(f"Input Quantity: {input_quantity}\n")
            report_file.write(f"Product Type: {input_product}\n")
            report_file.write(f"License Start ICCID: {license_iccid}\n")
            report_file.write(f"License Key: {license_key}\n\n")
            if errors:
                report_file.write("Validation Errors:\n")
                for error in errors:
                    report_file.write(f"- {error}\n")
            else:
                report_file.write("Validation Successful. No errors found.\n")

        if errors:
            messagebox.showerror("Validation Errors", "\n".join(errors))
            for error in errors:
                comparison_results.insert(tk.END, f"Error: {error}\n")
        else:
            messagebox.showinfo("Validation Successful", "License validation completed successfully.\nReport saved.")
            comparison_results.insert(tk.END, "Validation completed successfully. No errors found.\n")

    except Exception as e:
        messagebox.showerror("Error", str(e))

def browse_input_file():
    file_path = filedialog.askopenfilename(filetypes=[("Input Files", "*.inp")])
    if file_path:
        input_file_path.set(file_path)
        input_file_display.set(os.path.basename(file_path))

def browse_license_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file_path:
        license_file_path.set(file_path)
        license_file_display.set(os.path.basename(file_path))

def clear_fields():
    input_file_path.set("")
    license_file_path.set("")
    input_file_display.set("")
    license_file_display.set("")
    comparison_results.delete(1.0, tk.END)

# UI Setup
root = tk.Tk()
root.title("Validation Tool VI")
root.geometry("700x500")
root.configure(padx=20, pady=20)

input_file_path = tk.StringVar()
license_file_path = tk.StringVar()
input_file_display = tk.StringVar()
license_file_display = tk.StringVar()

tk.Label(root, text="Validation Tool VI", font=("Helvetica", 16, "bold")).pack(pady=10)

# Input File
input_frame = tk.Frame(root)
input_frame.pack(fill="x", pady=5)
tk.Label(input_frame, text="Input File:", width=15, anchor="w").pack(side="left")
tk.Entry(input_frame, textvariable=input_file_display, state='readonly', width=50).pack(side="left", padx=5)
tk.Button(input_frame, text="Browse", command=browse_input_file).pack(side="left")

# License File
license_frame = tk.Frame(root)
license_frame.pack(fill="x", pady=5)
tk.Label(license_frame, text="License File:", width=15, anchor="w").pack(side="left")
tk.Entry(license_frame, textvariable=license_file_display, state='readonly', width=50).pack(side="left", padx=5)
tk.Button(license_frame, text="Browse", command=browse_license_file).pack(side="left")

# Comparison Results
comparison_results = tk.Text(root, height=15, width=80, wrap=tk.WORD)
comparison_results.pack(pady=10)

# Buttons
buttons_frame = tk.Frame(root)
buttons_frame.pack(pady=20)
tk.Button(buttons_frame, text="Validate", command=validate_and_generate_report, font=("Arial", 12)).pack(side="left", padx=10)
tk.Button(buttons_frame, text="Clear", command=clear_fields, font=("Arial", 12), bg="lightgray").pack(side="left", padx=10)

root.mainloop()
