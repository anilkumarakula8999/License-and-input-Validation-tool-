import tkinter as tk
from tkinter import filedialog, messagebox
import os
import re
from datetime import datetime

def extract_input_data(file_path):
    errors = []
    with open(file_path, 'r') as f:
        lines = f.readlines()

    if len(lines) < 25:
        errors.append("Input file has fewer than 25 lines.")
        return None, None, None, None, errors

    iccid_range_line = lines[24]
    iccids = re.findall(r'\d{19}', iccid_range_line)
    if len(iccids) == 2:
        start_iccid, end_iccid = iccids
    else:
        errors.append("Start and end ICCID not found or incomplete in input file (line 25).")
        start_iccid, end_iccid = None, None

    product_line = lines[15] if len(lines) > 15 else ""
    product_match = re.search(r'SENSORISE_SS_(\w+)', product_line, re.IGNORECASE)
    product_name = product_match.group(1).upper() if product_match else None
    if not product_name:
        errors.append("Product name not found or invalid in input file (line 16).")

    quantity_line = lines[4] if len(lines) > 4 else ""
    quantity_match = re.search(r'Quantity:\s*(\d+)', quantity_line, re.IGNORECASE)
    if quantity_match:
        original_qty = int(quantity_match.group(1))
        quantity = str(original_qty)
    else:
        quantity = None
        errors.append("Quantity not found or invalid in input file (line 5).")

    return start_iccid, end_iccid, product_name, quantity, errors

def extract_license_data(file_path):
    errors = []
    with open(file_path, 'r') as f:
        lines = f.readlines()

    if len(lines) < 3:
        errors.append("License file has fewer than 3 lines.")
        return None, None, None, errors

    iccid_line = lines[0].strip().upper()
    iccid_match = re.search(r'ICCID:(\d{19})', iccid_line)
    license_iccid = iccid_match.group(1) if iccid_match else None
    if not license_iccid:
        errors.append("ICCID not found or invalid in license file (line 1).")

    quantity_line = lines[1].strip().upper()
    quantity_match = re.search(r'QUANTITY:\s*(\d+)', quantity_line)
    license_quantity = quantity_match.group(1) if quantity_match else None
    if not license_quantity:
        errors.append("Quantity not found or invalid in license file (line 2).")

    key_line = lines[2].strip().upper()
    key_match = re.search(r'KEY:([A-F0-9]+)', key_line)
    license_key = key_match.group(1) if key_match else None
    if not license_key:
        errors.append("License key not found or invalid in license file (line 3).")

    return license_iccid, license_key, license_quantity, errors

def validate_and_generate_report():
    try:
        if not input_file_path.get() or not license_file_path.get():
            messagebox.showwarning("Missing File", "Please select both Input and License files.")
            return

        input_iccid_start, input_iccid_end, product_type, total_quantity, input_errors = extract_input_data(input_file_path.get())
        license_iccid, license_key, license_quantity, license_errors = extract_license_data(license_file_path.get())

        errors = input_errors + license_errors

        comparison_results.delete(1.0, tk.END)
        comparison_results.insert(tk.END, "Validation Report:\n\n")

        if errors:
            for err in errors:
                comparison_results.insert(tk.END, f"Error: {err}\n")
            messagebox.showerror("Extraction Errors", "\n".join(errors))
            return

        # ICCID check
        if input_iccid_start != license_iccid:
            errors.append(f"ICCID mismatch!\nExpected: {input_iccid_start}\nActual: {license_iccid}")
        else:
            comparison_results.insert(tk.END, "Start ICCID match: OK\n")

        # Product code check
        expected_codes = {'JAVA': '0030', 'NATIVE': '2022'}
        expected_code = expected_codes.get(product_type)
        actual_code = None
        product_code_matched = False

        # Clean and normalize license key (remove spaces or newlines if any)
        license_key_clean = license_key.replace(" ", "").strip()
        # Validate license key length
        if len(license_key_clean) < 24:
           errors.append(f"Invalid license key length: expected at least 24 characters, got {len(license_key_clean)}")
        else:
            # Extract product code from positions 21 to 24 (0-based index 20 to 23)
            actual_code = license_key_clean[20:24]
         
            if not expected_code:
                errors.append(f"Unknown Product Type: {product_type}")
            elif actual_code == expected_code:
                product_code_matched = True
                comparison_results.insert(tk.END, f"Product code match: OK ({expected_code})\n")
            else:
                errors.append(f"Product code mismatch!\nExpected: {expected_code}\nActual: {actual_code}")
        # Quantity check
        if total_quantity != license_quantity:
            errors.append(f"Quantity mismatch!\nExpected: {total_quantity}\nActual: {license_quantity}")
        else:
            comparison_results.insert(tk.END, f"Quantity match: OK ({total_quantity})\n")

        # Save report
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        input_file_name = os.path.splitext(os.path.basename(input_file_path.get()))[0]
        save_path = os.path.join(os.path.dirname(input_file_path.get()), f"{input_file_name}_validation_report.txt")

        with open(save_path, 'w') as f:
            f.write("Vodafone License Validation Report (Version 1.4)\n")
            f.write("===============================================\n\n")
            f.write(f"Report Generated On: {timestamp}\n\n")
            f.write(f"Input File ICCID Start: {input_iccid_start}\n")
            f.write(f"License File ICCID: {license_iccid}\n")
            f.write(f"Product Type: {product_type}\n")
            f.write(f"Expected Product Code: {expected_code}\n")
            if product_code_matched:
                f.write(f"Actual Product Code: {actual_code}\n")
            f.write(f"Total Quantity (from Input File): {total_quantity}\n")
            f.write(f"Quantity in License File: {license_quantity}\n\n")

            if errors:
                f.write("Validation Errors:\n")
                for err in errors:
                    f.write(f"- {err}\n")
            else:
                f.write("Validation Successful. No errors found.\n")

        if errors:
            messagebox.showerror("Validation Failed", "\n"s.join(errors))
            for err in errors:
                comparison_results.insert(tk.END, f"Error: {err}\n")
        else:
            messagebox.showinfo("Validation Success", "All validations passed.")
            comparison_results.insert(tk.END, "Validation completed successfully.\n")

    except Exception as e:
        messagebox.showerror("Error", str(e))

def browse_input_file():
    file = filedialog.askopenfilename(filetypes=[("Input Files", "*.inp")])
    if file:
        input_file_path.set(file)
        input_file_display.set(os.path.basename(file))

def browse_license_file():
    file = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file:
        license_file_path.set(file)
        license_file_display.set(os.path.basename(file))

def clear_fields():
    input_file_path.set("")
    license_file_path.set("")
    input_file_display.set("")
    license_file_display.set("")
    comparison_results.delete(1.0, tk.END)

# GUI Setup
root = tk.Tk()
root.title("Vodafone License Validation Tool v1.4")
root.geometry("700x500")
root.configure(padx=20, pady=20)

input_file_path = tk.StringVar()
license_file_path = tk.StringVar()
input_file_display = tk.StringVar()
license_file_display = tk.StringVar()

tk.Label(root, text="Vodafone License Validation Tool V1.4", font=("Helvetica", 16, "bold")).grid(row=0, column=0, columnspan=2, pady=10)

input_frame = tk.Frame(root)
input_frame.grid(row=1, column=0, columnspan=2, pady=5, sticky="ew")
tk.Label(input_frame, text="Input File:", width=15, anchor="w").pack(side="left")
tk.Entry(input_frame, textvariable=input_file_display, state='readonly', width=50).pack(side="left", padx=5)
tk.Button(input_frame, text="Browse", command=browse_input_file).pack(side="left")

license_frame = tk.Frame(root)
license_frame.grid(row=2, column=0, columnspan=2, pady=5, sticky="ew")
tk.Label(license_frame, text="License File:", width=15, anchor="w").pack(side="left")
tk.Entry(license_frame, textvariable=license_file_display, state='readonly', width=50).pack(side="left", padx=5)
tk.Button(license_frame, text="Browse", command=browse_license_file).pack(side="left")

comparison_results = tk.Text(root, height=15, width=80, wrap=tk.WORD)
comparison_results.grid(row=3, column=0, columnspan=2, pady=10)

buttons_frame = tk.Frame(root)
buttons_frame.grid(row=4, column=0, columnspan=2, pady=10)
tk.Button(buttons_frame, text="Validate", command=validate_and_generate_report).pack(side="left", padx=10)
tk.Button(buttons_frame, text="Clear", command=clear_fields).pack(side="left", padx=10)

root.mainloop()
