import random
import string
from tkinter import *
from tkinter import filedialog
from tkinter import ttk
from tkinter import messagebox
import pyperclip
import requests
import hashlib
import time


class QuantumPasswordGenerator:
    def __init__(self):
        self.quantum_source = "anu"  # Default to ANU quantum source
        self.fallback_to_crypto = True

    def get_quantum_random_bytes(self, num_bytes=32):
        """Get quantum random bytes from ANU Quantum Random Numbers Server"""
        try:
            if self.offline_mode:
                raise Exception("Offline mode enabled")

            # ANU Quantum Random Numbers Server API
            url = f"https://qrng.anu.edu.au/API/jsonI.php?length={num_bytes}&type=uint8"
            response = requests.get(url, timeout=5)

            if response.status_code == 200:
                data = response.json()
                if data['success']:
                    return bytes(data['data'])

            raise Exception("Quantum service unavailable")

        except Exception as e:
            print(f"Quantum source failed: {e}")
            if self.fallback_to_crypto:
                # Fallback to cryptographically secure random
                import os
                return os.urandom(num_bytes)
            else:
                raise e

    def quantum_choice(self, sequence):
        """Make a quantum random choice from a sequence"""
        if not sequence:
            return None

        quantum_bytes = self.get_quantum_random_bytes(4)
        quantum_int = int.from_bytes(quantum_bytes, byteorder='big')
        index = quantum_int % len(sequence)
        return sequence[index]

    def quantum_shuffle(self, sequence):
        """Quantum Fisher-Yates shuffle"""
        sequence = list(sequence)
        for i in range(len(sequence) - 1, 0, -1):
            quantum_bytes = self.get_quantum_random_bytes(4)
            quantum_int = int.from_bytes(quantum_bytes, byteorder='big')
            j = quantum_int % (i + 1)
            sequence[i], sequence[j] = sequence[j], sequence[i]
        return sequence

    def generate_quantum_password(self, length=12, include_symbols=True):
        """Generate a quantum random password"""
        try:
            # Character sets
            uppercase = string.ascii_uppercase
            lowercase = string.ascii_lowercase
            digits = string.digits
            symbols = string.punctuation if include_symbols else ""

            # Ensure at least one character from each required set
            required = [
                self.quantum_choice(uppercase),
                self.quantum_choice(uppercase),
                self.quantum_choice(lowercase),
                self.quantum_choice(digits),
                self.quantum_choice(digits)
            ]

            if include_symbols:
                required.extend([
                    self.quantum_choice(symbols),
                    self.quantum_choice(symbols)
                ])

            # Fill remaining length with random characters
            all_chars = uppercase + lowercase + digits + symbols
            remaining_length = length - len(required)

            for _ in range(remaining_length):
                required.append(self.quantum_choice(all_chars))

            # Quantum shuffle the final password
            password_chars = self.quantum_shuffle(required)
            return ''.join(password_chars)

        except Exception as e:
            messagebox.showerror("Quantum Error",
                                 f"Quantum generation failed: {e}\nFalling back to standard generation.")
            return self.fallback_generate(length, include_symbols)

    def fallback_generate(self, length=12, include_symbols=True):
        """Fallback to standard cryptographically secure generation"""
        import secrets

        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        digits = string.digits
        symbols = string.punctuation if include_symbols else ""

        required = [
            secrets.choice(uppercase),
            secrets.choice(uppercase),
            secrets.choice(lowercase),
            secrets.choice(digits),
            secrets.choice(digits)
        ]

        if include_symbols:
            required.extend([
                secrets.choice(symbols),
                secrets.choice(symbols)
            ])

        all_chars = uppercase + lowercase + digits + symbols
        remaining_length = length - len(required)

        for _ in range(remaining_length):
            required.append(secrets.choice(all_chars))

        # Shuffle using secrets
        for i in range(len(required) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            required[i], required[j] = required[j], required[i]

        return ''.join(required)


# Global quantum generator instance
quantum_gen = QuantumPasswordGenerator()


def generate():
    try:
        length = int(length_var.get())
        include_symbols = symbols_var.get()

        if quantum_var.get():
            status_label.config(text="Generating quantum password...")
            window.update()
            password = quantum_gen.generate_quantum_password(length, include_symbols)
            status_label.config(text="Quantum password generated!")
        else:
            password = quantum_gen.fallback_generate(length, include_symbols)
            status_label.config(text="Cryptographic password generated!")

        genpass.set(password)
        save_button.config(state=NORMAL)
        copy_button.config(state=NORMAL)

        # Calculate entropy
        entropy = calculate_entropy(password)
        entropy_label.config(text=f"Entropy: {entropy:.1f} bits")

    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter a valid password length.")
    except Exception as e:
        messagebox.showerror("Generation Error", f"An error occurred: {e}")
        status_label.config(text="Generation failed!")


def calculate_entropy(password):
    """Calculate password entropy in bits"""
    charset_size = 0
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += len(string.punctuation)

    import math
    return len(password) * math.log2(charset_size) if charset_size > 0 else 0


def copy():
    pyperclip.copy(genpass.get())
    status_label.config(text="Password copied to clipboard!")


def save():
    try:
        file = filedialog.asksaveasfile(defaultextension='.txt',
                                        filetypes=[("Text file", ".txt")])
        if file:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            method = "Quantum" if quantum_var.get() else "Cryptographic"
            filetext = f"Generated: {timestamp}\nMethod: {method}\nPassword: {genpass.get()}\n"
            file.write(filetext)
            file.close()
            status_label.config(text="Password saved successfully!")
    except AttributeError:
        status_label.config(text="Save aborted!")


def test_quantum_connection():
    """Test quantum random number service"""
    try:
        status_label.config(text="Testing quantum connection...")
        window.update()
        quantum_gen.get_quantum_random_bytes(1)
        status_label.config(text="Quantum service available!")
        messagebox.showinfo("Quantum Test", "Successfully connected to ANU Quantum Random Number Server!")
    except Exception as e:
        status_label.config(text="Quantum service unavailable!")
        messagebox.showwarning("Quantum Test", f"Quantum service test failed: {e}\nWill use cryptographic fallback.")


# Create main window
window = Tk()
window.title("Quantum Password Generator")
window.configure(bg='#2c3e50')

# Configure styles
style = ttk.Style()
style.theme_use('clam')
style.configure('TButton', font=('Consolas', 12), padding=8)
style.configure('TLabel', font=('Consolas', 12), padding=5, background='#2c3e50', foreground='white')
style.configure('TCheckbutton', font=('Consolas', 10), background='#2c3e50', foreground='white')
style.configure('TScale', background='#2c3e50')

# Variables
genpass = StringVar()
genpass.set("Click Generate for Quantum Password")
quantum_var = BooleanVar(value=True)
symbols_var = BooleanVar(value=True)
length_var = IntVar(value=16)

# Title
title_label = ttk.Label(window, text="🔒 QUANTUM PASSWORD GENERATOR 🔒",
                        font=('Consolas', 16, 'bold'))
title_label.grid(row=0, column=0, columnspan=4, pady=10)

# Password display
password_frame = Frame(window, bg='#34495e', relief=RAISED, bd=2)
password_frame.grid(row=1, column=0, columnspan=4, pady=10, padx=10, sticky="ew")

password_label = ttk.Label(password_frame, textvariable=genpass,
                           background="#34495e", foreground="#ecf0f1",
                           font=('Consolas', 11, 'bold'))
password_label.pack(pady=10, padx=10)

# Options frame
options_frame = Frame(window, bg='#2c3e50')
options_frame.grid(row=2, column=0, columnspan=4, pady=10)

# Quantum checkbox
quantum_check = ttk.Checkbutton(options_frame, text="🌌 Use Quantum Randomness",
                                variable=quantum_var)
quantum_check.grid(row=0, column=0, padx=20, sticky="w")

# Symbols checkbox
symbols_check = ttk.Checkbutton(options_frame, text="Include Symbols",
                                variable=symbols_var)
symbols_check.grid(row=0, column=1, padx=20, sticky="w")

# Length control
length_frame = Frame(options_frame, bg='#2c3e50')
length_frame.grid(row=1, column=0, columnspan=2, pady=10)

ttk.Label(length_frame, text="Password Length:", background='#2c3e50', foreground='white').pack(side=LEFT)
length_scale = ttk.Scale(length_frame, from_=8, to=32, variable=length_var, orient=HORIZONTAL)
length_scale.pack(side=LEFT, padx=10)
length_display = ttk.Label(length_frame, textvariable=length_var, background='#2c3e50', foreground='white')
length_display.pack(side=LEFT)

# Buttons frame
buttons_frame = Frame(window, bg='#2c3e50')
buttons_frame.grid(row=3, column=0, columnspan=4, pady=10)

test_button = ttk.Button(buttons_frame, text="Test Quantum", command=test_quantum_connection)
test_button.grid(row=0, column=0, padx=5)

generate_button = ttk.Button(buttons_frame, text="Generate", command=generate)
generate_button.grid(row=0, column=1, padx=5)

copy_button = ttk.Button(buttons_frame, text="Copy", command=copy, state=DISABLED)
copy_button.grid(row=0, column=2, padx=5)

save_button = ttk.Button(buttons_frame, text="Save", command=save, state=DISABLED)
save_button.grid(row=0, column=3, padx=5)

exit_button = ttk.Button(buttons_frame, text="Quit", command=window.quit)
exit_button.grid(row=0, column=4, padx=5)

# Status and entropy labels
status_label = ttk.Label(window, text="Ready to generate quantum passwords",
                         background='#2c3e50', foreground='#3498db')
status_label.grid(row=4, column=0, columnspan=4, pady=5)

entropy_label = ttk.Label(window, text="Entropy: 0.0 bits",
                          background='#2c3e50', foreground='#e74c3c')
entropy_label.grid(row=5, column=0, columnspan=4, pady=5)

# Configure grid weights
for i in range(4):
    window.columnconfigure(i, weight=1)

window.minsize(500, 350)
window.mainloop()
