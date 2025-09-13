# Quantum Password Generator

A Tkinter-based **Quantum Password Generator** that uses the [ANU Quantum Random Numbers Server](https://qrng.anu.edu.au/) to generate high-entropy passwords, with cryptographic fallback, entropy calculation, clipboard copy, and save-to-file support.  

---

##  Features

-  **Quantum randomness** via ANU QRNG API.  
-  **Cryptographic fallback** with Python’s `secrets` if quantum service is unavailable.  
-  Password customization:
  - Adjustable length (8–32 characters).  
  - Option to include or exclude symbols.  
  - Guaranteed mix of uppercase, lowercase, and digits.  
-  **Quantum shuffle algorithm** for maximum unpredictability.  
-  **Entropy calculation** displayed in bits.  
-  **Copy to clipboard** with one click.  
-  **Save password to file** with timestamp and method used (Quantum or Cryptographic).  
-  Clean **Tkinter-based GUI** with modern styling.  

---

##  Screenshots

<div style="display: flex; gap: 20px;">

  <div>
    <p><strong>Quantum Password Generator UI:</strong></p>
    
  </div>

  <div>
    <p><strong>Password Generated with Entropy Calculation:</strong></p>
    <img width="663" height="370" alt="Image" src="https://github.com/user-attachments/assets/eba8d112-88e2-4341-90b8-964e6e7ecb55" />
  </div>

</div>


---
