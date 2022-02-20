# Antivirus for Files Integrity Checking in Java
The solution uses the Java Cryptographic Architecture to verify the integrity of the files in a folder and in its subfolders. It computes the SHA-256 HMAC of those files.

The application has two modes of operating: status update (computes the HMACs of all files in the path) and integrity check (recomputes the HMACs of all files in the path and checks them against the ones already stored to see if the files were tampered with).

When an integrity check is made, the application generates a report with the result. The files that were modified are signaled as CORRUPTED.

Input parameters:
- mode: status update/integrity check
- secret key
- root folder 