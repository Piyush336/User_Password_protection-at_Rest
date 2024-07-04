# INTEL UNNATI PROGRAM 
# User_Password_protection-at_Rest(on the Disk)
**DESCRIPTION**
1. Encrypt [AES-256] a user chosen file or directory using a random key a.k.a File Encryption Key.
2. Store the random key in a file, which has to be protected via user pass phrase.
3. The user pass phrase as well as the random key cannot be stored in plain form in the text file.


> See live demo: [https://itsvj.me](https://itsvj.me)    |  Feel free to use, but credit appreciated and a ⭐ to the repo would be awesome! ✨ ;)


Hi there! I'm Piyush, form Team - **THE BREACHERS** and this is our Project on Cybersecurity Domain Based on Encryption and Decryption of files or folder on a disk using a Graphical User Interface. Let's dive into the features:

## **HPJ_CRYP Features:**

* **🔒Password Handling✌️:**
  1. Securely prompts for user password without echoing.
  2. Confirms the password for correctness.
* **🤖🎊📄Encryption and Decryption🔓🔐:**
  1. Utilizes AES (Advanced Encryption Standard) in CFB (Cipher Feedback) mode.
  2. Generates a random encryption key or derives it from a user-provided password and salt.
  3. Supports encryption and decryption of files and folders. 
* **📂File Handling💻:**
  1. Allows browsing and selecting files or folders for encryption or decryption.
  2. Saves encrypted data and retrieves it for decryption.
* **😵‍💫Error Handling and Feedback🚀:**
  1. Provides error messages for issues like file not found or incorrect password.
  2. Feedback on successful encryption or decryption.
* **Graphical User Interface (GUI) ✅:**
  1. Includes fields for file/folder paths and buttons for browsing and actions.
  2. Displays progress bar and status messages for ongoing operations. 


### **Technologies Used:**
1. Graphical User Interface
    1.**tkinter**

2. Cryptography
   1. **pycryptodome**
       1. AES (Advanced Encryption Standard)
            * AES-256 in **CFB (Cipher Feedback)** mode for encryption.
       2. PBKDF2 (Password-Based Key Derivation Function 2)
            * derive a cryptographic key from a user-provided **password and a salt**.
       3. HMAC (Hash-based Message Authentication Code) and SHA-256 (Secure Hash Algorithm 256-bit)
            *  Secure Hashing and Message **Authentication**.
   
3. Multi-threading
    1.**threading**
    2.**queue**

4. File and Directory Management
    1.**os(Operating System)**
    2.**shutil**
    3.**time**

5. Data Handling
    1.**json**
      
6. Password Management
    1.**tkinter.simpledialog**         
          

### **Want to see complete Installization from github ? 👀**

* Visit: [https://itsvj.me/](https://itsvj.me/)
* Or, explore the code on GitHub: [https://github.com/itsvijaysingh/My-Portfolio/](https://github.com/Piyush336/User_Password_protection-at_Rest/tree/main)

## **Why HPJ_CRYP Stands Out**

* **User-Friendly GUI:**  
* **Strong Security Practices:** 
* **Versatility:**
      1. File and Directory Encryption: Supports both single file and entire directory encryption, making it versatile for different user needs.
* **Performance and Usability**
* **Clear and Maintainable Code**

## **Contact**

Feel free to connect with me or leave feedback. I'm always learning and improving! THANKYOU !!

> ~ [pkumar8@gitam.in](mailto:pkumar8@gitam.in)
