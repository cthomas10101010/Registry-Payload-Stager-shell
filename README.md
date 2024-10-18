# Registry-Payload-Stager

## **Introduction**

Welcome to the **Registry-Payload-Stager** project! This repository demonstrates a technique for staging and executing payloads by leveraging the Windows Registry. Instead of embedding the payload directly within malware, this approach stores the payload as a registry key value, allowing the malware to fetch and execute it at runtime. This method helps evade detection by traditional security solutions that scan malware binaries for embedded payloads.

## **Table of Contents**
- [Introduction](#introduction)
- [Features](#features)
- [How It Works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## **Features**
- **Encrypted Payload Storage:** Securely stores encrypted payloads in the Windows Registry.
- **Runtime Payload Retrieval:** Fetches, decrypts, and executes the payload from the Registry during runtime.
- **Reverse Shell Execution:** Executes shellcode that establishes a reverse shell connection back to a Command and Control (C&C) server.
- **Modular Design:** Code is organized into writing and reading payload segments for clarity and maintainability.
- **Evades Basic Scanning:** By avoiding direct embedding of payloads, it reduces the likelihood of detection by simple malware scanners.

## **How It Works**

1. **Writing the Payload:**
   - The first part of the code encrypts the shellcode containing a reverse shell and writes it to a specific Windows Registry key.
   
2. **Reading and Executing the Payload:**
   - The second part reads the encrypted payload from the Registry, decrypts it, and executes the shellcode, establishing a connection back to the C&C server.

> **Note:** This project focuses on demonstrating the payload staging technique. The encryption and decryption mechanisms are referenced from prior modules and are not detailed here.

## **Prerequisites**

- **Operating System:** Windows 10 or later
- **Development Environment:** Microsoft Visual Studio or any compatible C/C++ compiler
- **Permissions:** Administrative privileges may be required to modify certain Registry keys.
