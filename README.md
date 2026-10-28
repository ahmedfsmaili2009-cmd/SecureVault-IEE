# SecureVault-IEE (Isolated Encrypted Environment)

## Overview & Primary Purpose
SecureVault-IEE is a high-assurance cryptographic storage utility designed to secure, isolate, and manage highly sensitive local directories. It enforces strict access controls through hardware-bound machine identification and authenticated encryption, ensuring that stored assets remain strictly confidential, tamper-proof, and inaccessible to unauthorized entities.

## Project Background
This utility is the practical capstone of my self-directed exploration into applied cryptography, access control architecture, and the CIA triad (Confidentiality, Integrity, Availability). Instead of relying solely on theoretical frameworks, I developed this environment to implement real-world defensive mechanisms against unauthorized local data access and forensic recovery.

To formally document and validate these competencies for university and scholarship evaluations, I completed a targeted documentation sprint. This culminated in passing the final assessments for the Google Cybersecurity Professional Certificate, which directly verifies the security architecture implemented in this repository.

## Core Features
* Authenticated Cryptographic Engine (Confidentiality & Integrity): Utilizes AES-GCM for robust data encryption, paired with Scrypt and HKDF for key derivation, and HMAC to ensure strict file integrity.
* Hardware-Bound Access Control: Implements a dual-layer authentication system requiring both a Master Password and a valid, cryptographically signed Hardware ID (HWID) license, alongside automated idle session timeouts.
* Forensic Data Shredding: Integrates a multi-pass secure wiping algorithm (`secure_wipe_tree`) that overwrites original plaintext files with randomized bytes prior to deletion, neutralizing data recovery attempts.

## Academic Certification
This repository serves as the direct practical implementation of the cybersecurity frameworks verified by:

* Google Cybersecurity Professional Certificate
  Validates applied knowledge of the CIA triad, endpoint access control, and cryptographic data protection mechanisms used throughout this project.
  [View Google Certificate](./Certificates/Google_Cybersecurity_Certificate.pdf)

## Technology Stack
* Language: Python 3
* Security & Cryptography: Cryptography Library (AES-GCM, Scrypt, HKDF, HMAC)
* Interface: CustomTkinter