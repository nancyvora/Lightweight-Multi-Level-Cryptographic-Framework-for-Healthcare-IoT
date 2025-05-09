# Lightweight-Multi-Level-Cryptographic-Framework-for-Healthcare-IoT
A lightweight cryptographic framework for Healthcare IoT using PRESENT and ASCON-128 encryption, dynamic key management, and CP-ABE for access control. Designed for resource-constrained devices, it ensures secure, efficient, and regulation-compliant medical data transmission.

This project presents a lightweight, multi-layered cryptographic framework designed to secure sensitive medical data in resource-constrained Healthcare IoT (H-IoT) environments. By integrating ultra-efficient encryption algorithms, dynamic key management, and fine-grained access control, the system ensures data confidentiality, integrity, and availability without compromising performance.

# Key Features
Multi-Layered Encryption: Combines the PRESENT cipher for baseline confidentiality with ASCON-128 for authenticated encryption, providing robust defense against various attack vectors.

Dynamic Key Management: Implements a LEAIoT-inspired key generation mechanism with periodic rotation, enhancing security through ephemeral session keys.

Attribute-Based Access Control: Utilizes Ciphertext-Policy Attribute-Based Encryption (CP-ABE) to enforce role and department-based access policies, ensuring that only authorized personnel can decrypt sensitive data.

Lightweight Authentication: Employs a hybrid JWT-SHA3 approach for efficient and secure user authentication, suitable for constrained IoT devices.

Optimized for H-IoT Constraints: Designed to operate within the stringent resource limitations of medical IoT devices, ensuring low computational overhead and minimal energy consumption.

# Security Highlights
Confidentiality & Integrity: Ensures that sensitive medical data remains confidential and unaltered during transmission and storage.

Resistance to Common Attacks: Provides robust protection against data breaches, replay attacks, and privilege escalation through layered encryption and strict access controls.

Regulatory Compliance: Aligns with healthcare data protection regulations such as HIPAA and GDPR, facilitating secure and compliant data handling.

# Performance Metrics
Encryption/Decryption Latency: Achieves encryption latency below 1ms and authentication delays under 10ms, meeting real-time performance demands.

Resource Utilization: Operates efficiently within devices having <4KB RAM and <64KB flash memory, ensuring compatibility with a wide range of medical IoT devices.

Energy Efficiency: Maintains low energy consumption, preserving battery life in wearable and implantable medical devices.

# Core Cryptographic Components 
PRESENT Cipher
ASCON Cipher
Key Management System : LEAloT-Inspired Key Generation, Elliptic Curve Cryptography (ECC).
Role-Based Encryption
Token-Based Authentication: JWT-SHA-3
