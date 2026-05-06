```
███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗    ███╗   ██╗██╗██████╗ 
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝    ████╗  ██║██║██╔══██╗
███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗      ██╔██╗ ██║██║██║  ██║
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝      ██║╚██╗██║██║██║  ██║
███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗    ██║ ╚████║██║██████╔╝
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═══╝╚═╝╚═════╝ 

███╗   ███╗ █████╗ ███╗   ██╗ █████╗  ██████╗ ███████╗███╗   ███╗███████╗███╗   ██╗████████╗
████╗ ████║██╔══██╗████╗  ██║██╔══██╗██╔════╝ ██╔════╝████╗ ████║██╔════╝████╗  ██║╚══██╔══╝
██╔████╔██║███████║██╔██╗ ██║███████║██║  ███╗█████╗  ██╔████╔██║█████╗  ██╔██╗ ██║   ██║   
██║╚██╔╝██║██╔══██║██║╚██╗██║██╔══██║██║   ██║██╔══╝  ██║╚██╔╝██║██╔══╝  ██║╚██╗██║   ██║   
██║ ╚═╝ ██║██║  ██║██║ ╚████║██║  ██║╚██████╔╝███████╗██║ ╚═╝ ██║███████╗██║ ╚████║   ██║   
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝
```

A modern and secure **National ID (NID) Management System** built using the **C Programming Language**, **GTK+3 GUI**, **SQLite Database**, **OpenSSL Security**, and **QR Code Verification**.

This project provides a complete desktop-based solution for managing citizen information securely with an attractive graphical interface.

---

## Features

### Core Features
- Secure Admin Login System
- Citizen Registration
- View All Registered Citizens
- Search Citizen by NID
- Update Citizen Information
- Delete Citizen Record
- Audit Log Tracking
- SQLite Database Integration
- Graphical User Interface using GTK+3

---

## Advanced Features

### Security System
- Password hashing using OpenSSL
- PBKDF2 + SHA256 encryption
- Random Salt Generation
- Secure Authentication System

### QR Verification System
- Generate QR Code for each citizen
- Mobile-based verification support
- Instant identity validation

### NID Application Guide
- বাংলা ভাষায় নতুন NID আবেদন নির্দেশিকা
- Required documents information
- Eligibility guidelines
- Citizen support information

---

## Technologies Used

| Technology | Purpose |
|---|---|
| C Programming | Core Development |
| GTK+3 | GUI Development |
| SQLite3 | Database Management |
| OpenSSL | Security & Encryption |
| libqrencode | QR Code Generation |

---

## System Modules

### 1. Authentication Module
Provides secure admin login functionality using encrypted password verification.

### 2. Citizen Management Module
Handles:
- Registration
- Searching
- Updating
- Deleting
- Viewing citizen records

### 3. Database Module
Stores all citizen information securely using SQLite database.

### 4. Audit Log Module
Tracks important activities such as:
- Registration
- Search
- Update
- Delete
- QR Generation

### 5. QR Verification Module
Generates QR codes containing citizen verification data.

---
---

# Data Flow Diagram (DFD)

## Level 0 DFD

```
                    ┌────────────────────────────────┐
                    │                                │
                    │         ADMIN USER             │
                    │        (mdnaim/etc.)           │
                    │                                │
                    └───────┬────────────────▲───────┘
                            │                │
              Login Info    │                │  Login Result
              Citizen Data  │                │  Citizen Info
              NID Request   │                │  QR Code
              CRUD Command  │                │  Audit Logs
                            │                │  Error/Success
                            ▼                │
                ┌───────────────────────────────────┐
                │                                   │
                │            P0                     │
                │   NATIONAL ID MANAGEMENT          │
                │          SYSTEM                   │
                │                                   │
                └───┬──────────┬──────────┬─────────┘
                    │          │          │
          Read/Write│  Read/   │   Write  │
          Citizen   │  Verify  │   Log    │
                    ▼          ▼          ▼
            ┌───────────┐ ┌─────────┐ ┌────────────┐
            │    D1     │ │   D2    │ │    D3      │
            │ CITIZENS  │ │  USERS  │ │ AUDIT_LOGS │
            │    DB     │ │   DB    │ │    DB      │
            └───────────┘ └─────────┘ └────────────┘

                            │
                            │ QR Code Output
                            ▼
                ┌───────────────────────────────┐
                │   MOBILE / VERIFIER           │
                │   (QR Scanner)                │
                └───────────────────────────────┘
```

---

## Level 1 DFD

```text
┌─────────────────┐                                       ┌──────────────────┐
│   ADMIN USER    │                                       │ MOBILE/VERIFIER  │
└────────┬────────┘                                       └────────▲─────────┘
         │                                                         │
         │ username,                                            QR Code
         │ password                                              Image
         ▼                                                         │
┌─────────────────────┐    query user       ┌──────────────────┐   │
│        P1           │────────────────────▶│       D2         │   │
│  USER               │◀────────────────────│     USERS DB     │   │
│  AUTHENTICATION     │  hash, salt         └──────────────────┘   │
└────────┬────────────┘                                            │
         │ login success/fail                                      │
         ▼                                                         │
┌─────────────────────────────────────────────────────────────┐    │
│              ADMIN DASHBOARD (Session)                     │     │ 
└──┬──────────┬──────────┬──────────┬──────────┬─────────────┘     │
   │          │          │          │          │                   │
   │ Register │ Update   │ Delete   │ Search   │ QR Request        │
   │ Data     │ Data     │ NID      │ NID      │ (NID)             │
   ▼          ▼          ▼          ▼          ▼                   │
┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────────────┐     │
│   P2   │ │   P2   │ │   P3   │ │   P4   │ │      P5        │─────┘
│REGISTER│ │ UPDATE │ │ DELETE │ │ SEARCH │ │ QR GENERATION  │
│CITIZEN │ │CITIZEN │ │CITIZEN │ │CITIZEN │ │ & VERIFICATION │
└───┬────┘ └───┬────┘ └───┬────┘ └───┬────┘ └───────┬────────┘
    │INSERT    │UPDATE    │DELETE    │SELECT        │SELECT
    ▼          ▼          ▼          ▼              ▼
┌────────────────────────────────────────────────────────────┐
│                           D1                               │
│                     CITIZENS DB                            │
│ (nid, name, dob, gender, address, father_name,             │
│  mother_name, blood_group, is_active,                      │
│  created_at, last_modified)                                │
└────────────────────────────────────────────────────────────┘
         ▲            ▲           ▲          ▲        ▲
         │            │           │          │        │
         │ citizen    │ updated   │ success  │ citizen│ citizen
         │ saved      │ record    │ deleted  │ record │ record
         │            │           │          │        │
         ▼            ▼           ▼          ▼        ▼
┌────────────────────────────────────────────────────────────┐
│                           ADMIN                            │
│      (Success/Error Messages, Citizen Details)             │
└────────────────────────────────────────────────────────────┘

   Each CRUD/QR process also sends log info ──────┐
                                                  ▼
                                       ┌──────────────────┐
                                       │       P6         │
                                       │ AUDIT LOGGING    │
                                       │ (log_activity)   │
                                       └────────┬─────────┘
                                                │ INSERT
                                                ▼
                                       ┌──────────────────┐
                                       │       D3         │
                                       │  AUDIT_LOGS DB   │
                                       │ (id, nid,        │
                                       │  timestamp,      │
                                       │  activity_type)  │
                                       └──────────────────┘
                                                │
                                                │ View Logs
                                                ▼
                                       ┌──────────────────┐
                                       │       P7         │
                                       │  VIEW AUDIT      │
                                       │     LOGS         │
                                       └────────┬─────────┘
                                                │
                                                ▼
                                             ADMIN
```

---
---

## Database Tables

### citizens
Stores citizen information:
- NID
- Name
- DOB
- Gender
- Address
- Parents Information
- Blood Group
- Status

### users
Stores admin login information securely.

### audit_logs
Stores system activity history.

---

## Installation Requirements

Before running the project, install the following dependencies:

### Ubuntu / Linux Mint

```bash
sudo apt update

sudo apt install gcc gtk+-3.0 libgtk-3-dev sqlite3 libsqlite3-dev libssl-dev libqrencode-dev pkg-config
```

---

## Compile Command

```bash
gcc national_id_gtk.c -o nid_system `pkg-config --cflags --libs gtk+-3.0` -lsqlite3 -lssl -lcrypto -lqrencode
```

---

## Run the Project

```bash
./nid_system
```

---

## Default Admin Credentials

```text
Username: mdnaim
Password: mdnaim2004@
```

---

## GUI Preview

The system includes:
- Professional Login Interface
- Admin Dashboard
- Citizen Management Forms
- Search Window
- QR Verification Window
- Audit Log Viewer

---

## Security Highlights

- Secure Password Storage
- Salted Hash Authentication
- Database Protection
- Audit Logging
- Verification System

---

## Future Improvements

- Face Recognition Integration
- Fingerprint Authentication
- Cloud Database Support
- Multi-Admin System
- Online Verification API
- Smart Card Integration

---

## Project Objectives

The goal of this project is to develop a secure and user-friendly digital identity management system that demonstrates:
- Secure data handling
- Database integration
- GUI application development
- Encryption techniques
- Real-world government system simulation

---

## Author

**Md Naim**  
CSE Undergraduate Student  
Bangladesh

GitHub: `mdnaim2004`

---

## License

This project is developed for educational and academic purposes.

---

## Project Status

Completed with:
- Secure Authentication
- Full CRUD Operations
- QR Verification
- GTK GUI
- Database Integration
- Security Features
