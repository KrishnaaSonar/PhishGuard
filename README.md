# 🛡️ PhishGuard

PhishGuard is a Python-based phishing email detection tool that analyzes email content and identifies possible phishing attempts using keyword analysis, risk scoring, and rule-based threat detection.

The application provides a graphical interface built with CustomTkinter and generates reports for analysis.

---

## ✨ Features

🔍 Email phishing detection

📊 Risk scoring system

🚨 Threat keyword analysis

📝 Detection history tracking

📁 Report generation and export support

🖥️ CustomTkinter GUI interface

📈 Result logging

---

## 📂 Project Structure

```bash
PhishGuard/
│── reports/              # Generated reports
│── detector.py           # Core phishing detection logic
│── export.py             # Export functionality
│── main.py               # Main application entry point
│── results.txt           # Stored scan results
│── rules.py              # Phishing detection rules
│── scoring.py            # Risk scoring system
```

---

## ⚙️ Installation

Clone repository:

```bash
git clone https://github.com/KrishnaaSonar/PhishGuard.git
```

Move into project directory:

```bash
cd PhishGuard
```

Install dependencies:

```bash
pip install customtkinter
```

Run application:

```bash
python main.py
```

---

## 🧠 How It Works

PhishGuard processes email text through multiple stages:

### 1. Email Input

User enters email content into the interface.

### 2. Rule Analysis

The system checks for phishing indicators such as:

- Urgent requests
- Credential stealing attempts
- Suspicious wording
- Fake verification messages
- Financial pressure tactics

### 3. Risk Scoring

Each detected indicator increases threat score.

Risk levels:

| Score | Status |
|--------|--------|
| Low | Safe ✅ |
| Medium | Suspicious ⚠️ |
| High | Phishing 🚨 |

### 4. Result Storage

Results are saved for later review and reporting.

---

## 📌 Example

### Safe Email

Subject:
Meeting Reminder

Message:

Hi Team,

Reminder for tomorrow’s project discussion at 10 AM.

Result:

Safe ✅

---

### Suspicious Email

Subject:
Account Verification Needed

Message:

Please verify your account details soon.

Result:

Suspicious ⚠️

---

### Phishing Email

Subject:
URGENT: Bank Verification

Message:

Your account will be disabled in 24 hours.

Click immediately:

http://verify-bank-login.xyz

Result:

Phishing 🚨

---

## 🛠 Technologies Used

- Python
- CustomTkinter
- Rule-based analysis
- Risk scoring logic
- File handling
- Report generation

---

## 🎯 Use Cases

- Cybersecurity learning
- Phishing awareness
- Academic projects
- Resume projects
- Threat analysis demos
- Email safety experiments

---

## 🚀 Future Improvements

- Machine learning detection
- URL analysis
- Sender reputation checking
- Attachment scanning
- Dashboard analytics
- Browser extension support
- Real-time threat feeds

---

## 👨‍💻 Author
Krishna Sonar

---

## 📜 License

This project is intended for educational and cybersecurity learning purposes.
