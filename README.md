# MissionCtrl Installation Guide

Welcome to **Mission Ctrl**! This app lets you upload, download, and manage files on the Autonomi Network.

Please note this App is a "learning project" and should be treated as such. Only add small amounts of funds to your wallet and expect bugs.

## Cloning the Repository

To get started, clone the repository:

```bash
git clone git@github.com:josh-clsn/MissionCtrl.git
cd MissionCtrl
```

---

# Setting Up a Python Virtual Environment (venv)

## **For Ubuntu/Linux**

### **Prerequisites**
Ensure you have Python 3 and `pip` installed. Run the following command to install the necessary system packages:

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv python3-tk -y
```

### **Step 1: Create a Virtual Environment**
```bash
python3 -m venv venv
```

### **Step 2: Activate the Virtual Environment**
```bash
source venv/bin/activate
```

### **Step 3: Upgrade `pip`**
```bash
pip install -U pip
```

### **Step 4: Install Required Python Packages**
```bash
pip install asyncio web3 autonomi-client cryptography pillow
```

### **Step 5: Run the Application**
```bash
python ctrl.py
```

### **Step 6: Deactivate the Virtual Environment**
```bash
deactivate
```

---

## **For Windows**

### **Prerequisites**
- Download and install **Python** from: [https://www.python.org/downloads/](https://www.python.org/downloads/)
- Ensure "Add Python to PATH" is checked during installation.

### **Step 1: Open Command Prompt (cmd) or PowerShell and run:**

```powershell
python -m venv venv
```

### **Step 2: Activate the Virtual Environment**
```powershell
venv\Scriptsctivate
```

### **Step 3: Upgrade `pip`**
```powershell
pip install -U pip
```

### **Step 4: Install Required Python Packages**
```powershell
pip install asyncio web3 autonomi-client cryptography pillow
```

### **Step 5: Run the Application**
```powershell
python ctrl.py
```

### **Step 6: Deactivate the Virtual Environment**
```powershell
deactivate
```

---

## **For macOS**

### **Prerequisites**
Ensure you have Python 3 and Homebrew installed:

```bash
brew install python3
xcode-select --install  # Ensure Xcode command-line tools are installed
```

### **Step 1: Create a Virtual Environment**
```bash
python3 -m venv venv
```

### **Step 2: Activate the Virtual Environment**
```bash
source venv/bin/activate
```

### **Step 3: Upgrade `pip`**
```bash
pip install -U pip
```

### **Step 4: Install Required Python Packages**
```bash
pip install asyncio web3 autonomi-client cryptography pillow
```

### **Step 5: Run the Application**
```bash
python ctrl.py
```

### **Step 6: Deactivate the Virtual Environment**
```bash
deactivate
```

---

# Get Started

Here’s a quick rundown to start using the app:

- **Wallet**: You need a wallet to store funds and pay for uploads.
  - First time? The app will guide you to create or import a wallet.
- **Funds**: Add a tiny amount of ETH and ANT tokens to your wallet:
  - Get them from a crypto exchange, community faucet, or community member.
  - Send them to the wallet address shown in the "Wallet" tab.
- **Tabs**:
  - **Wallet**: Manage your funds and wallet settings.
  - **Upload**: Send files to the blockchain (Public = anyone can see; Private = encrypted).
  - **Download**: Retrieve files using an address.
  - **Manage Files**: Organize or remove your uploads.

### Quick Start Example
1. Go to the "Wallet" tab, click "Create a New Wallet," and set a password.
2. Send a small amount of ETH and ANT to your wallet address.
3. Go to "Upload," check "Public," and upload a photo.
4. Copy the address shown, then use it in "Download" to get your photo back!

---

# Troubleshooting

- **“python: command not found”**: Python isn’t installed or added to PATH. Recheck Step 1.
- **App doesn’t start**: Ensure you’re in the right folder and typed `python ctrl.py` correctly.
- **Wallet issues**: Save your private key securely—it’s your backup!

---

# Important Notes

- **Funds Safety**: Only send small amounts of ETH and ANT. The app developer isn’t responsible for lost funds.
- **Private Key**: When creating a wallet, save your private key somewhere safe. You’ll lose access to your funds without it.

Enjoy trying **Mission Ctrl**! 🚀
