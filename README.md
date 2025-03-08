# MissionCtrl Installation Guide

Welcome to **Mission Ctrl**! This app lets you upload, download, and manage files on the Autonomi Network.

Please note this App is a "learning project" and should be treated as such, only add small amounts of funds to your wallet and expect bugs.

# Setting Up a Python Virtual Environment (venv) on Ubuntu/Linux

## Prerequisites
Ensure you have Python 3 and `pip` installed. Run the following command to install the necessary system packages:

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv python3-tk -y
```

### Why are these needed?
- `python3` → Installs Python
- `python3-pip` → Installs `pip` for package management
- `python3-venv` → Enables virtual environment support
- `python3-tk` → Ensures Tkinter (GUI support) is available

---

## Step 1: Create a Virtual Environment
Navigate to your project directory and create a virtual environment:

```bash
cd /path/to/your/project
python3 -m venv venv
```

---

## Step 2: Activate the Virtual Environment
Run the following command to activate the virtual environment:

```bash
source venv/bin/activate
```

After activation, your terminal prompt should show `(venv)`, indicating the environment is active.

---

## Step 3: Upgrade `pip`
Ensure `pip` is up to date inside the virtual environment:

```bash
pip install -U pip
```

---

## Step 4: Install Required Python Packages
Run the following command to install the necessary dependencies:

```bash
pip install asyncio web3 autonomi-client cryptography pillow
```

> **Note:** Tkinter does **not** need to be installed with `pip` because it comes with Python but requires the system package `python3-tk` (installed in Step 1).

---

## Step 5: Verify Installations
Test if all required packages are correctly installed:

```bash
python -c 'import tkinter; print("Tkinter is installed!")'
python -c 'import web3; print("Web3 is installed!")'
python -c 'import autonomi_client; print("Autonomi Client is installed!")'
python -c 'import cryptography; print("Cryptography is installed!")'
python -c 'import PIL; print("Pillow is installed!")'
```

If each command prints a success message, your environment is correctly set up.

---

## Step 6: Run the Application
Now, start the project:

```bash
python ctrl.py
```

---

## Step 5: Get Started

Here’s a quick rundown to start using the app:

- **Wallet**: You need a wallet to store funds and pay for uploads.
  - First time? The app will guide you to create or import a wallet.
- **Funds**: Add a tiny amount of ETH and ANT tokens to your wallet:
  - Get them from a crypto exchange, community faucet or community member.
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

## Troubleshooting

- **“python: command not found”**: Python isn’t installed or added to PATH. Recheck Step 1.
- **Errors about missing libraries**: Rerun the `pip install` command from Step 3.
- **App doesn’t start**: Ensure you’re in the right folder and typed `python ctrl.py` correctly.
- **Wallet issues**: Save your private key securely—it’s your backup!

---

## Important Notes

- **Funds Safety**: Only send small amounts of ETH and ANT. The app developer isn’t responsible for lost funds.
- **Private Key**: When creating a wallet, save your private key somewhere safe. You’ll lose access to your funds without it.

Enjoy trying Mission Ctrl!
