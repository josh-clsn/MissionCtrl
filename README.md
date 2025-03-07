# MissionCtrl Installation Guide

Welcome to **Mission Ctrl**! This app lets you upload, download, and manage files on the Autonomi Network. This guide is designed for beginners—no coding experience needed. Just follow the steps below to get started!

Please note this App is a "learning project" and should be treated as such, only add small amounts of funds to your wallet and expect bugs.

---

## Step 1: Install Python

Mission Ctrl runs on Python, a free programming language. Here’s how to install it:

1. Visit [python.org/downloads](https://www.python.org/downloads/).
2. Download the latest version (e.g., Python 3.11).
3. Run the installer:
   - **Windows**: Check "Add Python to PATH" during installation.
   - **Mac**: Follow the prompts; Python will install to `/usr/local/bin/`.
   - **Linux**: Python is often pre-installed. If not, use your package manager (e.g., `sudo apt install python3` on Ubuntu).
4. Open a terminal:
   - **Windows**: Search for "Command Prompt" in the Start menu.
   - **Mac**: Open "Terminal" from Applications > Utilities.
   - **Linux**: Open your terminal app.
5. Type `python --version` (or `python3 --version` on Mac/Linux). If you see a version number (e.g., `3.11.0`), Python is ready!

---

## Step 2: Download Mission Ctrl

1. Save the Mission Ctrl files to a folder on your computer:
   - `ctrl.py`, `gui.py`, `wallet.py`, `public.py`, `private.py`, `get.py`, `view.py`
   - **Tip**: Create a new folder like `C:\MissionCtrl` (Windows) or `~/MissionCtrl` (Mac/Linux) to keep things organized.
2. Extract them if they’re in a ZIP file.

---

## Step 3: Install Required Libraries

Mission Ctrl needs some extra tools to work. Here’s how to install them:

1. Open your terminal and navigate to your Mission Ctrl folder:
   - **Windows**: `cd C:\MissionCtrl`
   - **Mac/Linux**: `cd ~/MissionCtrl`
2. Run this command: `   pip install web3 cryptography pillow autonomi-client`

---

## Step 4: Start The App

- On Mac/Linux, `python3 ctrl.py`
2. A warning window will appear:
- Read it carefully—it warns about using small amounts of funds for safety.
- Click "OK" to proceed (or "Cancel" to exit).
3. The Mission Ctrl window should open!

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
- **Help**: Click the "Help" button in the app for more tips!

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

Enjoy using Mission Ctrl!
