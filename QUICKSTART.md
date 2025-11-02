# 🚀 Quick Start Guide

Get the Sleep Data Tool running in under 10 minutes!

## Prerequisites Check

- ✅ Python 3.10 or higher installed
- ✅ A Fitbit account with sleep data
- ✅ Internet connection

**Check Python version:**
```bash
python --version
# or
python3 --version
```

## 5-Minute Setup

### 1. Download & Install (2 minutes)

```bash
# Clone or download the repository
git clone https://github.com/apob-100/sleep-data-tool.git
cd fitbit-sleep-tool

# Install dependencies
pip install -r requirements.txt
# or on macOS/Linux:
pip3 install -r requirements.txt
```

### 2. Register Fitbit App (3 minutes)

1. Go to: [dev.fitbit.com/apps](https://dev.fitbit.com/apps)
2. Click **"Register a New App"**
3. Fill in:
   - **Application Name:** My Sleep Tool
   - **OAuth 2.0 Application Type:** `Client` ⚠️ IMPORTANT
   - **Redirect URL:** `http://localhost:8080/` (with trailing slash!)
   - **Default Access Type:** Read Only
4. Click **"Save"**
5. Copy your **Client ID**

### 3. Configure Environment (1 minute)

```bash
# Copy the example file
cp .env.example .env

# Edit .env and add your Client ID
# Replace "your_client_id_here" with your actual Client ID
```

Your `.env` should look like:
```env
FITBIT_CLIENT_ID=23ABCD
FITBIT_REDIRECT_URI=http://localhost:8080/
LOG_LEVEL=INFO
```

### 4. Run! (10 seconds)

```bash
python fitbit_sleep_tool.py
# or
python3 fitbit_sleep_tool.py
```

## First Use

### Authenticate Your Account

1. Click **"Add Account"** button
2. Enter a name (e.g., "MyFitbit")
3. Browser opens → Click **"Allow"** on Fitbit's page
4. Done! Return to the app

### Fetch Your Sleep Data

1. Select your account from dropdown
2. Enter a date: `2025-10-30`
3. Click **"Fetch Data"**
4. View your sleep metrics in the table!

### Export to CSV

1. Click **"Export to CSV"**
2. Choose save location
3. Open with Excel/Sheets

## Troubleshooting

### "pip is not recognized"
**Solution:** Python not in PATH. Reinstall Python and check "Add to PATH"

### Browser doesn't open
**Solution:** Copy the URL from console and paste in browser manually

### "Invalid redirect_uri"
**Solution:** Make sure you used:
- `http://localhost:8080/` (with trailing slash!)
- Same URL in Fitbit app registration AND .env file

### Import errors
**Solution:** Run `pip install -r requirements.txt` again

### Port 8080 in use
**Solution:** 
1. Close other apps using port 8080
2. Or change to 8888 in both Fitbit app and .env

## Common Use Cases

### Daily Sleep Tracking

```
1. Open app
2. Today's date is pre-filled
3. Click "Fetch Data"
4. View your last night's sleep!
```

### Weekly Export

```
1. Fetch data for each day (Monday-Sunday)
2. Click "Export to CSV"
3. Analyze in Excel
```

### Multiple Accounts

```
1. Add Account → "MyAccount"
2. Add Account → "PartnerAccount"
3. Switch between accounts in dropdown
4. Fetch data for each
5. Export shows all accounts
```

## Tips & Tricks

### 💡 Pro Tips

- **Batch dates:** Fetch multiple dates before exporting
- **Account names:** Use descriptive names like "Alice_Fitbit" or "Work_Account"
- **Date format:** Always use YYYY-MM-DD (2025-10-30)
- **Themes:** Try different themes by editing line 1465 in the .py file
- **Debug mode:** Set `LOG_LEVEL=DEBUG` in .env for troubleshooting

### 🎨 Change Theme

Edit `fitbit_sleep_tool.py` line 1465:
```python
themename="darkly"  # Dark theme
themename="flatly"  # Light theme (default)
themename="superhero"  # Comic book style
themename="cyborg"  # Futuristic
```

### 📊 Understanding Sleep Metrics

- **REM:** Rapid Eye Movement sleep (dreaming, memory consolidation)
- **Light:** Transition sleep, easy to wake from
- **Deep:** Restorative sleep, hardest to wake from
- **SOL:** Time it took to fall asleep
- **WASO:** Time awake during the night
- **TIB:** Total time in bed

## Next Steps

✅ **Working?** Great! Check the [README](README.md) for advanced features

❓ **Issues?** See the [Troubleshooting](README.md#troubleshooting) section

🐛 **Found a bug?** [Report it](https://github.com/apob-100/sleep-data-tool/issues)

💡 **Feature idea?** [Suggest it](https://github.com/apob-100/sleep-data-tool/discussions)

⭐ **Like it?** Star the repository!

## Need More Help?

- 📖 [Full README](README.md) - Complete documentation
- 🤝 [Contributing](CONTRIBUTING.md) - Help improve the tool
- 🔐 [Security](README.md#security) - Security best practices
- 💬 [Discussions](https://github.com/apob-100/sleep-data-tool/discussions) - Ask questions

---

**That's it! You're ready to explore your sleep data.** 🌙💤

*Remember: Your data stays private on your computer. We never send it anywhere.*
