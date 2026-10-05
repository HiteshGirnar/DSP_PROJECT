# 🏥 Healthcare IoT Security Checker — Complete Project

### A tool that pretends to be a hospital's network of smart medical devices, then hunts for hackers and privacy leaks inside it — so real hospitals don't have to find out the hard way.

**You do not need to know anything about cybersecurity, AI, or coding to use this.**
Follow the steps below in order and you'll have a working dashboard in your browser.

---

## 🤔 What even is this? (Explain-it-like-I'm-new)

Imagine a hospital ward full of smart medical gadgets:
- A wearable that watches a patient's heart rate
- A pump that automatically drips medicine into a patient's arm
- A glucose sensor that tracks blood sugar
- A thermometer, a blood-pressure cuff, and so on

All of these gadgets constantly send little messages back to the hospital's
computers — "heart rate 78," "temperature 37.1°C," and so on. That's
convenient... but it's also a target. If a hacker can trick one of these
devices, they could:

- **Feed the hospital fake readings** (so a doctor makes the wrong call),
- **Break into the pump and change a medicine dose**,
- **Flood the network with junk traffic** so real alerts get lost,
- Or just quietly **figure out which patient is which**, even if the hospital
  thought the data was "anonymous."

Testing this on a *real* hospital with *real* patients would be reckless and
illegal. So this project builds a **fake (synthetic) hospital network** —
same kind of devices, same kind of data, zero real patients — and then:

1. **Plants a bunch of realistic "attacks"** inside the fake data on purpose
   (so we know exactly what a real attack would look like),
2. **Builds a detector** (part simple rules, part AI) that tries to catch
   those attacks just by looking at the data,
3. **Checks whether patients could be identified** even from data that looks
   harmless (like "which ward, which device, what time"),
4. Wraps all of it in a **point-and-click dashboard** so you can see the
   results without reading a single line of code.

### 💡 Why should you care?

Because this is exactly the kind of exercise real hospitals, device makers,
and security teams run before they trust an IoT device near a patient. The
dashboard below will show you, in plain numbers:

- **How good is a simple rule-based alarm system** at catching known attacks?
  *(Spoiler: very good — it catches ~92% of them with zero false alarms.)*
- **How good is "AI" (machine learning) alone** at catching attacks it wasn't
  specifically told about?
  *(Spoiler: worse on its own, but valuable for catching brand-new attacks
  nobody wrote a rule for yet.)*
- **Can a patient be re-identified from "harmless" hospital metadata** like
  their ward and the time of day, even without a name attached?
  *(Spoiler: yes — every single group we checked was in the "risky" zone.)*

That last finding is the kind of thing a hospital's privacy officer would
want to know *before* a real incident, not after.

---

## 🗺️ What you'll actually see

Once it's running, you get a website (only visible on your own computer)
with 5 tabs:

| Tab | In plain English |
|---|---|
| 📊 **Overview** | The "at a glance" numbers — how many devices, how many fake attacks we planted, how many the system caught. |
| 🛡️ **Threat Detection** | A scoreboard comparing "simple rules" vs. "AI" at catching attacks, plus a searchable list of every suspicious event. |
| 🔐 **Privacy Risk** | Shows how easily a patient could be identified from data that looks anonymous. |
| 📋 **Risk Register & Recommendations** | A plain checklist of the biggest risks, ranked, and what to actually do about each one. |
| 📥 **Downloads & Diagrams** | Grab any table as a spreadsheet, the security diagrams, or the full written report. |

You don't need to understand every number on day one — just play with the
sliders in the sidebar and watch the numbers react. That's the point.

---

## 📁 What's in this folder (you can ignore this section if you just want to run it)

```
healthcare-iot-security/
├── README.md                  <- you are here
├── requirements.txt            <- list of Python add-ons needed
├── package.json                <- list of Node add-ons needed (optional report step)
│
├── core/                       <- the "brains": data-faking, detection, privacy logic
├── scripts/                    <- run-from-terminal versions of the same brains
├── app/streamlit_app.py        <- ⭐ the dashboard you'll actually open in a browser
│
├── data/                        <- the fake hospital data lands here once generated
├── diagrams/                    <- ready-made security diagrams (open with diagrams.net)
└── outputs/                     <- result spreadsheets, charts, and the Word report
```

---

## ✅ Before You Start — What You Need Installed

You only need **one** thing installed on your computer to begin: **Python**.

- **Check if you already have it:** open a terminal (Mac: "Terminal" app,
  Windows: "PowerShell" or "Command Prompt", search for it in your Start
  menu) and type:
  ```bash
  python3 --version
  ```
  (On Windows, try `python --version` if the above doesn't work.)
  If you see something like `Python 3.11.4`, you're good — skip ahead to Step 1.

- **If you don't have it:** download and install Python from
  [python.org/downloads](https://www.python.org/downloads/) (any version
  3.10 or newer). During installation on Windows, make sure to check the box
  that says **"Add Python to PATH."**

*Node.js is only needed for one optional step (building the polished Word
report) — you can skip it entirely and everything else still works. Get it
at [nodejs.org](https://nodejs.org/) if you want that step.*

---

## 🚀 Step-by-Step: From Zero to Running Dashboard

Every command below goes into your terminal, one line at a time, in order.
Don't worry about understanding each one — just copy, paste, press Enter,
and read what it prints.

### Step 1 — Open a terminal inside the project folder

Unzip the project, then navigate into it:

```bash
cd healthcare-iot-security
```

*(If you're not sure how to "cd" into a folder: on Mac/Linux you can often
just type `cd ` and then drag the folder from Finder into the terminal
window. On Windows, right-click the folder while holding Shift and choose
"Open PowerShell window here.")*

### Step 2 — Create a private Python workspace ("virtual environment")

This keeps everything this project needs separate from anything else on
your computer — think of it as giving this project its own clean toolbox.

**Mac / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows (PowerShell):**
```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

**Windows (Command Prompt):**
```cmd
python -m venv venv
venv\Scripts\activate.bat
```

✅ **How do you know it worked?** Your terminal prompt should now start with
`(venv)`. If you ever close and reopen your terminal, just run the
"activate" line again before continuing.

### Step 3 — Install the tools this project needs

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

This downloads and installs pandas, numpy, scikit-learn, matplotlib,
Streamlit, and Plotly — all the libraries the project is built on. This can
take a minute or two. You'll see a lot of text scroll by; that's normal.

### Step 4 — Create the fake hospital data

```bash
cd scripts
python generate_data.py
```

You should see something like:
```
Generated telemetry rows: 20872
Label distribution:
 threat_name
normal                     20568
brute_force_auth             116
denial_of_service_burst       86
...
Saved to ../data/healthcare_iot_telemetry.csv and ../data/device_inventory.csv
```
This just means: "I created a fake hospital network with ~21,000 readings
and hid some attacks inside it." Nothing to worry about — this is exactly
what's supposed to happen.

### Step 5 — Run the attack detector

```bash
python analysis.py
```

This makes the detector go through all that fake data and try to catch the
hidden attacks. It'll print a scoreboard and save some charts.

### Step 6 — Run the privacy check

```bash
python privacy_analysis.py
```

This checks how easily a "patient" in the fake data could be identified,
even without their name attached.

### Step 7 (Optional) — Build the polished Word report

Skip this if you don't have Node.js, or don't need a Word document.

```bash
cd ..
npm install
node scripts/build_report.js
```

### Step 8 — Launch the dashboard! 🎉

Make sure you're back in the main project folder (not inside `scripts`),
then run:

```bash
streamlit run app/streamlit_app.py
```

A browser tab should open automatically at `http://localhost:8501`. If it
doesn't open by itself, copy that address into your browser manually.

**That's it — you now have a working, interactive security dashboard.**

---

## 🕹️ How to Actually Use the Dashboard (No Jargon)

1. On the **left sidebar**, pick a data source: generate a fresh fake
   hospital with the sliders, **upload your own CSV file** (click "Browse
   files" under "Upload my own CSV file" — there's a sample template you
   can download first to see the exact format expected), or load the file
   you already created with `generate_data.py`. Then click
   **"🚀 Generate & Run Analysis"** to see the numbers on the right update.
2. Click through the **5 tabs at the top** of the main area. Each one is
   described in the table earlier in this README.
3. In the **Threat Detection** tab, try the filter boxes above the table to
   only show, say, `brute_force_auth` events, or only events from
   `smart_infusion_pump` devices.
4. In the **Downloads & Diagrams** tab, click any button to save that
   table, diagram, or the report to your own computer.
5. There's no way to "break" anything — every button either shows you data
   or downloads a file. Feel free to click around.

---

## 🔁 Quick Reference — All Commands, No Explanations

```bash
cd healthcare-iot-security
python3 -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\Activate.ps1
pip install -r requirements.txt
cd scripts
python generate_data.py
python analysis.py
python privacy_analysis.py
cd ..
npm install && node scripts/build_report.js            # optional
streamlit run app/streamlit_app.py
```

---

## 🧯 Something Went Wrong? Troubleshooting

| What you see | What it means / what to do |
|---|---|
| `ModuleNotFoundError: No module named 'streamlit'` | Your venv isn't active, or Step 3 didn't finish. Re-run Step 2's "activate" line, then Step 3. |
| `streamlit: command not found` | Same as above — activate the venv first. |
| App says "No existing CSV found in /data" | Run Step 4 (`python generate_data.py`) first, or in the sidebar switch to "Generate new synthetic data" instead of "Load existing CSV." |
| "Missing required column(s)..." when uploading | Your CSV needs specific column names. Download the sample CSV from the sidebar (appears when you select "Upload my own CSV file") to see the exact columns and format expected. |
| Downloads tab says "report not found" | You skipped the optional Step 7. Either run it, or just ignore that one download button — everything else still works. |
| `python3: command not found` | Python isn't installed, or isn't on your PATH. Reinstall from python.org and check the "Add to PATH" box. |
| A browser tab doesn't open automatically | Copy `http://localhost:8501` into your browser's address bar manually. |
| Port 8501 already in use | Someone/something else is using that port. Run `streamlit run app/streamlit_app.py --server.port 8502` instead. |
| The numbers change every time I click "Generate" | That's expected if you also change the random seed or sliders — it's making a *new* fake hospital each time. Keep the seed the same to reproduce the same data. |

---

## 🧠 The Headline Results (So You Know What "Good" Looks Like)

| Question | Answer this project found |
|---|---|
| Can simple rules catch known attacks? | Yes — ~92% caught, with **zero** false alarms. |
| Can AI alone catch attacks with no rule written for them? | Partially — much lower accuracy alone, but valuable as a backup net for brand-new attack types. |
| Can a patient be re-identified from "anonymous" hospital metadata? | **Yes, essentially always** in this simulation — every group checked fell into the risky zone. This is the project's most important finding. |

---

## 📜 A Note on the Data

Everything here — every "patient," every device reading, every attack — is
**fabricated by this project's code**. No real patient, hospital, or device
was involved in creating this data or this project. It's a safe sandbox
for learning what a real assessment would look like.
