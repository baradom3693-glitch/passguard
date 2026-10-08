# 🚀 PassGuard Deployment Guide

This guide covers how to deploy **PassGuard** online for free using **Streamlit Community Cloud** (recommended for Streamlit apps) and **Vercel**.

---

## 🌟 Option 1: Streamlit Community Cloud (Recommended — 1-Click Free Hosting)

Streamlit Community Cloud is the official, free hosting platform built specifically for Streamlit apps.

### Steps:

1. **Initialize Git & Push to GitHub**:
   Open your terminal in `D:\Projects\passguard`:
   ```bash
   cd D:\Projects\passguard
   git init
   git add .
   git commit -m "Initial PassGuard release"
   ```

2. **Create a GitHub Repository**:
   - Go to [GitHub.com](https://github.com/new) and create a new repository named `passguard`.
   - Link and push your code:
     ```bash
     git remote add origin https://github.com/YOUR_USERNAME/passguard.git
     git branch -M main
     git push -u origin main
     ```

3. **Deploy on Streamlit Cloud**:
   - Visit [share.streamlit.io](https://share.streamlit.io/) and log in with GitHub.
   - Click **New app**.
   - Select your Repository (`passguard`), Branch (`main`), and Main file path (`app.py`).
   - Click **Deploy!**
   - Your app will be live at `https://passguard.streamlit.app` within 30 seconds!

---

## ⚡ Option 2: Deploying on Vercel

Vercel is designed primarily for static sites and serverless APIs. Because Streamlit is a long-running Python server app, deploying to Vercel requires hosting via Git integration.

### Steps for Vercel:

1. **Push your code to GitHub** (follow Step 1 & 2 above).
2. **Import to Vercel**:
   - Log in to [Vercel Dashboard](https://vercel.com/dashboard).
   - Click **Add New...** -> **Project**.
   - Import your `passguard` GitHub repository.
   - Leave default settings and click **Deploy**.

---

## ☁️ Option 3: Deploying on Render / Hugging Face Spaces

### Render (Free Web Service):
1. Create account on [Render.com](https://render.com/).
2. Create **New Web Service** connected to your GitHub repo.
3. Environment: `Python 3`
4. Build Command: `pip install -r requirements.txt`
5. Start Command: `streamlit run app.py --server.port $PORT --server.address 0.0.0.0`

### Hugging Face Spaces (Free Streamlit Hosting):
1. Go to [huggingface.co/spaces](https://huggingface.co/spaces).
2. Click **Create new Space**.
3. Select SDK: **Streamlit**.
4. Upload your files (`app.py`, `core/`, `data/`, `requirements.txt`).
5. App builds automatically!
