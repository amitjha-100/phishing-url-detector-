# Upload This Project to GitHub

## Option 1: Upload in the Browser

1. Go to <https://github.com/new>.
2. Repository name: `phishing-url-detector`.
3. Description: `Offline phishing URL risk analyzer with explainable scoring.`
4. Choose Public or Private.
5. Do not add a README, license, or gitignore because this project already has them.
6. Click **Create repository**.
7. Click **uploading an existing file**.
8. Drag all files from this folder into GitHub:
   - `phishing_detector.py`
   - `README.md`
   - `sample_urls.txt`
   - `test_phishing_detector.py`
   - `.gitignore`
   - `LICENSE`
9. Commit the upload with this message:

```text
Initial phishing URL detector project
```

## Option 2: Use Git Later

If Git is installed later, run these commands inside the project folder:

```powershell
git init
git add .
git commit -m "Initial phishing URL detector project"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/phishing-url-detector.git
git push -u origin main
```
