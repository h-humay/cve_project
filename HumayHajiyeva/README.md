# CVE Lookup Tool 

A web-based tool for searching and retrieving CVE (Common Vulnerabilities and Exposures) information with a beautiful interface.

## Dependencies

1. Python 3.8 or higher
2. Google Chrome browser
3. wkhtmltopdf (for PDF generation)

## Installation Steps

1. Extract the zip file.
HumayHajiyeva.zip
2. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```
3. Install wkhtmltopdf:
   - Windows: Download and install from https://wkhtmltopdf.org/downloads.html
   - macOS: `brew install wkhtmltopdf`
   - Linux: `sudo apt-get install wkhtmltopdf`

## Running the Application
1. Make sure you're in the project directory
2. Run the Flask application:
   ```bash
   python3 app.py
   ```
3. Open your web browser and go to: `http://127.0.0.1:5000`

## Features
- Search for CVE details using CVE ID
- View comprehensive vulnerability information
- Get CVSS scores and vectors
- Access verified references
- Export reports in HTML, PDF, and TXT formats
- Beautiful and user-friendly interface

## Project Structure
- `app.py` - Main Flask application
- `templates/index.html` - Frontend interface
- `requirements.txt` - Python dependencies
- `reports/` - Directory where generated reports are saved (created automatically)

## Troubleshooting
1. If you get ChromeDriver errors:
   - Make sure Google Chrome is installed
   - The webdriver-manager should handle driver installation automatically

2. If PDF generation fails:
   - Verify wkhtmltopdf is properly installed
   - Try running the application with administrator privileges

## Note
The application requires an active internet connection to fetch CVE data from various sources including NIST, Vulners, Vulmon and CVEDetails.com. 