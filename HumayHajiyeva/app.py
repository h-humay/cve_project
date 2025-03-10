from flask import Flask, render_template, request, jsonify, send_file
from selenium.webdriver import Chrome
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
from time import time
import re
from platform import system
from datetime import datetime
from pdfkit import from_string
from os import makedirs
from os import path as ospath
from requests import Session, head, get, RequestException, Response
from concurrent.futures import ThreadPoolExecutor
from selenium import webdriver
import pdfkit

app = Flask(__name__)

def validate_cve_id(cve_id):
    """Validate CVE ID format and rules"""
    # Convert to uppercase for consistency
    cve_id = cve_id.upper()
    
    # Basic CVE format check
    pattern = r'^CVE-(\d{4})-(\d+)$'
    m = re.match(pattern, cve_id)
    if not m:
        return False, "Invalid format. Expected format: CVE-YYYY-NNNN (NNNN must be 4 or more digits)"
    
    # Extract year and ID
    year = int(m.group(1))
    id_part = m.group(2)
    
    # Check year range (1999 to current year)
    current_year = datetime.now().year
    if year < 1999:
        return False, "Year must be 1999 or later"
    if year > current_year:
        return False, "Year cannot be in the future"
    
    # Check ID length and zeros
    if len(id_part) < 4:
        return False, "ID must be at least 4 digits"
    if all(d == '0' for d in id_part):
        return False, "ID cannot contain all zeros"
    
    return True, "Valid CVE ID"

def get_chrome_driver():
    """Get Chrome WebDriver based on the operating system"""
    options = Options()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--disable-gpu')
    options.add_argument('--disable-extensions')
    options.add_argument('--disable-notifications')
    options.add_argument('--disable-popup-blocking')
    options.add_argument('--log-level=3')  # Only show fatal errors
    
    try:
        driver_path = ChromeDriverManager(
            cache_valid_range=7,
            version="latest",
            log_level=0
        ).install()
        
        service = Service(driver_path)
        
        if system() == 'Windows':
            from subprocess import CREATE_NO_WINDOW
            service.creation_flags = CREATE_NO_WINDOW
            
        return Chrome(service=service, options=options)
            
    except Exception:
        try:
            service = Service()
            return Chrome(service=service, options=options)
        except Exception:
            raise Exception("Could not initialize ChromeDriver. Please ensure Chrome is installed and up to date.")

def verify_link(url):
    """Verify if a link is accessible with improved error handling"""
    try:
        session = Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        try:
            response = session.head(url, timeout=2, allow_redirects=True)
            if response.status_code in [200, 301, 302, 307, 308]:
                return url
                
            response = session.get(url, timeout=2, allow_redirects=True, stream=True)
            response.close()
            
            return url if response.status_code in [200, 301, 302, 307, 308] else None
            
        finally:
            session.close()
            
    except (RequestException, Exception):
        return None

def fetch_exploit_table(cve_id):
    """
    Use Selenium to fetch the HTML table of exploits from Exploit‑DB for the given CVE.
    Returns the table's outer HTML or None if not found.
    """
    driver = get_chrome_driver()
    try:
        driver.get(f'https://www.exploit-db.com/search?cve={cve_id}')
        WebDriverWait(driver, 5).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, '#exploits-table tbody tr'))
        )
        table_element = driver.find_element(By.ID, 'exploits-table')
        table_html = table_element.get_attribute('outerHTML')
    except Exception as e:
        table_html = None
    finally:
        driver.quit()
    return table_html

def get_unified_cve_data(cve_id):
    """Get CVE data from NIST and Vulmon, and concurrently fetch Exploit DB data."""
    start_time = time()  # Start the timer
    cve_id = cve_id.upper()
    cve_data = {
        'id': cve_id,
        'description': 'Description not available',
        'cvss_score': 'No CVSS score found.',
        'published_date': '',
        'updated_date': '',
        'references': [],
        'severity': 'unknown',
        'source': 'Unknown',
        'vector': 'No vector information available',
        'category': 'No category found',  # Added category field
        'error': None
    }
    
    print("Starting exploit table fetch concurrently...")
    with ThreadPoolExecutor(max_workers=2) as executor:
        exploit_future = executor.submit(fetch_exploit_table, cve_id)
        
        driver = get_chrome_driver()
        try:
            nist_url = f'https://nvd.nist.gov/vuln/detail/{cve_id}'
            print(f"Accessing NIST URL: {nist_url}")
            driver.get(nist_url)
            
            print("Waiting for NIST page to load...")
            WebDriverWait(driver, 5).until(
                EC.presence_of_element_located((By.TAG_NAME, 'body'))
            )
            print("NIST page loaded.")
            
            if any([
                "CVE ID Not Found" in driver.page_source,
                "This vulnerability does not exist" in driver.page_source,
                "Unable to find" in driver.page_source
            ]):
                print(f"{cve_id} not found in NVD.")
                cve_data['error'] = f"{cve_id} does not exist in the NVD database."
                return cve_data

            soup = BeautifulSoup(driver.page_source, 'html.parser')
            description = soup.find('div', {'data-testid': 'vuln-analysis-description'}) or \
                          soup.find('p', {'data-testid': 'vuln-description'})
            
            if description:
                desc_text = description.get_text(strip=True)
                if 'Product:' in desc_text:
                    desc_text = desc_text.split('Product:')[0]
                cve_data['description'] = desc_text.strip()
                
                source_element = soup.find('span', {'data-testid': 'vuln-current-description-source'})
                if source_element:
                    cve_data['source'] = source_element.get_text(strip=True)

            print("Waiting for CVSS element...")
            try:
                cvss_element = WebDriverWait(driver, 3).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, 
                        '[data-testid="vuln-cvss3-panel-score"], [data-testid="vuln-cvss3-panel-score-na"]'
                    ))
                )
                print("CVSS element found.")
                cve_data['cvss_score'] = cvss_element.text
            except Exception as e:
                print(f"Error fetching CVSS score: {e}")

            try:
                vector_element = driver.find_element(By.CSS_SELECTOR, 'span[data-testid="vuln-cvss3-nist-vector"]')
                if vector_element:
                    cve_data['vector'] = vector_element.text.strip()
            except Exception:
                pass

            score_text = cve_data['cvss_score'].upper()
            if "CRITICAL" in score_text:
                cve_data['severity'] = 'critical'
            elif "HIGH" in score_text:
                cve_data['severity'] = 'high'
            elif "MEDIUM" in score_text:
                cve_data['severity'] = 'medium'
            elif "LOW" in score_text:
                cve_data['severity'] = 'low'

            print("Waiting for references container...")
            try:
                refs_container = WebDriverWait(driver, 3).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, '[data-testid="vuln-hyperlinks-table"]'))
                )
                print("References container found.")
                refs = refs_container.find_elements(By.TAG_NAME, 'a')
                all_refs = [ref.get_attribute('href') for ref in refs 
                            if ref.get_attribute('href') and not ref.get_attribute('href').startswith('javascript:')]
            except Exception as e:
                print(f"Error fetching references: {e}")
                all_refs = []

            all_refs = list(set(all_refs))
            print(len(all_refs))
            verified_refs = []
            max_links = 5

            with ThreadPoolExecutor(max_workers=10) as ref_executor:
                future_to_url = {ref_executor.submit(head, url, timeout=3): url for url in all_refs}

                for future in future_to_url:
                    try:
                        result = future.result()
                        if isinstance(result, Response):
                            verified_refs.append(future_to_url[future])
                        if len(verified_refs) >= max_links:
                            break
                    except RequestException as e:
                        print(f"Error verifying link: {future_to_url[future]} - {e}")
                        continue
            cve_data['references'] = verified_refs

            try:
                print("Accessing CVE Details URL for date and category information...")
                cvedetails_url = f'https://www.cvedetails.com/cve/{cve_id}/'
                driver.get(cvedetails_url)

                print("Waiting for CVE Details page to load...")
                WebDriverWait(driver, 5).until(
                    EC.presence_of_element_located((By.CLASS_NAME, 'd-inline-block'))
                )
                print("CVE Details page loaded.")

                soup = BeautifulSoup(driver.page_source, 'html.parser')
                date_elements = soup.find_all(class_='d-inline-block')

                if len(date_elements) >= 3:
                    cve_data['published_date'] = extract_datetime(date_elements[1].get_text(strip=True))
                    cve_data['updated_date'] = extract_datetime(date_elements[2].get_text(strip=True))
                else:
                    print(f"Not enough date elements found. Found {len(date_elements)} elements.")
                    cve_data['published_date'] = date_elements[1].get_text(strip=True) if len(date_elements) >= 2 else "Not available"
                    cve_data['updated_date'] = "Not available"
                
                category_element = soup.find(class_='ssc-vuln-cat')
                if category_element:
                    cve_data['category'] = category_element.get_text(strip=True)
                else:
                    cve_data['category'] = 'Not available'

            except Exception as e:
                print(f"Error fetching dates and category from CVE Details: {e}")
                cve_data['published_date'] = "Not available"
                cve_data['updated_date'] = "Not available"
                cve_data['category'] = 'Not available'

        except Exception as e:
            cve_data['error'] = f"Error processing {cve_id}: {e}"
            return cve_data

        finally:
            try:
                driver.quit()
            except Exception as e:
                print(f"Error closing driver: {e}")

        print("Waiting for the exploit table to be fetched...")
        try:
            exploit_table = exploit_future.result(timeout=5)
            exploit_table_n = re.sub(r'href="', r'target="_blank" href="https://exploit-db.com', exploit_table)
            exploit_table_n = re.sub(r'<i class="mdi mdi-check mdi-18px" style="color: #96b365"></i>', r'✔', exploit_table_n)
            exploit_table_n = re.sub(r'<i class="mdi mdi-close mdi-18px" style="color: #ec5e10"></i>', r'❌', exploit_table_n)
            exploit_table_n = re.sub(r'<i class="mdi mdi-download mdi-18px" style="color: #132f50"></i>', r'💾', exploit_table_n)
            print("Exploit table fetched.")
            cve_data['exploit_table'] = exploit_table_n if exploit_table_n else "<p>No exploit data available.</p>"
        except Exception as e:
            print(f"Error fetching exploit table: {e}")
            cve_data['exploit_table'] = "<p>No exploit data available.</p>"

    execution_time = time() - start_time
    print(f"Execution time: {execution_time:.6f} seconds")

    return cve_data

def html_table_to_text(html):
    soup = BeautifulSoup(html, 'html.parser')
    table = soup.find('table')
    text_rows = []
    for row in table.find_all('tr'):
        cols = row.find_all(['td', 'th'])
        cols = [col.get_text(strip=True) for col in cols]
        text_rows.append(' | '.join(cols))
    return '\n'.join(text_rows)

def extract_datetime(text):
    m = re.search(r'(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})', text)
    return f"{m.group(1)} | {m.group(2)}" if m else "Not available"

def generate_html_report(cve_data):
    severity_colors = {
        'critical': '#FF0000',
        'high': '#FF4500',
        'medium': '#FFA500',
        'low': '#008000',
        'unknown': '#808080'
    }
    
    severity = cve_data.get('severity', 'unknown')
    color = severity_colors.get(severity, '#808080')
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>CVE Report - {cve_data['id']}</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                margin: 40px;
                background-color: #f5f5f5;
            }}
            .container {{
                background-color: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            .header {{
                text-align: center;
                margin-bottom: 30px;
            }}
            .cve-id {{
                font-size: 24px;
                color: #333;
            }}
            .severity {{
                display: inline-block;
                padding: 5px 10px;
                border-radius: 4px;
                color: white;
                background-color: {color};
                margin: 10px 0;
            }}
            .section {{
                margin: 20px 0;
                padding: 15px;
                background-color: #f8f9fa;
                border-radius: 4px;
            }}
            .section-title {{
                color: var(--primary-color);
                font-weight: 600;
                margin-bottom: 0.5rem;
                padding: 10px 20px;
                border-radius: 15px;
                border: px solid #ccc;
                box-shadow: 2px 2px 10px rgb(0 0 0 / 5%);
                background-color: #fefefe;
            }}
            .reference-link {{
                color: #0066cc;
                text-decoration: none;
            }}
            .reference-link:hover {{
                text-decoration: underline;
            }}
            .date-info {{
                color: #666;
                font-style: italic;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1 class="cve-id">{cve_data['id']}</h1>
                <div class="severity">{severity.upper()}</div>
            </div>
            
            <div class="section">
                <h2 class="section-title">Description</h2>
                <p>{cve_data['description']}</p>
                <p style="color: #666; font-style: italic; margin-top: 10px;">Source: {cve_data.get('source', 'Unknown')}</p>
            </div>
            
            <div class="section">
                <h2 class="section-title">CVSS Score</h2>
                <p>{cve_data['cvss_score']}</p>
                <p style="font-family: monospace;">Vector: {cve_data['vector']}</p>
            </div>
            
            <div class="section">
                <h2 class="section-title">Dates</h2>
                <p class="date-info">Published: {cve_data['published_date']}</p>
                <p class="date-info">Updated: {cve_data['updated_date']}</p>
            </div>

            <div class="section">
                <h3 class="section-title">Vulnerability Category</h3>
                <p><strong>Category:</strong> <span id="cve-cat">{cve_data['category']}</span></p>
            </div>
            
            <div class="section">
                <h2 class="section-title">References</h2>
                <ul>
                    {''.join(f'<li><a class="reference-link" href="{ref}" target="_blank">{ref}</a></li>' for ref in cve_data['references'])}
                </ul>
            </div>
            
            <div class="section">
                <h2 class="section-title">Exploit DB Results</h2>
                {cve_data.get('exploit_table', '<p>No exploit data available.</p>')}
            </div>
            
            <div class="section">
                <p style="text-align: center; color: #666;">
                    Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </p>
            </div>
        </div>
    </body>
    </html>
    """
    return html_content

def generate_text_report(cve_data):
    text_content = f"""
CVE REPORT - {cve_data['id']}
{'=' * 50}

SEVERITY: {cve_data.get('severity', 'unknown').upper()}

DESCRIPTION:
{cve_data['description']}

Source: {cve_data.get('source', 'Unknown')}

CVSS SCORE:
{cve_data['cvss_score']}
Vector: {cve_data['vector']}

DATES:
Published: {cve_data['published_date']}
Updated: {cve_data['updated_date']}

REFERENCES:
{chr(10).join(f"{ref}" for ref in cve_data['references']) if cve_data['references'] else "No references available"}

EXPLOIT DB RESULTS:
{html_table_to_text(cve_data["exploit_table"])}

Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    return text_content

def save_report(cve_data, format='html'):
    if not ospath.exists('reports'):
        makedirs('reports')
        
    base_filename = f"reports/{cve_data['id']}"
    
    if format == 'html':
        filename = f"{base_filename}.html"
        html_content = generate_html_report(cve_data)
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return filename
    
    elif format == 'pdf':
        filename = f"{base_filename}.pdf"
        html_content = generate_html_report(cve_data)
        html_content = re.sub(r'💾', 'save', html_content)
        html_content = re.sub(r'❌', 'no', html_content)
        html_content = re.sub(r'✔', 'yes', html_content)
        try:
            from_string(html_content, filename)
            return filename
        except Exception:
            return None
    
    elif format == 'txt':
        filename = f"{base_filename}.txt"
        text_content = generate_text_report(cve_data)
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(text_content)
        return filename
    
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search', methods=['POST'])
def search():
    cve_id = request.form.get('cve_id', '').strip()
    is_valid, message = validate_cve_id(cve_id)
    if not is_valid:
        return jsonify({'error': message})
    
    try:
        cve_data = get_unified_cve_data(cve_id)
        if cve_data.get('error'):
            return jsonify({'error': cve_data['error']})
        return jsonify(cve_data)
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/save_report', methods=['POST'])
def save_report_route():
    try:
        cve_data = request.get_json()
        format = request.args.get('format', 'html')
        if not cve_data:
            return jsonify({'error': 'No CVE data provided'}), 400
            
        filename = save_report(cve_data, format)
        if filename:
            return jsonify({
                'success': True,
                'message': f'Report saved successfully as {filename}',
                'filename': filename
            })
        else:
            return jsonify({'error': 'Failed to save report'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download_report/<path:filename>')
def download_report(filename):
    try:
        return send_file(filename, as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 404

if __name__ == '__main__':
    app.run(debug=True)
