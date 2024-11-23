# app.py
from flask import Flask, render_template, request
import pandas as pd
import re
from urllib.parse import urlparse, parse_qs
import os
import logging
from logging.handlers import RotatingFileHandler
import numpy as np  # Added for statistical calculations

app = Flask(__name__)

# Configure logging
log_file = 'access.log'  # Use a local log file
handler = RotatingFileHandler(log_file, maxBytes=1000000, backupCount=1)

# Define log format to include client details and timestamp
formatter = logging.Formatter(
    '%(remote_addr)s - %(remote_user)s [%(asctime)s] "%(request_line)s" %(status_code)d %(response_length)s "%(referrer)s" "%(user_agent)s"'
)
handler.setFormatter(formatter)
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

def count_params(url):
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    return len(params)

def check_suspicious_patterns(url):
    # Define suspicious patterns
    patterns = [
        r'(\%27)|(\')|(\-\-)|(\%23)|(#)',  # SQL injection patterns
        r'(\%3C)|<.*?>|(\%3E)',            # XSS patterns
        r'script',                         # Script tags
        r'union', r'select', r'insert', r'drop', r'update', r'delete', r'where', r'having',  # SQL keywords
        r'\.\./', r'/etc/passwd', r'/bin/bash',  # Directory traversal
        r'\.\.\\', r'c:\\windows', r'cmd.exe',    # Windows directory traversal
    ]
    # Combine patterns into a single regex
    pattern = re.compile('|'.join(patterns), re.IGNORECASE)
    # Search for patterns in the URL
    if pattern.search(url):
        return 1
    else:
        return 0

def classify_request(row):
    # Rule-based classification
    if row['suspicious_patterns'] == 1:
        return 'Malicious'
    elif row['num_params'] > threshold_num_params:
        return 'Suspicious'
    elif row['status'] in ['400', '401', '403', '404', '500']:
        return 'Error'
    else:
        return 'Normal'

# Define threshold for number of parameters
threshold_num_params = 5

def remove_outliers(df, column, threshold=3):
    mean = df[column].mean()
    std = df[column].std()
    if std == 0:
        return df  # Avoid division by zero if std is zero
    z_scores = (df[column] - mean) / std
    return df[np.abs(z_scores) < threshold]

def process_logs():
    # Check if the log file exists
    if not os.path.exists(log_file):
        print(f"Log file not found: {log_file}")
        return pd.DataFrame()  # Return an empty DataFrame

    # Regular expression to parse the log
    log_pattern = re.compile(
        r'(?P<ip>\S+) - (?P<user>\S+) \[(?P<time>[^\]]+)\] '
        r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\S+) '
        r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
    )

    # List to store parsed entries
    parsed_logs = []

    # Read the log file
    with open(log_file, 'r') as file:
        for line in file:
            match = log_pattern.match(line)
            if match:
                entry = match.groupdict()
                parsed_logs.append(entry)

    if not parsed_logs:
        print("No log entries were parsed.")
        return pd.DataFrame()

    # Convert to pandas DataFrame
    df = pd.DataFrame(parsed_logs)

    # Convert 'size' to integer, treat '-' as 0
    df['size'] = df['size'].replace('-', 0).astype(int)

    # Extract method, URL, and protocol from the request
    df[['method', 'url', 'protocol']] = df['request'].str.split(' ', expand=True, n=2)

    # Handle missing values
    df = df.dropna(subset=['method', 'url', 'protocol'])

    # Count the number of parameters in the URL
    df['num_params'] = df['url'].apply(count_params)

    # Remove outliers in 'size' and 'num_params'
    df = remove_outliers(df, 'size')
    df = remove_outliers(df, 'num_params')

    # Create additional attributes
    df['suspicious_patterns'] = df['url'].apply(check_suspicious_patterns)

    # (Optionally) Create more attributes, e.g., length of URL
    df['url_length'] = df['url'].apply(len)

    # Classify the requests
    df['classification'] = df.apply(classify_request, axis=1)

    return df

@app.before_request
def log_request_info():
    # Get the real IP address if behind a proxy
    if request.headers.getlist("X-Forwarded-For"):
        remote_addr = request.headers.getlist("X-Forwarded-For")[0]
    else:
        remote_addr = request.remote_addr or '-'

    # Prepare log record with request details
    log_params = {
        'remote_addr': remote_addr,
        'remote_user': getattr(request, 'remote_user', '-'),
        'request_line': f"{request.method} {request.full_path} {request.environ.get('SERVER_PROTOCOL')}",
        'status_code': 0,  # Placeholder, will be updated in after_request
        'response_length': 0,  # Placeholder, will be updated in after_request
        'referrer': request.referrer or '-',
        'user_agent': request.user_agent.string or '-',
        # Removed 'asctime' to avoid KeyError
    }
    # Attach log_params to the request context for use in after_request
    request._log_params = log_params

@app.after_request
def after_request(response):
    # Update the status code and response length in the log
    log_params = getattr(request, '_log_params', {})
    log_params['status_code'] = response.status_code
    log_params['response_length'] = response.content_length or 0
    # Log the request
    app.logger.info('', extra=log_params)
    return response

@app.route('/')
def index():
    return 'Welcome to the Cyber Threat Detection System! Access /metrics to view the data.'

@app.route('/metrics')
def metrics():
    # Process the logs
    df = process_logs()

    # Check if the DataFrame is empty
    if df.empty:
        return "No data available to display."

    # Select the columns to display
    selected_columns = ['ip', 'time', 'method', 'url', 'status', 'size', 'num_params', 'suspicious_patterns', 'classification', 'user_agent']

    # Generate the HTML table
    data_html = df[selected_columns].to_html(classes='table custom-table', index=False)

    return render_template('metrics.html', tables=[data_html], titles=[''])

if __name__ == '__main__':
    app.run(debug=True)
