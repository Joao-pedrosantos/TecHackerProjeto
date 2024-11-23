# app.py
from flask import Flask, render_template, request
import pandas as pd
import re
from urllib.parse import urlparse, parse_qs
import os
import logging
from logging.handlers import RotatingFileHandler
from model_predict import predict_url

app = Flask(__name__)

# Configure logging
log_file = 'access.log'  # Use a local log file
handler = RotatingFileHandler(log_file, maxBytes=1000000, backupCount=1)

# Define log format similar to Apache's Combined Log Format
formatter = logging.Formatter(
    '%(remote_addr)s - - [%(asctime)s] "%(request_line)s" %(status_code)d - "%(referrer)s" "%(user_agent)s"'
)
handler.setFormatter(formatter)
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

def classify_request(row):
    url = row['url']
    return predict_url(url)

def process_logs():
    # Check if the log file exists
    if not os.path.exists(log_file):
        print(f"Log file not found: {log_file}")
        return pd.DataFrame()  # Return an empty DataFrame

    # Regular expression to parse the log
    log_pattern = re.compile(
        r'(?P<ip>\S+) - - \[(?P<time>[^\]]+)\] '
        r'"(?P<request>[^"]*)" (?P<status>\d{3}) - '
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

    # Extract method, URL, and protocol from the request
    df[['method', 'url', 'protocol']] = df['request'].str.split(' ', expand=True, n=2)

    # Handle missing values
    df = df.dropna(subset=['method', 'url', 'protocol'])

    # Count the number of parameters in the URL
    def count_params(url):
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        return len(params)

    df['num_params'] = df['url'].apply(count_params)

    # Classify the requests
    df['classification'] = df.apply(classify_request, axis=1)

    return df

@app.before_request
def log_request_info():
    # Log the request in a format similar to Apache's Combined Log Format
    app.logger.info('', extra={
        'remote_addr': request.remote_addr,
        'request_line': f"{request.method} {request.path} {request.environ.get('SERVER_PROTOCOL')}",
        'status_code': 200,  # Placeholder, will be updated in after_request
        'referrer': request.referrer or '-',
        'user_agent': request.user_agent.string,
    })

@app.after_request
def after_request(response):
    # Update the status code in the log
    app.logger.info('', extra={
        'remote_addr': request.remote_addr,
        'request_line': f"{request.method} {request.path} {request.environ.get('SERVER_PROTOCOL')}",
        'status_code': response.status_code,
        'referrer': request.referrer or '-',
        'user_agent': request.user_agent.string,
    })
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
    selected_columns = ['ip', 'time', 'method', 'url', 'status', 'num_params', 'classification']

    # Generate the HTML table
    data_html = df[selected_columns].to_html(classes='table custom-table', index=False)

    return render_template('metrics.html', tables=[data_html], titles=[''])

if __name__ == '__main__':
    app.run(debug=True)
