import nmap
import subprocess
import smtplib
from email.mime.text import MIMEText
import configparser
import re
import os

config = configparser.ConfigParser()
config.read('config.ini')

# Configure email server
smtp_server = config['Email']['smtp_server']
smtp_port = config['Email'].getint('smtp_port')
email = config['Email']['email']
password = config['Email']['password']

def is_valid_email(email):
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None

def scan_open_ports(host):
    nm = nmap.PortScanner()
    nm.scan(host, '1-1024')
    results = ""
    for host in nm.all_hosts():
        results += f'Host: {host}\n'
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                state = nm[host][proto][port]['state']
                results += f'Port: {port}\tState: {state}\n'
    return results

def scan_outdated_dependencies():
    print("Scanning for outdated dependencies...")
    result = subprocess.run(['safety', 'check'], capture_output=True, text=True)
    return result.stdout

def perform_static_analysis():
    print("Performing static code analysis...")
    result = subprocess.run(['bandit', '-r', '.'], capture_output=True, text=True)
    return result.stdout

def generate_email(subject, body, recipient):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = email
    msg['To'] = recipient

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()  # Upgrade the connection to a secure encrypted SSL/TLS connection
        server.login(email, password)
        server.sendmail(email, recipient, msg.as_string())

if __name__ == '__main__':
    target_host = '127.0.0.1'
    port_results = scan_open_ports(target_host)
    dependency_results = scan_outdated_dependencies()
    analysis_results = perform_static_analysis()
    subject = 'Security Scan Results'
    body = f"Port Scan Results:\n{port_results}\n\nOutdated Dependencies Scan:\n{dependency_results}\n\nStatic Code Analysis:\n{analysis_results}"

    recipient = input("Please enter the recipient's email address: ")
    while not is_valid_email(recipient):
        print("Invalid email address. Please try again.")
        recipient = input("Please enter the recipient's email address: ")

    try:
        generate_email(subject, body, recipient)
        print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")