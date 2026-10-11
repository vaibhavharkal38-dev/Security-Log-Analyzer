Security Log Analyzer – Mini SOC Dashboard

About the Project

Security Log Analyzer is a Python-based web application built using Flask. It analyzes security log files, detects failed login attempts, identifies suspicious IP addresses, and displays security events through a web dashboard.

This project is developed for learning cybersecurity and basic Security Operations Center (SOC) monitoring concepts.

Features

- Upload and analyze log files.
- Count total log entries and failed login attempts.
- Identify suspicious IP addresses based on repeated failed logins.
- Display security statistics on a dashboard.
- Visualize failed login attempts using Chart.js.
- Monitor newly appended log entries.
- Display live security events and failed-login alerts.

Technologies Used

- Python
- Flask
- HTML
- CSS
- JavaScript
- Chart.js

Project Structure

Security-Log-Analyzer/
├── analyzer/
│   ├── __init__.py
│   ├── log_analyzer.py
│   └── live_monitor.py
├── logs/
│   └── sample.log
├── templates/
│   └── index.html
├── app.py
└── README.md

How to Run

Requirements

- Python
- Flask
- A web browser

Steps

1. Clone or download this repository.

2. Open the project folder in VS Code.

3. Open the terminal.

4. Install Flask if it is not already installed:
   
   pip install flask

5. Start the application:
   
   python app.py

6. Open the following URL in your browser:
   
   "http://127.0.0.1:5000"

Windows Virtual Environment

If you use the project's existing virtual environment, you can run:

.\venv\Scripts\python.exe app.py

How It Works

1. The user selects a log file.
2. The application analyzes log entries.
3. Failed login attempts and suspicious IP addresses are identified using the implemented rules.
4. The dashboard displays statistics and a chart.
5. Live monitoring checks for new log entries.
6. New security events appear in the Live Security Events section.

Testing

The live monitoring feature has been tested using a sample failed-login entry. The dashboard displayed the failed-login status, IP address, timestamp, and alert.

Future Improvements

- Add risk scores and threat-level classification.
- Export reports as CSV files.
- Add filters for event status and IP address.
- Improve support for different log formats.
- Add more security detection rules.

Limitations

This is an educational project that uses basic detection rules. It is not a replacement for an enterprise SIEM or a production security monitoring system.

Author

Vaibhav Harkal

B.Sc. Computer Science Student | Cybersecurity Learner

LinkedIn: "Vaibhav Harkal" (https://linkedin.com/in/vaibhav-harkal)

Disclaimer

For educational and defensive cybersecurity purposes only. Analyze only log files you are authorized to access.