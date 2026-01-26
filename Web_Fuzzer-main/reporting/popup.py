
import webbrowser
import os
from config import Colors

def show_results_popup(report_file):
    try:
        # Check if file exists
        if os.path.exists(report_file):
            Colors.info("Opening scan report in default browser...")
            webbrowser.open('file://' + os.path.realpath(report_file))
        else:
            Colors.error(f"Report file not found: {report_file}")
    except Exception as e:
        Colors.error(f"Failed to open report: {e}")
