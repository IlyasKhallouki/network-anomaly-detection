import logging
import os
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class Logger:
    def __init__(self, log_dir='/tmp/anwork/logs', general_log_name='general.log', alert_log_name='alerts.log'):
        """
        Initialize the Logger class, set up log directory and file handlers.
        """
        # Define the log directory and ensure it exists
        self.log_dir = log_dir
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

        # Set up the general logger
        self.general_logger = self.setup_logger(general_log_name)

        # Set up the alert logger
        self.alert_logger = self.setup_alert_logger(alert_log_name)

    def setup_logger(self, log_file):
        """
        Setup the logger with a specified log file.
        """
        logger = logging.getLogger(log_file)
        logger.setLevel(logging.DEBUG)
        
        # Define log file path
        log_path = os.path.join(self.log_dir, log_file)
        
        # Create file handler for writing logs to a file
        file_handler = logging.FileHandler(log_path)
        file_handler.setLevel(logging.DEBUG)
        
        # Create log formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        
        # Add the file handler to the logger
        logger.addHandler(file_handler)
        
        return logger

    def setup_alert_logger(self, alert_log_name):
        """
        Setup a specific alert logger for critical log entries.
        """
        alert_logger = logging.getLogger("alerts")
        alert_logger.setLevel(logging.WARNING)
        alert_file = os.path.join(self.log_dir, alert_log_name)
        alert_handler = logging.FileHandler(alert_file)
        alert_handler.setLevel(logging.WARNING)
        
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        alert_handler.setFormatter(formatter)
        alert_logger.addHandler(alert_handler)

        return alert_logger

    def log_info(self, message, print_message=True):
        """
        Log an informational message and optionally print it to the console.
        """
        self.general_logger.info(message)
        if print_message:
            print(Fore.CYAN + f"INFO: {message}")

    def log_warning(self, message, print_message=True):
        """
        Log a warning message and optionally print it to the console.
        """
        self.general_logger.warning(message)
        if print_message:
            print(Fore.YELLOW + f"WARNING: {message}")

    def log_error(self, message, print_message=True):
        """
        Log an error message and optionally print it to the console.
        """
        self.general_logger.error(message)
        if print_message:
            print(Fore.RED + f"ERROR: {message}")

    def log_debug(self, message, print_message=True):
        """
        Log a debug message and optionally print it to the console.
        """
        self.general_logger.debug(message)
        if print_message:
            print(Fore.GREEN + f"DEBUG: {message}")

    def log_exception(self, exception, print_message=True):
        """
        Log exception details and optionally print it to the console.
        """
        self.general_logger.error(f"Exception: {str(exception)}")
        if print_message:
            print(Fore.RED + f"EXCEPTION: {str(exception)}")

    def log_alert(self, message, print_message=True):
        """
        Log a critical alert message, log it to the alert file, and optionally print it to the console.
        """
        # Log to the alert file
        self.alert_logger.warning(message)
        
        # Print to the terminal with red background and white text
        if print_message:
            print(Fore.RED + Style.BRIGHT + f"ALERT: {message}")

# if __name__ == "__main__":
#     logger = Logger()

#     # Example logging messages
#     logger.log_info("Informational message")
#     logger.log_warning("Warning message")
#     logger.log_error("Error message")
#     try:
#         raise Exception("This is an exception")
#     except Exception as e:
#         logger.log_exception(e)
#     logger.log_alert("This is an alert message")