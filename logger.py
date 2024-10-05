import logging
from colorama import Fore, Style, init
from datetime import datetime

# Initialize colorama for auto-resetting colors
init(autoreset=True)

# Define a color map for different logging levels
COLOR_MAP = {
    logging.DEBUG: Fore.CYAN,
    logging.INFO: Fore.GREEN,
    logging.WARNING: Fore.RED,
    logging.ERROR: Fore.RED,
    logging.CRITICAL: Fore.MAGENTA + Style.BRIGHT,  # Make critical bold
}

# Custom Formatter to colorize log messages
class ColoredFormatter(logging.Formatter):
    def format(self, record):
        log_color = COLOR_MAP.get(record.levelno, Style.RESET_ALL)
        message = super().format(record)
        return f"{log_color}{message}{Style.RESET_ALL}"

# Custom Logger class that includes the time method
class CustomLogger(logging.Logger):
    def time(self, data):
        print(f"{Fore.LIGHTBLACK_EX}[TIME] {data}{Style.RESET_ALL}")

# Create a logger and set up the colored formatter
logger = CustomLogger(__name__)
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = ColoredFormatter('[%(levelname)s] %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)
