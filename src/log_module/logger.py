import logging
import sys

# CustomFormatter class with ANSI color codes for log levels
class CustomFormatter(logging.Formatter):
    grey = "\x1b[1;37m"
    green = "\x1b[32;21m"
    yellow = "\x1b[33;21m"
    red = "\x1b[31;21m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = (
        "%(asctime)s - %(levelname)s - %(message)s [%(name)s:%(filename)s:%(lineno)d]"
    )

    # Mapping of log level to colored format string
    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: green + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


def get_logger_obj(app_name, log_level=logging.INFO):
    """
    Creates and returns a custom logger object.

    Parameters:
    - app_name (str): The name of the application to be used as the logger's name.

    Returns:
    - logger (logging.Logger): The customized logger object.
    """
    # Create a logger with the specified 'app_name'
    logger = logging.getLogger(app_name)
    logger.setLevel(log_level)

    # Check if the logger already has handlers to avoid duplicate log messages
    if not logger.handlers:
        # Create a console handler with a higher log level
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(log_level)

        # Set the custom formatter for the console handler
        ch.setFormatter(CustomFormatter())

        # Add the console handler to the logger
        logger.addHandler(ch)

    return logger


def error_msg(var) -> str:
    error_type = var[0].__name__
    error = var[1]
    return f"Type: {error_type}, Msg: {error}"
