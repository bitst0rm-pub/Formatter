import logging

from . import PACKAGE_NAME

# Custom level STATUS
STATUS = 42
logging.addLevelName(STATUS, 'STATUS')


def status(self, message, *args, **kwargs):
    if self.isEnabledFor(STATUS):
        self._log(STATUS, message, args, **kwargs)


logging.Logger.status = status


def setup_logger(name):
    formatter = logging.Formatter(fmt='▍[' + PACKAGE_NAME + '](%(filename)s#L%(lineno)s): [%(levelname)s] %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    if logger.hasHandlers():
        logger.handlers.clear()
    logger.addHandler(handler)
    return logger


def enable_logging():
    root_logger = logging.getLogger(__name__)
    root_logger.setLevel(logging.DEBUG)


def enable_status():
    root_logger = logging.getLogger(__name__)
    root_logger.setLevel(STATUS)


def disable_logging():
    root_logger = logging.getLogger(__name__)
    root_logger.setLevel(logging.CRITICAL)


setup_logger(__name__)
log = logging.getLogger(__name__)
