import logging

def setup_logger(name, log_file='sentinelle_soc.log'):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    # Avoid duplicate handlers
    if not logger.handlers:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(f'%(asctime)s - [{name}] %(levelname)s - %(message)s'))
        
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(f'[{name}] %(message)s'))
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
    return logger
