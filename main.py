import argparse
import logging
import ssl
import socket
import datetime
import pandas as pd
import OpenSSL

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description='Inspects SSL/TLS certificates for expiration, issuer, and vulnerabilities.')
    parser.add_argument('hostname', help='The hostname to inspect.')
    parser.add_argument('-p', '--port', type=int, default=443, help='The port to connect to (default: 443).')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging.')
    parser.add_argument('-o', '--output', help='Output the certificate details to a CSV file.')
    return parser

def get_certificate(hostname, port=443):
    """
    Retrieves the SSL/TLS certificate from the specified hostname and port.

    Args:
        hostname (str): The hostname to connect to.
        port (int): The port to connect to (default: 443).

    Returns:
        ssl.SSLSocket: The SSL/TLS socket object.  Returns None on error.

    Raises:
        socket.gaierror: If the hostname cannot be resolved.
        ConnectionRefusedError: If the connection is refused.
        ssl.SSLError: If there's an SSL-related error.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert(binary_form=True)
    except socket.gaierror as e:
        logging.error(f"Hostname resolution error: {e}")
        return None
    except ConnectionRefusedError as e:
        logging.error(f"Connection refused: {e}")
        return None
    except ssl.SSLError as e:
        logging.error(f"SSL error: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

def analyze_certificate(cert_bytes):
    """
    Analyzes the SSL/TLS certificate and extracts relevant information.

    Args:
        cert_bytes (bytes): The certificate in binary form.

    Returns:
        dict: A dictionary containing certificate details, or None on error.
    """
    try:
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bytes)
        subject = cert.get_subject()
        issuer = cert.get_issuer()
        
        subject_data = {component.decode(): subject.components()[i][1].decode() for i, component in enumerate(subject.components()[0])}
        issuer_data = {component.decode(): issuer.components()[i][1].decode() for i, component in enumerate(issuer.components()[0])}


        not_before = datetime.datetime.strptime(cert.get_notBefore().decode(), '%Y%m%d%H%M%SZ')
        not_after = datetime.datetime.strptime(cert.get_notAfter().decode(), '%Y%m%d%H%M%SZ')
        
        return {
            'subject': subject_data,
            'issuer': issuer_data,
            'not_before': not_before,
            'not_after': not_after,
            'version': cert.get_version(),
            'serial_number': cert.get_serial_number()
        }
    except OpenSSL.crypto.Error as e:
        logging.error(f"OpenSSL error while analyzing certificate: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred during certificate analysis: {e}")
        return None

def check_expiration(cert_details):
    """
    Checks if the certificate is expired or nearing expiration.

    Args:
        cert_details (dict): A dictionary containing certificate details.

    Returns:
        str: A message indicating the expiration status.
    """
    if not cert_details:
        return "Could not retrieve expiration details."

    not_after = cert_details['not_after']
    now = datetime.datetime.now()
    time_left = not_after - now

    if time_left.days < 0:
        return "Certificate has expired!"
    elif time_left.days < 30:
        return f"Certificate expires in {time_left.days} days."
    else:
        return f"Certificate expires on {not_after.strftime('%Y-%m-%d %H:%M:%S')}."

def save_to_csv(cert_details, filename):
    """
    Saves certificate details to a CSV file.

    Args:
        cert_details (dict): A dictionary containing certificate details.
        filename (str): The name of the CSV file to save to.
    """
    try:
        df = pd.DataFrame([cert_details])
        df.to_csv(filename, index=False)
        logging.info(f"Certificate details saved to {filename}")
    except Exception as e:
        logging.error(f"Error saving to CSV: {e}")

def main():
    """
    The main function of the script.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    hostname = args.hostname
    port = args.port

    logging.info(f"Inspecting certificate for {hostname}:{port}")

    cert_bytes = get_certificate(hostname, port)
    
    if not cert_bytes:
        print("Failed to retrieve certificate.")
        return

    cert_details = analyze_certificate(cert_bytes)

    if not cert_details:
        print("Failed to analyze certificate.")
        return

    print("Certificate Details:")
    print(f"  Subject: {cert_details['subject']}")
    print(f"  Issuer: {cert_details['issuer']}")
    print(f"  Valid From: {cert_details['not_before'].strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Valid Until: {cert_details['not_after'].strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Serial Number: {cert_details['serial_number']}")

    expiration_status = check_expiration(cert_details)
    print(f"  Expiration Status: {expiration_status}")

    if args.output:
        save_to_csv(cert_details, args.output)

if __name__ == "__main__":
    main()