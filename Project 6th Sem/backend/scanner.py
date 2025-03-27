import nmap
import sqlite3
import pandas as pd
import joblib
import logging
from datetime import datetime
from gvm.connections import TLSConnection  # Updated import
from gvm.protocols.gmp import Gmp          # Updated GMP (Greenbone Management Protocol)
from gvm.errors import GvmError

# Configure logging
logging.basicConfig(filename='scanner.log', level=logging.INFO)

def run_scan(target_range='192.168.1.1-100'):
    try:
        # Initialize database connection
        conn = sqlite3.connect('backend/database.db')
        cursor = conn.cursor()
        
        # Create table if not exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER,
                service TEXT,
                severity TEXT,
                cvss_score REAL,
                risk_level TEXT,
                timestamp DATETIME
            )
        ''')
        conn.commit()

        # Load pre-trained AI model
        model = joblib.load('model.pkl')

        # ----------------------
        # Phase 1: Nmap Scanning
        # ----------------------
        logging.info("Starting Nmap scan...")
        nm = nmap.PortScanner()
        nm.scan(hosts=target_range, arguments='-sV')  # Version detection scan

        # ----------------------
        # Phase 2: OpenVAS/GVM Scan
        # ----------------------
        # Configure GVM connection
        connection = TLSConnection(hostname='gvm', port=9390)  # Use Docker service name "gvm"
        
        # Authenticate with GVM
        with Gmp(connection=connection) as gmp:
            try:
                gmp.authenticate('admin', 'admin')  # Update credentials if needed
                
                # Create target
                target = gmp.create_target(
                    name="Temp Target",
                    hosts=[target_range],
                    comment="Scan target for vulnerabilities"
                )
                
                # Create and run scan
                scan_config_id = 'daba56c8-73ec-11df-a475-002264764cea'  # "Full and Fast" config
                task = gmp.create_task(
                    name="Vulnerability Scan",
                    config_id=scan_config_id,
                    target_id=target.id
                )
                gmp.start_task(task.id)

                # Wait for scan to complete and get results
                report = gmp.get_reports(filter_string="task_id={0} and status=Done".format(task.id))
                
                # Process results
                for host in report.findall('.//host'):
                    ip = host.findtext('ip')
                    for port in host.findall('.//port'):
                        port_num = port.findtext('portid')
                        service = port.findtext('service/name')
                        severity = port.findtext('severity')
                        cvss_score = port.findtext('cvss_base_score')
                        
                        # ----------------------
                        # Phase 3: AI Prediction
                        # ----------------------
                        try:
                            severity_map = {'Low': 0, 'Medium': 1, 'High': 2, 'Critical': 3}
                            input_data = pd.DataFrame([[
                                severity_map.get(severity, 3),  # Default to Critical if unknown
                                float(cvss_score) if cvss_score else 0.0
                            ]], columns=['severity', 'cvss_score'])
                            
                            risk_level = model.predict(input_data)[0]
                            risk_labels = {0: 'Low', 1: 'Medium', 2: 'High', 3: 'Critical'}
                            risk_level = risk_labels.get(risk_level, 'Unknown')
                            
                        except Exception as e:
                            logging.error(f"AI prediction failed: {str(e)}")
                            risk_level = 'Unknown'

                        # Insert into database
                        cursor.execute('''
                            INSERT INTO vulnerabilities 
                            (ip, port, service, severity, cvss_score, risk_level, timestamp)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            ip,
                            port_num,
                            service,
                            severity,
                            cvss_score,
                            risk_level,
                            datetime.now()
                        ))

            except GvmError as e:
                logging.error(f"GVM error: {str(e)}")
                return {"status": "error", "message": str(e)}

        conn.commit()
        logging.info("Scan completed successfully")
        return {"status": "success", "message": "Scan completed"}

    except Exception as e:
        logging.critical(f"Critical error: {str(e)}")
        return {"status": "error", "message": str(e)}
    
    finally:
        if 'conn' in locals():
            conn.close()

# Example usage
if __name__ == '__main__':
    print(run_scan('192.168.1.1-10'))  # Test with a small range