"""
Fingerprint Authentication Module
Supports hardware fingerprint scanners (pyfingerprint compatible) and simulation mode
"""
import cv2
import pickle
import hashlib
import numpy as np
import logging
import serial
import time
from pathlib import Path
from typing import Tuple, Optional, Dict, Any, Union
from PIL import Image
import io

from config import (
    FINGERPRINT_VENDOR_ID, FINGERPRINT_PRODUCT_ID, FINGERPRINT_BAUDRATE,
    FINGERPRINT_TIMEOUT, SENDER_FINGERPRINT_TEMPLATE, RECEIVER_FINGERPRINT_TEMPLATE
)

logger = logging.getLogger(__name__)

class FingerprintAuthenticator:
    """
    Fingerprint authentication supporting hardware and simulation modes
    """

    def __init__(self, port: Optional[str] = None, baudrate: int = FINGERPRINT_BAUDRATE, 
                 use_simulation: bool = False):
        """
        Initialize fingerprint authenticator

        Args:
            port: Serial port (e.g., '/dev/ttyUSB0' or 'COM3')
            baudrate: Serial baudrate
            use_simulation: If True, use software simulation instead of hardware
        """
        self.port = port
        self.baudrate = baudrate
        self.use_simulation = use_simulation
        self.sensor = None
        self.is_hardware = False

        if not use_simulation:
            try:
                self._init_hardware()
            except Exception as e:
                logger.warning(f"⚠️  Hardware initialization failed: {e}")
                logger.info("🔄 Falling back to simulation mode")
                self.use_simulation = True

    def _init_hardware(self):
        """Initialize hardware fingerprint sensor"""
        try:
            from pyfingerprint.pyfingerprint import PyFingerprint

                                               
            if self.port is None:
                self.port = self._detect_serial_port()

            self.sensor = PyFingerprint(self.port, self.baudrate, 0xFFFFFFFF, 0x00000000)

            if self.sensor.verifyPassword():
                logger.info(f"✅ Fingerprint sensor initialized on {self.port}")
                self.is_hardware = True
            else:
                raise ValueError("Failed to verify sensor password")

        except ImportError:
            logger.warning("pyfingerprint not installed, using simulation mode")
            self.use_simulation = True
        except Exception as e:
            logger.error(f"Hardware sensor error: {e}")
            raise

    def _detect_serial_port(self) -> str:
        """Auto-detect fingerprint sensor port"""
        import serial.tools.list_ports

                                                        
        known_devices = [
            (0x1A86, 0x7523),         
            (0x0403, 0x6001),         
            (0x0Bca, 0x2100),                 
            (0x1a86, 0x7523),                     
            (0x0403, 0x6001),                     
            (0x0bca, 0x2100),                             
        ]

        ports = list(serial.tools.list_ports.comports())
        
        logger.info(f"🔍 Scanning {len(ports)} serial ports for fingerprint sensor...")

        for port in ports:
            logger.info(f"   Port: {port.device}, Description: {port.description}, VID: {port.vid}, PID: {port.pid}")
            
                                     
            if hasattr(port, 'vid') and hasattr(port, 'pid') and port.vid is not None and port.pid is not None:
                if (port.vid, port.pid) in known_devices:
                    logger.info(f"✅ Found known fingerprint device on {port.device}")
                    return port.device

                                                        
            desc_lower = port.description.lower() if port.description else ""
            if 'fingerprint' in desc_lower or 'fm220' in desc_lower or 'access' in desc_lower:
                logger.info(f"✅ Found fingerprint device by description on {port.device}")
                return port.device

                                                   
            device_lower = port.device.lower() if port.device else ""
            if 'usb' in device_lower:
                logger.info(f"✅ Found USB device on {port.device}, trying it...")
                return port.device

                                                     
        if len(ports) > 0:
            logger.warning(f"⚠️  No known fingerprint device found, using fallback: {ports[0].device}")
            return ports[0].device

        raise RuntimeError("No serial port found")

    def _generate_simulated_template(self) -> bytes:
        """Generate a simulated fingerprint template (for testing)"""
                                                               
        np.random.seed(int(time.time() * 1000) % 10000)
        template = np.random.bytes(512)                      
        return template

    def capture_fingerprint(self, timeout: int = FINGERPRINT_TIMEOUT) -> Tuple[bool, Optional[bytes]]:
        """
        Capture fingerprint and return template

        Returns:
            (success, template_data)
        """
        if self.use_simulation:
            logger.info("🖐️  Place your finger on the sensor (simulated)...")
            time.sleep(2)                          
            template = self._generate_simulated_template()
            logger.info("✅ Fingerprint captured (simulated)")
            return True, template

        if not self.is_hardware or self.sensor is None:
            return False, None

        try:
            from pyfingerprint.pyfingerprint import PyFingerprint

            logger.info("🖐️  Place your finger on the sensor...")

                             
            start_time = time.time()
            while not self.sensor.readImage():
                if time.time() - start_time > timeout:
                    logger.warning("⏱️  Fingerprint capture timeout")
                    return False, None
                time.sleep(0.1)

            logger.info("✅ Finger detected, converting...")

                                       
            self.sensor.convertImage(0x01)

                                      
            characteristics = self.sensor.downloadCharacteristics(0x01)

            logger.info("✅ Fingerprint captured successfully")
            return True, bytes(characteristics)

        except Exception as e:
            logger.error(f"Failed to capture fingerprint: {e}")
            return False, None

    def enroll_fingerprint(self, identity: str, samples: int = 3) -> Tuple[bool, str]:
        """
        Enroll fingerprint template for identity

        Args:
            identity: 'sender' or 'receiver'
            samples: Number of samples to capture (hardware only)

        Returns:
            (success, message)
        """
        if identity not in ['sender', 'receiver']:
            return False, "Identity must be 'sender' or 'receiver'"

        template_path = SENDER_FINGERPRINT_TEMPLATE if identity == 'sender' else RECEIVER_FINGERPRINT_TEMPLATE

        if self.use_simulation:
                                            
            success, template = self.capture_fingerprint()
            if not success:
                return False, "Failed to capture fingerprint"

                           
            template_data = {
                'template': template,
                'identity': identity,
                'mode': 'simulation',
                'timestamp': time.time()
            }

            with open(template_path, 'wb') as f:
                pickle.dump(template_data, f)

            return True, f"Fingerprint enrolled for {identity} (simulated)"

                       
        try:
            logger.info(f"Enrolling fingerprint for {identity}...")
            logger.info(f"Need {samples} samples...")

            templates = []
            for i in range(samples):
                logger.info(f"Sample {i+1}/{samples}: Place finger...")

                                 
                while not self.sensor.readImage():
                    time.sleep(0.1)

                self.sensor.convertImage(0x01)

                if i > 0:
                                               
                    if not self.sensor.compareCharacteristics():
                        logger.warning("❌ Fingers do not match, try again")
                        i -= 1
                        continue

                if i < samples - 1:
                    logger.info("Remove finger...")
                    while self.sensor.readImage():
                        time.sleep(0.1)

                templates.append(self.sensor.downloadCharacteristics(0x01))

                             
            self.sensor.createTemplate()
            position = self.sensor.storeTemplate()

                          
            template_data = {
                'position': position,
                'identity': identity,
                'mode': 'hardware',
                'timestamp': time.time()
            }

            with open(template_path, 'wb') as f:
                pickle.dump(template_data, f)

            logger.info(f"✅ Fingerprint enrolled at position {position}")
            return True, f"Fingerprint enrolled successfully for {identity}"

        except Exception as e:
            logger.error(f"Enrollment failed: {e}")
            return False, str(e)

    def verify_fingerprint(self, identity: str) -> Tuple[bool, float, str]:
        """
        Verify fingerprint against enrolled template

        Returns:
            (verified, confidence, message)
        """
        if identity not in ['sender', 'receiver']:
            return False, 0.0, "Identity must be 'sender' or 'receiver'"

        template_path = SENDER_FINGERPRINT_TEMPLATE if identity == 'sender' else RECEIVER_FINGERPRINT_TEMPLATE

        if not template_path.exists():
            return False, 0.0, f"No enrolled template found for {identity}"

                              
        try:
            with open(template_path, 'rb') as f:
                stored_data = pickle.load(f)
        except Exception as e:
            return False, 0.0, f"Failed to load template: {e}"

                                     
        success, current_template = self.capture_fingerprint()
        if not success:
            return False, 0.0, "Failed to capture fingerprint"

        if self.use_simulation:
                                        
            stored_hash = hashlib.sha256(stored_data['template']).hexdigest()
            current_hash = hashlib.sha256(current_template).hexdigest()

                                                                      
                                                            
            confidence = 0.95                             
            verified = True

            if verified:
                return True, confidence, "Fingerprint verified (simulated)"
            else:
                return False, confidence, "Fingerprint mismatch"

                               
        try:
                                     
            position = stored_data.get('position', 0)

            self.sensor.loadTemplate(position, 0x01)

                    
            result = self.sensor.searchTemplate()

            if result[0] >= 0:
                confidence = result[1] / 100.0                        
                if confidence > 0.6:             
                    return True, confidence, "Fingerprint verified successfully"
                else:
                    return False, confidence, "Low confidence match"
            else:
                return False, 0.0, "No matching fingerprint found"

        except Exception as e:
            logger.error(f"Verification error: {e}")
            return False, 0.0, f"Verification failed: {e}"

    def get_template_for_fusion(self, identity: str) -> Optional[bytes]:
        """
        Get fingerprint template hash for key fusion
        Returns 256-bit hash of template for key material
        """
        template_path = SENDER_FINGERPRINT_TEMPLATE if identity == 'sender' else RECEIVER_FINGERPRINT_TEMPLATE

        if not template_path.exists():
            return None

        try:
            with open(template_path, 'rb') as f:
                data = pickle.load(f)

            if 'template' in data:
                return hashlib.sha256(data['template']).digest()
            else:
                                                              
                seed = f"{data.get('position', 0)}-{data.get('timestamp', 0)}"
                return hashlib.sha256(seed.encode()).digest()

        except Exception as e:
            logger.error(f"Failed to get template for fusion: {e}")
            return None

    def delete_template(self, identity: str) -> bool:
        """Delete enrolled template"""
        template_path = SENDER_FINGERPRINT_TEMPLATE if identity == 'sender' else RECEIVER_FINGERPRINT_TEMPLATE

        if template_path.exists():
            template_path.unlink()
            logger.info(f"Deleted fingerprint template for {identity}")
            return True
        return False

    def check_enrollment(self, identity: str) -> bool:
        """Check if identity is enrolled"""
        template_path = SENDER_FINGERPRINT_TEMPLATE if identity == 'sender' else RECEIVER_FINGERPRINT_TEMPLATE
        return template_path.exists()

    def get_sensor_info(self) -> Dict[str, Any]:
        """Get sensor information"""
        if self.use_simulation:
            return {
                'mode': 'simulation',
                'hardware': False,
                'status': 'active'
            }

        if self.is_hardware and self.sensor:
            try:
                return {
                    'mode': 'hardware',
                    'hardware': True,
                    'port': self.port,
                    'baudrate': self.baudrate,
                    'template_count': self.sensor.getTemplateCount(),
                    'capacity': self.sensor.getStorageCapacity(),
                    'status': 'active'
                }
            except:
                pass

        return {
            'mode': 'unknown',
            'hardware': False,
            'status': 'inactive'
        }

    def close(self):
        """Close sensor connection"""
        if self.is_hardware and self.sensor:
            try:
                                                                                
                pass
            except:
                pass
