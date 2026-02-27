"""
Face Recognition Authentication Module
Uses DeepFace with ArcFace model for high-accuracy face verification
"""
import time
import cv2
import pickle
import numpy as np
import logging
from pathlib import Path
from typing import Tuple, Optional, Dict, Any
from deepface import DeepFace
from deepface.commons import distance as dst

from config import (
    FACE_MODEL, FACE_DETECTOR, FACE_SIMILARITY_THRESHOLD,
    FACE_EMBEDDING_SIZE, SENDER_FACE_TEMPLATE, RECEIVER_FACE_TEMPLATE
)

logger = logging.getLogger(__name__)

class FaceAuthenticator:
    """
    Face authentication using DeepFace ArcFace model
    Provides enrollment, verification, and real-time capture
    """

    def __init__(self, model_name: str = FACE_MODEL, detector: str = FACE_DETECTOR):
        self.model_name = model_name
        self.detector = detector
        self.embedding_size = FACE_EMBEDDING_SIZE

        # Initialize model (downloads on first run)
        try:
            logger.info(f"Initializing face model: {model_name}")
            self.model = DeepFace.build_model(model_name)
            logger.info("✅ Face model loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load face model: {e}")
            self.model = None

    def capture_face(self, camera_index: int = 0, timeout: int = 120) -> Optional[np.ndarray]:
        """
        Capture face from webcam with auto-detection

        Args:
            camera_index: Camera device index
            timeout: Maximum time to wait for face detection (seconds)

        Returns:
            Captured face image or None if failed
        """
        # Try multiple camera indices
        cap = None
        for idx in range(3):  # Try indices 0, 1, 2
            logger.info(f"Trying camera index {idx}...")
            cap = cv2.VideoCapture(idx)
            if cap.isOpened():
                logger.info(f"✅ Successfully opened camera {idx}")
                break
            else:
                logger.warning(f"Cannot open camera {idx}")
                cap = None
        
        if cap is None or not cap.isOpened():
            logger.error("❌ Cannot open camera - no camera found or camera is in use")
            logger.info("Please check:")
            logger.info("  1. Ensure a webcam is connected")
            logger.info("  2. Close other applications using the camera")
            logger.info("  3. Try a different camera index")
            return None

        # Load OpenCV's Haar Cascade for face detection (faster than DeepFace)
        face_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
        )

        logger.info("📷 Starting face capture... Look at the camera")
        logger.info("Press SPACE to capture, ESC to cancel")

        start_time = cv2.getTickCount()
        captured_frame = None
        face_detected = False

        while True:
            ret, frame = cap.read()
            if not ret:
                continue

            # Convert to grayscale for faster detection
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

            # Detect faces using Haar Cascade (much faster)
            faces = face_cascade.detectMultiScale(
                gray, 
                scaleFactor=1.1, 
                minNeighbors=5, 
                minSize=(30, 30)
            )

            if len(faces) > 0:
                # Draw rectangle around detected face
                for (x, y, w, h) in faces:
                    cv2.rectangle(frame, (x, y), (x+w, y+h), (0, 255, 0), 2)
                cv2.putText(frame, "Face Detected - Press SPACE to capture", 
                           (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
                face_detected = True
                captured_frame = frame.copy()
            else:
                cv2.putText(frame, "No face detected - Look at camera", 
                           (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)
                face_detected = False

            # Show frame
            cv2.imshow("Face Capture", frame)

            # Check for key press
            key = cv2.waitKey(1) & 0xFF

            # Press SPACE to capture - even if no face detected, capture anyway
            if key == 32:  # SPACE key
                logger.info("✅ Capture button pressed")
                if not face_detected:
                    # Capture anyway even if no face detected
                    logger.info("No face detected, but capturing anyway for enrollment")
                    captured_frame = frame.copy()
                break

            # Press ESC to cancel
            if key == 27:  # ESC key
                logger.info("Capture cancelled")
                captured_frame = None
                break

            # Check timeout
            elapsed = (cv2.getTickCount() - start_time) / cv2.getTickFrequency()
            if elapsed > timeout:
                logger.warning("⏱️  Capture timeout")
                if face_detected:
                    logger.info("Auto-capturing detected face")
                    break
                captured_frame = None
                break

        cap.release()
        cv2.destroyAllWindows()

        return captured_frame

    def get_embedding(self, image_path_or_array) -> Optional[np.ndarray]:
        """
        Get face embedding vector from image

        Args:
            image_path_or_array: Path to image or numpy array

        Returns:
            512-dimensional embedding vector or None
        """
        import tempfile
        import os
        
        try:
            # If input is a numpy array, save to temp file
            if isinstance(image_path_or_array, np.ndarray):
                # Save to temporary file
                temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.jpg')
                temp_path = temp_file.name
                cv2.imwrite(temp_path, image_path_or_array)
                img_to_process = temp_path
            else:
                img_to_process = image_path_or_array
            
            # Use DeepFace represent function
            embeddings = DeepFace.represent(
                img_path=img_to_process,
                model_name=self.model_name,
                detector_backend=self.detector,
                enforce_detection=False  # Don't enforce to allow enrollment without face detection
            )

            # Clean up temp file
            if isinstance(image_path_or_array, np.ndarray) and os.path.exists(temp_path):
                time.sleep(0.5)  # small delay
                try:
                    os.remove(temp_path)
                except:
                    pass

            if embeddings and len(embeddings) > 0:
                # Handle different return formats
                result = embeddings[0]
                
                # If result is a dictionary with 'embedding' key
                if isinstance(result, dict) and 'embedding' in result:
                    return np.array(result['embedding'])
                
                # If result is already an array/tuple
                elif isinstance(result, (np.ndarray, tuple, list)):
                    return np.array(result)
                
                # If result is a tuple/list of (embedding, something)
                elif isinstance(result, (tuple, list)) and len(result) > 0:
                    return np.array(result[0])
                
                # Try to find embedding anywhere in the result
                else:
                    logger.warning(f"Unexpected DeepFace.represent format: {type(result)}")
                    return None

            return None

        except Exception as e:
            logger.error(f"Failed to get embedding: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return None

    def enroll_face(self, identity: str, image=None, camera_index: int = 0) -> Tuple[bool, str]:
        """
        Enroll face template for identity

        Args:
            identity: 'sender' or 'receiver'
            image: Optional pre-captured image
            camera_index: Camera index if capture needed

        Returns:
            (success, message)
        """
        if identity not in ['sender', 'receiver']:
            return False, "Identity must be 'sender' or 'receiver'"

        template_path = SENDER_FACE_TEMPLATE if identity == 'sender' else RECEIVER_FACE_TEMPLATE

        # Capture if no image provided
        if image is None:
            logger.info(f"Capturing face for {identity}...")
            image = self.capture_face(camera_index)
            if image is None:
                return False, "Failed to capture face"

        # Get embedding
        logger.info("Extracting face embedding...")
        embedding = self.get_embedding(image)

        if embedding is None:
            return False, "Failed to extract face features"

        # Save template
        try:
            template_data = {
                'embedding': embedding,
                'identity': identity,
                'model': self.model_name,
                'size': self.embedding_size
            }

            with open(template_path, 'wb') as f:
                pickle.dump(template_data, f)

            logger.info(f"✅ Face template saved to {template_path}")
            return True, f"Face enrolled successfully for {identity}"

        except Exception as e:
            logger.error(f"Failed to save template: {e}")
            return False, f"Failed to save template: {e}"

    def verify_face(self, identity: str, image=None, camera_index: int = 0) -> Tuple[bool, float, str]:
        """
        Verify face against enrolled template

        Args:
            identity: 'sender' or 'receiver'
            image: Optional pre-captured image
            camera_index: Camera index if capture needed

        Returns:
            (verified, similarity_score, message)
        """
        if identity not in ['sender', 'receiver']:
            return False, 0.0, "Identity must be 'sender' or 'receiver'"

        template_path = SENDER_FACE_TEMPLATE if identity == 'sender' else RECEIVER_FACE_TEMPLATE

        # Load template
        if not template_path.exists():
            return False, 0.0, f"No enrolled template found for {identity}. Please enroll first."

        try:
            with open(template_path, 'rb') as f:
                template_data = pickle.load(f)

            stored_embedding = template_data['embedding']

        except Exception as e:
            return False, 0.0, f"Failed to load template: {e}"

        # Capture if no image provided
        if image is None:
            logger.info(f"Capturing face for verification ({identity})...")
            image = self.capture_face(camera_index)
            if image is None:
                return False, 0.0, "Failed to capture face for verification"

        # Get current embedding
        current_embedding = self.get_embedding(image)
        if current_embedding is None:
            return False, 0.0, "Failed to extract features from captured face"

        # Calculate cosine similarity
        try:
            # DeepFace verification
            result = DeepFace.verify(
                img1_path=stored_embedding.reshape(1, -1) if isinstance(stored_embedding, np.ndarray) else template_data,
                img2_path=image,
                model_name=self.model_name,
                detector_backend=self.detector,
                distance_metric="cosine"
            )

            similarity = 1 - result['distance']  # Convert distance to similarity
            verified = result['verified']

        except Exception as e:
            # Fallback to manual calculation
            logger.warning(f"DeepFace verify failed, using manual calculation: {e}")
            similarity = self._calculate_similarity(stored_embedding, current_embedding)
            verified = similarity >= FACE_SIMILARITY_THRESHOLD

        if verified:
            logger.info(f"✅ Face verified for {identity} (similarity: {similarity:.3f})")
            return True, similarity, "Face verified successfully"
        else:
            logger.warning(f"❌ Face verification failed (similarity: {similarity:.3f})")
            return False, similarity, f"Face not recognized (similarity: {similarity:.3f})"

    def _calculate_similarity(self, embedding1: np.ndarray, embedding2: np.ndarray) -> float:
        """Calculate cosine similarity between two embeddings"""
        # Normalize
        e1_norm = embedding1 / np.linalg.norm(embedding1)
        e2_norm = embedding2 / np.linalg.norm(embedding2)

        # Cosine similarity
        return float(np.dot(e1_norm, e2_norm))

    def get_embedding_for_fusion(self, identity: str, image=None, camera_index: int = 0) -> Optional[bytes]:
        """
        Get face embedding for key fusion
        Returns 512-bit hash of embedding for key material
        """
        import hashlib

        if image is None:
            image = self.capture_face(camera_index)
            if image is None:
                return None

        embedding = self.get_embedding(image)
        if embedding is None:
            return None

        # Hash embedding to fixed size for key fusion
        embedding_bytes = embedding.astype(np.float32).tobytes()
        return hashlib.sha256(embedding_bytes).digest()

    def delete_template(self, identity: str) -> bool:
        """Delete enrolled template"""
        template_path = SENDER_FACE_TEMPLATE if identity == 'sender' else RECEIVER_FACE_TEMPLATE

        if template_path.exists():
            template_path.unlink()
            logger.info(f"Deleted template for {identity}")
            return True
        return False

    def check_enrollment(self, identity: str) -> bool:
        """Check if identity is enrolled"""
        template_path = SENDER_FACE_TEMPLATE if identity == 'sender' else RECEIVER_FACE_TEMPLATE
        return template_path.exists()
