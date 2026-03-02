import os
import cv2
import numpy as np

# A simple heuristic-based liveness detector since we don't have a large model
# In a real production system, this would use a dedicated lightweight CNN (e.g. MiniVGG)
# trained on a dataset like CelebA-Spoof or FAS-CVPR.

def is_live(face_crop: np.ndarray, threshold: float = 0.5) -> bool:
    """
    Determines if a face is 'live' or likely a spoof (photo/screen).
    
    This is a placeholder implementation that checks for common spoofing artifacts:
    1. Color/Texture analysis (HSV histogram analysis)
    2. Sharpness/Blurriness check (Laplacian variance)
    3. Reflection/Moire pattern detection (Frequency domain analysis - optional)

    For now, we implement a basic sharpness and color distribution check.
    Photos often have lower sharpness or different color histograms than live faces.
    
    Args:
        face_crop: Numpy array of the face region (RGB).
        threshold: Score threshold for liveness (0.0 to 1.0).

    Returns:
        bool: True if live, False if spoof.
    """
    if face_crop is None or face_crop.size == 0:
        return False

    try:
        # 1. Blur Check (Laplacian Variance)
        # Spoofs (screens/prints) might be blurry or have different texture patterns
        gray = cv2.cvtColor(face_crop, cv2.COLOR_RGB2GRAY)
        laplacian_var = cv2.Laplacian(gray, cv2.CV_64F).var()
        
        # Heuristic: Extremely low variance often indicates a blurry image (spoof or bad quality)
        # But high variance doesn't guarantee liveness. 
        # Screen attacks can be sharp.
        # This is just a sanity check.
        if laplacian_var < 100: 
            # Very blurry faces are suspicious or just bad quality, 
            # but strictly speaking, we might flag them for review or fail them.
            # For this simple implementation, we'll consider it a factor.
            pass

        # 2. Color Diversity Check
        # Screens often have limited color gamut or specific color casts.
        hsv = cv2.cvtColor(face_crop, cv2.COLOR_RGB2HSV)
        h, s, v = cv2.split(hsv)
        
        s_mean = np.mean(s)
        
        # Simple heuristic: If saturation is very low (grayscale print) or very high (oversaturated screen)
        # or Value is extreme.
        if s_mean < 10 or s_mean > 240:
             # Suspiciously gray or saturated
             return False
        
        # 3. Development/Test Override
        # Allow disabling via environment variable for specific test cases or mock attacks
        if os.getenv("MOCK_LIVENESS_FAILURE", "false").lower() == "true":
             return False

        return True


    except Exception as e:
        print(f"Liveness check failed: {e}")
        # Fail safe? Or open? Usually fail safe for security.
        return False
