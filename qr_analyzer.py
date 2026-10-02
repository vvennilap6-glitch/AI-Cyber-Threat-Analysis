import cv2


# ==========================================
# QR CODE ANALYZER
# ==========================================

def analyze_qr(image_path):

    detector = cv2.QRCodeDetector()

    image = cv2.imread(image_path)

    if image is None:
        return {
            "detected": False,
            "data": "",
            "message": "Unable to read the image."
        }

    data, points, _ = detector.detectAndDecode(image)

    if data:

        return {
            "detected": True,
            "data": data,
            "message": "QR code detected successfully."
        }

    return {
        "detected": False,
        "data": "",
        "message": "No QR code detected."
    }