import cv2
from read_video import openCamera

def get_camera_properties(cam):
    props = {
        "frame_width": cam.get(cv2.CAP_PROP_FRAME_WIDTH),
        "frame_height": cam.get(cv2.CAP_PROP_FRAME_HEIGHT),
        "fps": cam.get(cv2.CAP_PROP_FPS),
        "brightness": cam.get(cv2.CAP_PROP_BRIGHTNESS),
        "contrast": cam.get(cv2.CAP_PROP_CONTRAST),
        "saturation": cam.get(cv2.CAP_PROP_SATURATION),
        "hue": cam.get(cv2.CAP_PROP_HUE),
        "gain": cam.get(cv2.CAP_PROP_GAIN),
        "exposure": cam.get(cv2.CAP_PROP_EXPOSURE),
        "focus": cam.get(cv2.CAP_PROP_FOCUS),
        "backlight": cam.get(cv2.CAP_PROP_BACKLIGHT),
        "white_balance_blue": cam.get(cv2.CAP_PROP_WHITE_BALANCE_BLUE_U),
        "white_balance_red": cam.get(cv2.CAP_PROP_WHITE_BALANCE_RED_V),
        "convert_rgb": cam.get(cv2.CAP_PROP_CONVERT_RGB),
        "temperature": cam.get(cv2.CAP_PROP_TEMPERATURE),
        "mode": cam.get(cv2.CAP_PROP_MODE),
    }
    return props

# Usage
cam = cv2.VideoCapture(0)
if not cam.isOpened():
    raise RuntimeError("Cannot open camera")

camera_props = get_camera_properties(cam)
print(camera_props)
openCamera()