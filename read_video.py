# read_video.py
import cv2 as cv
import numpy as np
from aiortc import VideoStreamTrack
from av import VideoFrame

# OpenCV capture
capture = cv.VideoCapture(0)
if not capture.isOpened():
    raise RuntimeError("Could not open camera")

class OpenCVVideoTrack(VideoStreamTrack):
    def __init__(self):
        super().__init__()
        self.kind = "video"   # must be set for aiortc
        self.capture = capture

    async def recv(self):
        pts, time_base = await self.next_timestamp()
        ret, frame = self.capture.read()
        if not ret or frame is None:
            frame = np.zeros((480, 640, 3), dtype=np.uint8)

        frame = cv.resize(frame, (640, 480))
        frame = cv.cvtColor(frame, cv.COLOR_BGR2RGB)

        video_frame = VideoFrame.from_ndarray(frame, format="rgb24")
        video_frame.pts = pts
        video_frame.time_base = time_base
        return video_frame

# import cv2 as cv
# import numpy as np
# from aiortc import VideoStreamTrack
# from av import VideoFrame

# capture = cv.VideoCapture(0)
# if not capture.isOpened():
#     raise RuntimeError("Could not open camera")

# def changeRes(capture, width, height):
#     ##Changes live video only
#     capture.set(3, width)
#     capture.set(4, height)

# def rescaleFrame(frame, scale = 0.75):
#         ##Changes live video, prerecorded videos, and images
#         width = int(frame.shape[1] *scale )
#         height = int(frame.shape[0] * scale)
#         dimensions = (width, height)

#         return cv.resize(frame, dimensions, interpolation = cv.INTER_AREA)

# def openCamera():
#     while True:
#         isTrue, frame = capture.read()
#         if not isTrue or frame is None:
#             continue

#         frame_resized = rescaleFrame(frame)

#         ret, buffer = cv.imencode('.jpg', frame_resized)
#         if not ret:
#             continue
#         frame_bytes = buffer.tobytes()

#         yield (b'--frame\r\n'
#         b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

# class OpenCVVideoTrack(VideoStreamTrack):
#     def __init__(self):
#         super().__init__()
#         self.kind = "video"
#         self.capture = capture

#     async def recv(self):
#             pts, time_base = await self.next_timestamp()
#             ret, frame = self.capture.read()
#             if not ret:
#                 frame = np.zeros((480, 640, 3), dtype=np.uint8)  # fallback black frame

#             frame = cv.resize(frame, (640, 480))
#             frame = cv.cvtColor(frame, cv.COLOR_BGR2RGB)

#             video_frame = VideoFrame.from_ndarray(frame, format="rgb24")
#             video_frame.pts = pts
#             video_frame.time_base = time_base
#             return video_frame
