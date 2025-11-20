import asyncio
from aiortc import RTCPeerConnection, RTCSessionDescription, VideoStreamTrack
from read_video import OpenCVVideoTrack
from aiortc.contrib.media import MediaPlayer, MediaRecorder

async def run(peer_ip):
    pc = RTCPeerConnection()

    # Send your local video
    pc.addTrack(OpenCVVideoTrack())

    # Receive remote video
    @pc.on("track")
    def on_track(track):
        print("Received track:", track.kind)
        if track.kind == "video":
            # Save or display remote video
            recorder = MediaRecorder("remote.mp4")  # or use OpenCV to show live
            recorder.addTrack(track)
            asyncio.create_task(recorder.start())

    # Create offer
    offer = await pc.createOffer()
    await pc.setLocalDescription(offer)

    # Send offer to signaling server
    import requests, json
    r = requests.post(f"http://{peer_ip}:5000/offer", json={
        "peer_id": "my_pc",
        "sdp": pc.localDescription.sdp,
        "type": pc.localDescription.type
    })

    # Here you would normally wait for the answer from the other peer
    # Once answer arrives:
    # answer_sdp = ...
    # await pc.setRemoteDescription(RTCSessionDescription(sdp=answer_sdp, type="answer"))

asyncio.run(run("192.168.1.2"))  # IP of the other computer
