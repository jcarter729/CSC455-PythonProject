import asyncio
from aiortc import RTCPeerConnection, RTCSessionDescription
from read_video import OpenCVVideoTrack
from aiortc.contrib.media import MediaRecorder


async def run(peer_ip, my_id="my_pc", remote_id="peer1"):
    pc = RTCPeerConnection()

    # Send your local video
    pc.addTrack(OpenCVVideoTrack())

    # Receive remote video
    @pc.on("track")
    def on_track(track):
        print("Received track:", track.kind)
        if track.kind == "video":
            recorder = MediaRecorder("remote.mp4")
            recorder.addTrack(track)
            asyncio.create_task(recorder.start())

    # Forward locally gathered ICE candidates to the signaling server
    @pc.on("icecandidate")
    def on_icecandidate(candidate):
        # candidate may be an object or a dict depending on aiortc version
        if not candidate:
            return
        try:
            import requests
            if isinstance(candidate, dict):
                cdict = candidate
            else:
                cdict = {
                    "candidate": getattr(candidate, "candidate", None),
                    "sdpMid": getattr(candidate, "sdpMid", None),
                    "sdpMLineIndex": getattr(candidate, "sdpMLineIndex", None),
                }
            requests.post(f"http://{peer_ip}:5000/candidate", json={"peer_id": my_id, "candidate": cdict})
        except Exception as e:
            print("Failed to send local candidate:", e)

    # Create offer and set local description
    offer = await pc.createOffer()
    await pc.setLocalDescription(offer)

    # Send offer to signaling server (flat form)
    import requests
    try:
        requests.post(f"http://{peer_ip}:5000/offer", json={
            "peer_id": my_id,
            "sdp": pc.localDescription.sdp,
            "type": pc.localDescription.type
        })
    except Exception as e:
        print("Failed to post offer:", e)

    # Poll for the answer
    answer = None
    while True:
        await asyncio.sleep(1)
        try:
            res = requests.get(f"http://{peer_ip}:5000/get_answer/{my_id}")
            data = res.json()
            # our server returns {} when no answer yet
            if data and data.get("sdp"):
                answer = data
                break
        except Exception as e:
            print("Error fetching answer:", e)

    # Apply remote description
    try:
        await pc.setRemoteDescription(RTCSessionDescription(sdp=answer["sdp"], type=answer["type"]))
        print("Remote description set")
    except Exception as e:
        print("Failed to set remote description:", e)

    # Poll for remote ICE candidates and add them
    async def poll_candidates():
        seen = set()
        while True:
            await asyncio.sleep(1)
            try:
                res = requests.get(f"http://{peer_ip}:5000/get_candidates/{remote_id}")
                data = res.json()
                for c in data.get("candidates", []):
                    key = (c.get("candidate"), c.get("sdpMid"), c.get("sdpMLineIndex"))
                    if key in seen:
                        continue
                    seen.add(key)
                    try:
                        await pc.addIceCandidate(c)
                    except Exception as e:
                        print("Failed to add ICE candidate:", e)
            except Exception as e:
                print("Error polling candidates:", e)

    asyncio.create_task(poll_candidates())


if __name__ == "__main__":
    # Adjust the IP and ids as needed: first arg is signaling server IP
    asyncio.run(run("172.26.95.31", my_id="my_pc", remote_id="peer2"))
