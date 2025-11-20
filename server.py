from quart import Quart, request, jsonify, send_from_directory
import os

app = Quart(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Storage for WebRTC data between browsers
offers = {}
answers = {}
candidates = {}

@app.route('/')
async def serve_html():
    return await send_from_directory(os.path.join(BASE_DIR, 'static'), 'index.html')

# ---- OFFER ----
@app.route("/offer", methods=["POST"])
async def offer():
    data = await request.get_json()
    peer_id = data["peer_id"]
    offers[peer_id] = data["offer"]
    return jsonify({"status": "ok"})

@app.route("/get_offer/<peer_id>", methods=["GET"])
async def get_offer(peer_id):
    return jsonify({"offer": offers.get(peer_id)})

# ---- ANSWER ----
@app.route("/answer", methods=["POST"])
async def answer():
    data = await request.get_json()
    peer_id = data["peer_id"]
    answers[peer_id] = data["answer"]
    return jsonify({"status": "ok"})

@app.route("/get_answer/<peer_id>", methods=["GET"])
async def get_answer(peer_id):
    return jsonify({"answer": answers.get(peer_id)})

# ---- ICE CANDIDATES ----
@app.route("/candidate", methods=["POST"])
async def candidate():
    data = await request.get_json()
    peer_id = data["peer_id"]
    cand = data["candidate"]

    if peer_id not in candidates:
        candidates[peer_id] = []
    candidates[peer_id].append(cand)

    return jsonify({"status": "ok"})

@app.route("/get_candidates/<peer_id>", methods=["GET"])
async def get_candidates(peer_id):
    return jsonify({"candidates": candidates.get(peer_id, [])})

# ---- RUN SERVER ----
if __name__ == "__main__":
    import asyncio
    asyncio.run(app.run_task(host="0.0.0.0", port=5000))
