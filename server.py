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
    # Accept either { "peer_id": "id", "offer": {"type":..., "sdp":...} }
    # or the flat form { "peer_id": "id", "type": ..., "sdp": ... }
    print("/offer received:", data)
    peer_id = data.get("peer_id")
    if not peer_id:
        return jsonify({"error": "missing peer_id"}), 400

    offer_obj = data.get("offer")
    if not offer_obj:
        # build from flat fields if provided
        sdp = data.get("sdp")
        typ = data.get("type")
        if sdp and typ:
            offer_obj = {"sdp": sdp, "type": typ}
        else:
            return jsonify({"error": "missing offer or sdp/type"}), 400

    offers[peer_id] = offer_obj
    return jsonify({"status": "ok"})

@app.route("/get_offer/<peer_id>", methods=["GET"])
async def get_offer(peer_id):
    # Return the raw offer object (or empty object) so clients can call setRemoteDescription
    return jsonify(offers.get(peer_id, {}))

# ---- ANSWER ----
@app.route("/answer", methods=["POST"])
async def answer():
    data = await request.get_json()
    print("/answer received:", data)
    peer_id = data.get("peer_id")
    if not peer_id:
        return jsonify({"error": "missing peer_id"}), 400

    answer_obj = data.get("answer")
    if not answer_obj:
        sdp = data.get("sdp")
        typ = data.get("type")
        if sdp and typ:
            answer_obj = {"sdp": sdp, "type": typ}
        else:
            return jsonify({"error": "missing answer or sdp/type"}), 400

    answers[peer_id] = answer_obj
    return jsonify({"status": "ok"})

@app.route("/get_answer/<peer_id>", methods=["GET"])
async def get_answer(peer_id):
    # Return the raw answer object (or empty object)
    return jsonify(answers.get(peer_id, {}))

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
