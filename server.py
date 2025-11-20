from quart import Quart, request, jsonify, send_from_directory
import os

app = Quart(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
offers = {}
answers = {}

@app.route('/')
async def serve_html():
    return await send_from_directory(os.path.join(BASE_DIR, 'static'), 'index.html')

@app.route("/offer", methods=["POST"])
async def offer():
    params = await request.get_json()
    peer_id = params["peer_id"]
    offers[peer_id] = params
    return jsonify({"status": "ok"})

@app.route("/get_offer/<peer_id>", methods=["GET"])
async def get_offer(peer_id):
    return jsonify(offers.get(peer_id, {}))

@app.route("/answer", methods=["POST"])
async def answer():
    params = await request.get_json()
    peer_id = params["peer_id"]
    answers[peer_id] = params
    return jsonify({"status": "ok"})

@app.route("/get_answer/<peer_id>", methods=["GET"])
async def get_answer(peer_id):
    return jsonify(answers.get(peer_id, {}))

candidates = {}

@app.route("/candidate", methods=["POST"])
async def candidate():
    params = await request.get_json()
    peer_id = params["peer_id"]
    candidates.setdefault(peer_id, []).append(params["candidate"])
    return jsonify({"status": "ok"})

@app.route("/get_candidates/<peer_id>", methods=["GET"])
async def get_candidates(peer_id):
    return jsonify({"candidates": candidates.get(peer_id, [])})

if __name__ == "__main__":
    import asyncio
    asyncio.run(app.run_task(host="0.0.0.0", port=5000))
