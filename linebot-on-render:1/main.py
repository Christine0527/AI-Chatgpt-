from fastapi import FastAPI, Request, HTTPException
import hmac, hashlib, base64, os, requests

app = FastAPI()

LINE_TOKEN = os.getenv("LINE_TOKEN")
LINE_SECRET = os.getenv("LINE_SECRET")
OPENAI_KEY = os.getenv("OPENAI_KEY")

def verify_line_signature(body: bytes, signature: str) -> bool:
    mac = hmac.new(LINE_SECRET.encode(), body, hashlib.sha256).digest()
    expected = base64.b64encode(mac).decode()
    return hmac.compare_digest(expected, signature)

@app.get("/")
def read_root():
    return {"ok": True}

@app.post("/webhook")
async def webhook(request: Request):
    signature = request.headers.get("X-Line-Signature")
    body_bytes = await request.body()
    if not verify_line_signature(body_bytes, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

    body = await request.json()
    for event in body.get("events", []):
        if event.get("type") == "message" and event["message"]["type"] == "text":
            user_text = event["message"]["text"]

            # 呼叫 OpenAI
            r = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {OPENAI_KEY}"},
                json={
                    "model": "gpt-4o-mini",
                    "messages": [{"role": "user", "content": user_text}],
                }
            )
            reply_text = r.json()["choices"][0]["message"]["content"][:4900]

            # 回覆 LINE
            requests.post(
                "https://api.line.me/v2/bot/message/reply",
                headers={"Authorization": f"Bearer {LINE_TOKEN}", "Content-Type": "application/json"},
                json={
                    "replyToken": event["replyToken"],
                    "messages": [{"type": "text", "text": reply_text}]
                }
            )
    return {"status": "ok"}