import uvicorn
import hashlib
import hmac

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import HTMLResponse

from dataclasses import dataclass
from urllib.parse import parse_qs
from datetime import datetime
from typing import Optional

app = FastAPI()

@dataclass
class TG:
    id: int
    first_name: str
    username: str
    auth_date: datetime
    hash: str
    last_name: Optional[str] = None


TOKEN_BOT = ''
TOKEN_BOT_HASH = hashlib.sha256(TOKEN_BOT.encode()).digest()


def auth_tg_check(data: TG):
    hash_from_data = data.hash
    data_string = '\n'.join([f'{k}={v}' for k, v in sorted(data.__dict__.items()) if k != 'hash' and v is not None])
    hmac_hash = hmac.new(TOKEN_BOT_HASH, data_string.encode(), hashlib.sha256).hexdigest()

    if hash_from_data != hmac_hash:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='hash check failed')

@app.get('/auth/telegram')
async def auth_tg(request: Request):
    form_data = request.query_params
    data = {k: v[0] for k, v in parse_qs(str(form_data)).items()}
    
    auth_tg_check(TG(**data))
    return {'success': 'ok'}

@app.get('/')
async def hello():
    html_content = """
    <html>
        <head>
            <title>TG AUTH</title>
        </head>
        <body>
            <script async src="https://telegram.org/js/telegram-widget.js?22" data-telegram-login="" data-size="large" data-auth-url="" data-request-access="write"></script>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content, status_code=200)


if __name__ == '__main__':
    uvicorn.run('main:app', reload=True)
    