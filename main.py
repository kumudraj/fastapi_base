import logging
import os

import uvicorn
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from src.config.constants import APP_HOST, APP_PORT
from src.endpoint.routes import router
from src.log_module.logger import get_logger_obj

log = get_logger_obj(os.path.basename(__file__).replace(".py", ''))

# FastAPI app setup
app = FastAPI()

app.include_router(router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

if __name__ == "__main__":
    log.info("App Engine starting host:{APP_HOST}, port:{PORT}")
    uvicorn.run(app, host=APP_HOST, port=APP_PORT, access_log=False, log_level=logging.INFO)
