# FIXTURE: a minimal FastAPI shape for stack detection.
from fastapi import FastAPI

app = FastAPI()


@app.get("/")
def read_root():
    return {"fixture": True}
