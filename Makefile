.PHONY: install data feed train test serve docker
install: ; pip install -r requirements.txt
data:    ; python -m nova.data
feed:    ; python -m nova.feeds
train:   ; python -m nova.train
test:    ; python -m pytest -q tests
serve:   ; uvicorn nova.api:app --port 8000
docker:  ; docker compose up --build -d
