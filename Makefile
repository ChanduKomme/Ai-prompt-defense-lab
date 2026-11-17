# Author: Chandu Komme — PromptShield
PYTHON ?= python3

.PHONY: help test redteam demo serve clean

help:  ## Show available targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

test:  ## Run the unit and system tests
	$(PYTHON) -m unittest discover -s tests -v

redteam:  ## Run the red-team suites and write the scorecard
	$(PYTHON) -m promptshield redteam --output reports/scorecard.md --json reports/redteam.json

demo:  ## Show one indirect injection against both agents
	$(PYTHON) -m promptshield ask "How are refunds processed for returned gear?" --poison returns-tool-call.md --naive
	@echo "-----"
	$(PYTHON) -m promptshield ask "How are refunds processed for returned gear?" --poison returns-tool-call.md

serve:  ## Start the JSON API on 127.0.0.1:8080
	$(PYTHON) -m promptshield serve

clean:  ## Remove generated reports
	rm -rf reports
