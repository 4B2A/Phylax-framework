@echo off
title Phylax-framework Launcher

pip install -r requirements.txt --quiet



if "%~1"=="" (
    python phylax.py
) else (
    python phylax.py "%~1"
)
pause
