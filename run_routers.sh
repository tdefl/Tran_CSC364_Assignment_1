#!/bin/bash

# Use the specific directory path where your scripts are located
SCRIPT_PATH="/Users/alfredtran/Desktop/CSC364/assignments/my_repo/Tran_CSC364_Assignment_1"

# Open 6 terminals, each running a different router script in reverse order
osascript -e 'tell application "Terminal" to do script "python3 '"$SCRIPT_PATH"'/router6.py"'
osascript -e 'tell application "Terminal" to do script "python3 '"$SCRIPT_PATH"'/router5.py"'
osascript -e 'tell application "Terminal" to do script "python3 '"$SCRIPT_PATH"'/router4.py"'
osascript -e 'tell application "Terminal" to do script "python3 '"$SCRIPT_PATH"'/router3.py"'
osascript -e 'tell application "Terminal" to do script "python3 '"$SCRIPT_PATH"'/router2.py"'
osascript -e 'tell application "Terminal" to do script "python3 '"$SCRIPT_PATH"'/router1.py"'
