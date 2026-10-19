# FastMile Reboot

A small Python utility that logs in to the Nokia FastMile web UI and triggers a
reboot via the Reboot CGI endpoint. It prints the login result, session id,
token, and the reboot request/response details.

## Usage

1. Create a `credentials.txt` file in the project directory with two lines:
   - username
   - password
2. Run:

   ```sh
   python3 reset.py
   ```

## Requirements

- Python 3
- `cryptography` package (`pip install cryptography`)

## Safety

`credentials.txt` is gitignored.