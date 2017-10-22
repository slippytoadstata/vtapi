# vtapi
Simple Virus Total API

## Demo:

![demo_vtapi](https://media.giphy.com/media/d47I0oxXsBpRlg40/giphy.gif)

## Requirements:
+ API Key VirusTotal
+ requests  `pip install requests`

## Use:
Add key API:
```python
# API/virustotal.py
# line:17
self.apikey = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
```
Start test:
```bash
python vtapi.py -f test.bat
```
or
```bash
python vtapi.py -u https://google.com/
```
