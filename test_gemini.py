import urllib.request
import json
import traceback

def test():
    import urllib.request
    import json
    
    url = 'https://generativelanguage.googleapis.com/v1beta/models?key=AIzaSyDNZQ9LoNXh9RaUyRwZls-twlhgBw0PpOs'
    
    req = urllib.request.Request(
        url,
        method='GET'
    )
    
    try:
        with urllib.request.urlopen(req) as res:
            print("SUCCESS ListModels:")
            data = json.loads(res.read().decode('utf-8'))
            models = [m['name'] for m in data.get('models', [])]
            print("Available models:", models)
    except Exception as e:
        print("FAILED ListModels:", e)
        if hasattr(e, 'read'):
            print("  Response:", e.read().decode('utf-8'))

if __name__ == '__main__':
    test()

if __name__ == '__main__':
    test()
