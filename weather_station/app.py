from flask import Flask, request

app = Flask(__name__)

@app.route('/readfile/location.txt', methods=['GET'])
def get_location():
    try:
        with open('location.txt', 'r', encoding='utf-8') as file:
            content = file.read()
            return content, 200  # Explicitly return 200 status code
    except FileNotFoundError:
        return "File not found", 404
    except UnicodeDecodeError:
        return "Unicode Decode Error", 500

@app.route('/weather', methods=['POST'])
def post_weather():
    data = request.data  # Get raw data
    try:
        decoded_data = data.decode('utf-8')  # Try to decode as UTF-8
    except UnicodeDecodeError:
        decoded_data = data.decode('latin-1')  # Fallback to latin-1 if UTF-8 fails
    
    decoded_data = decoded_data.replace('\\n', '\n')  # Replace literal '\n' with newline
    print(decoded_data)  # For demonstration
    return "Data received", 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1234)
