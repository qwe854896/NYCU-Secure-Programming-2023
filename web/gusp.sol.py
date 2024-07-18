import random
import string
from flask import Flask, request, jsonify, redirect
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# A dictionary to store the mapping between aliases and original URLs
url_mapping = {}

@app.route('/api', methods=['POST'])
def shorten_url():
    # Check the Content-Type header
    content_type = request.headers.get('Content-Type')
    if content_type != 'application/gusp':
        return generate_error_response("Invalid Content-Type")

    try:
        data = request.get_data(as_text=True)
        
        # Parse the request body
        alias = None

        parts = data.strip('[gusp]').strip('/gusp]').strip('[').split('|')
        if len(parts) == 4:
            _, length, original, alias = parts
        elif len(parts) == 3:
            _, length, original = parts
        else:
            return generate_error_response("Invalid request body format")
        
        # Check if alias is provided and validate it
        if alias is not None:
            if not is_valid_alias(alias):
                return generate_error_response("Invalid alias format")
            if alias in url_mapping:
                return generate_error_response("Alias already in use")
        else:
            # Generate a unique alias if not provided
            alias = generate_unique_alias()

        # Store the mapping between alias and original URL
        url_mapping[alias] = original

        # Create the response
        return generate_success_response(alias)

    except Exception as e:
        return generate_error_response(str(e))

def generate_success_response(alias):
    response_body = f'[gusp]SUCCESS|{len(alias)}|{alias}[/gusp]'
    response = jsonify(response_body)
    response.headers['Content-Type'] = 'application/gusp'
    return response

def generate_error_response(error_message):
    response_body = f'[gusp]ERROR|{len(error_message)}|{error_message}[/gusp]'
    response = jsonify(response_body)
    response.headers['Content-Type'] = 'application/gusp'
    return response

def is_valid_alias(alias):
    # Check if the alias contains only valid characters
    valid_characters = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    if not set(alias).issubset(valid_characters):
        return False

    return True


def generate_unique_alias():
    while True:
        alias = generate_random_alias()
        if alias not in url_mapping:
            return alias

def generate_random_alias(length=8):
    characters = string.ascii_letters + string.digits + '-_'
    return ''.join(random.choice(characters) for _ in range(length))


@app.route('/api/<alias>', methods=['GET'])
def get_shortened_url(alias):
    if alias in url_mapping:
        original_url = url_mapping[alias]
        response = redirect(original_url, code=302)
        response.headers['Location'] = original_url  # Set the Location header
        return response
    else:
        return "Alias not found", 404


if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)

