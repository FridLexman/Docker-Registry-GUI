from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import requests
import os

app = Flask(__name__, static_folder='static')
CORS(app)

REGISTRY_URL = os.environ.get('REGISTRY_URL', 'http://localhost:5000')

def get_registry_url():
    return request.args.get('registry_url', REGISTRY_URL).rstrip('/')

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/api/catalog')
def get_catalog():
    """Get list of all repositories in the registry"""
    registry_url = get_registry_url()
    try:
        response = requests.get(
            f'{registry_url}/v2/_catalog',
            timeout=10,
            verify=False
        )
        if response.status_code == 200:
            return jsonify(response.json())
        return jsonify({'error': f'Registry returned status {response.status_code}'}), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/repositories/<path:repo>/tags')
def get_tags(repo):
    """Get all tags for a repository"""
    registry_url = get_registry_url()
    try:
        response = requests.get(
            f'{registry_url}/v2/{repo}/tags/list',
            timeout=10,
            verify=False
        )
        if response.status_code == 200:
            return jsonify(response.json())
        return jsonify({'error': f'Registry returned status {response.status_code}'}), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/repositories/<path:repo>/manifests/<tag>')
def get_manifest(repo, tag):
    """Get manifest for a specific image tag"""
    registry_url = get_registry_url()
    try:
        headers = {
            'Accept': 'application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json'
        }
        response = requests.get(
            f'{registry_url}/v2/{repo}/manifests/{tag}',
            headers=headers,
            timeout=10,
            verify=False
        )
        if response.status_code == 200:
            digest = response.headers.get('Docker-Content-Digest', '')
            data = response.json()
            data['digest'] = digest
            return jsonify(data)
        return jsonify({'error': f'Registry returned status {response.status_code}'}), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/repositories/<path:repo>/manifests/<tag>', methods=['DELETE'])
def delete_manifest(repo, tag):
    """Delete an image by tag (requires registry to have delete enabled)"""
    registry_url = get_registry_url()
    try:
        # First get the digest
        headers = {
            'Accept': 'application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json'
        }
        response = requests.get(
            f'{registry_url}/v2/{repo}/manifests/{tag}',
            headers=headers,
            timeout=10,
            verify=False
        )
        if response.status_code != 200:
            return jsonify({'error': 'Could not get manifest digest'}), 400
        
        digest = response.headers.get('Docker-Content-Digest')
        if not digest:
            return jsonify({'error': 'No digest found in response'}), 400
        
        # Delete by digest
        delete_response = requests.delete(
            f'{registry_url}/v2/{repo}/manifests/{digest}',
            timeout=10,
            verify=False
        )
        if delete_response.status_code in [200, 202]:
            return jsonify({'success': True, 'message': f'Deleted {repo}:{tag}'})
        return jsonify({'error': f'Delete failed with status {delete_response.status_code}'}), delete_response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health')
def health():
    """Check if registry is accessible"""
    registry_url = get_registry_url()
    try:
        response = requests.get(
            f'{registry_url}/v2/',
            timeout=5,
            verify=False
        )
        return jsonify({
            'status': 'ok' if response.status_code == 200 else 'error',
            'registry_url': registry_url,
            'registry_status': response.status_code
        })
    except requests.exceptions.RequestException as e:
        return jsonify({
            'status': 'error',
            'registry_url': registry_url,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    import warnings
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')
    app.run(host='0.0.0.0', port=12000, debug=True)
