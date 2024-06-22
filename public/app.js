let token = '';

function showResult(message) {
    document.getElementById('result').innerText = message;
}

async function register() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const response = await fetch('/register', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username, password})
    });
    const data = await response.json();
    showResult(data.message);
}

async function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const response = await fetch('/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username, password})
    });
    const data = await response.json();
    if (data.token) {
        token = data.token;
        document.getElementById('auth').style.display = 'none';
        document.getElementById('actions').style.display = 'block';
        showResult('Logged in successfully');
    } else {
        showResult('Login failed');
    }
}

async function issueCredential() {
    const response = await fetch('/issue-credential', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({type: 'ExampleCredential', claim: {exampleClaim: 'value'}})
    });
    const data = await response.json();
    showResult('Credential issued: ' + JSON.stringify(data));
}

async function uploadDocument() {
    const title = document.getElementById('docTitle').value;
    const content = document.getElementById('docContent').value;
    const response = await fetch('/upload', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({title, content})
    });
    const data = await response.json();
    showResult(data.message + '. Document ID: ' + data.docId);
}

async function downloadDocument() {
    const id = document.getElementById('docId').value;
    const response = await fetch(`/download/${id}`, {
        headers: {'Authorization': `Bearer ${token}`}
    });
    const data = await response.json();
    showResult(`Title: ${data.title}, Content: ${data.content}`);
}

async function shareDocument() {
    const id = document.getElementById('shareDocId').value;
    const username = document.getElementById('shareUsername').value;
    const response = await fetch(`/share/${id}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({username})
    });
    const data = await response.json();
    showResult(data.message);
}