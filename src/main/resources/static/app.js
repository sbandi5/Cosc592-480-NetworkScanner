async function scanPorts() {
    let target = document.getElementById("scanTarget").value;
    let response = await fetch(`/api/scan-sniff?target=${target}`);
    let result = await response.text();
    document.getElementById("scanResult").innerText = result;
}

async function sniffPackets() {
    let response = await fetch(`/api/sniff`);
    let result = await response.json();
    document.getElementById("sniffResult").innerText = JSON.stringify(result, null, 2);
}

async function runExploit() {
    let target = document.getElementById("exploitTarget").value;
    let response = await fetch(`/api/exploit?target=${target}`, { method: 'POST' });
    let result = await response.text();
    document.getElementById("exploitResult").innerText = result;
}
