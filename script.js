async function startCamera() {
    const preview = document.getElementById("preview");

    try {
        const stream = await navigator.mediaDevices.getUserMedia({
            video: true,
            audio: true
        });

        preview.srcObject = stream;
    } catch (error) {
        alert("Camera or microphone permission was denied.");
        console.error(error);
    }
}

window.onload = startCamera;