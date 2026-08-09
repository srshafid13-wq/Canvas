document.addEventListener("DOMContentLoaded", () => {

    const video = document.getElementById("preview");

    const cameraBtn = document.getElementById("cameraBtn");
    const micBtn = document.getElementById("micBtn");
    const startBtn = document.querySelector(".start-btn");

    let stream = null;
    let cameraOn = false;
    let micOn = false;

    // CAMERA + MICROPHONE
    async function startMedia() {
        try {
            stream = await navigator.mediaDevices.getUserMedia({
                video: true,
                audio: true
            });

            video.srcObject = stream;

            cameraOn = true;
            micOn = true;

            if (cameraBtn) {
                cameraBtn.classList.add("active");
                cameraBtn.innerHTML = "📷 Camera";
            }

            if (micBtn) {
                micBtn.classList.add("active");
                micBtn.innerHTML = "🎙️ Microphone";
            }

            console.log("Camera and microphone ready.");

        } catch (error) {
            console.error(error);

            alert(
                "Camera or microphone permission was denied. " +
                "Please allow camera and microphone access in your browser."
            );
        }
    }

    // CAMERA BUTTON
    if (cameraBtn) {
        cameraBtn.addEventListener("click", async () => {

            if (!stream) {
                await startMedia();
                return;
            }

            const track = stream.getVideoTracks()[0];

            if (track) {
                cameraOn = !cameraOn;
                track.enabled = cameraOn;

                cameraBtn.classList.toggle("active", cameraOn);
            }
        });
    }

    // MICROPHONE BUTTON
    if (micBtn) {
        micBtn.addEventListener("click", async () => {

            if (!stream) {
                await startMedia();
                return;
            }

            const track = stream.getAudioTracks()[0];

            if (track) {
                micOn = !micOn;
                track.enabled = micOn;

                micBtn.classList.toggle("active", micOn);
            }
        });
    }

    // START STREAMING
    if (startBtn) {
        startBtn.addEventListener("click", async () => {

            if (!stream) {
                await startMedia();
                return;
            }

            if (!cameraOn && !micOn) {
                alert("Turn on your camera or microphone first.");
                return;
            }

            alert(
                "Your camera is ready! " +
                "The streaming backend still needs to be connected."
            );
        });
    }

    // Automatically ask for camera + microphone
    startMedia();

});
