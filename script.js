document.addEventListener("DOMContentLoaded", () => {

    // =========================================
    // CANVAS - STREAMING SYSTEM
    // =========================================

    const video = document.getElementById("preview");

    const cameraBtn = document.getElementById("cameraBtn");
    const micBtn = document.getElementById("micBtn");
    const startBtn = document.querySelector(".start-btn");

    let stream = null;
    let cameraOn = false;
    let micOn = false;
    let isStreaming = false;
    let streamId = null;


    // =========================================
    // CANVAS BACKEND
    // =========================================

    const BACKEND_URL = "YOUR_EXISTING_BACKEND_URL";


    // =========================================
    // START CAMERA + MICROPHONE
    // =========================================

    async function startMedia() {

        try {

            stream = await navigator.mediaDevices.getUserMedia({
                video: true,
                audio: true
            });

            if (video) {
                video.srcObject = stream;
                video.muted = true;
                video.play().catch(() => {});
            }

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

            console.log("Canvas camera and microphone ready.");

        } catch (error) {

            console.error("Media permission error:", error);

            alert(
                "Camera or microphone permission was denied. " +
                "Please allow camera and microphone access in your browser."
            );
        }
    }


    // =========================================
    // STOP CAMERA + MICROPHONE
    // =========================================

    function stopMedia() {

        if (stream) {

            stream.getTracks().forEach(track => {
                track.stop();
            });

        }

        stream = null;
        cameraOn = false;
        micOn = false;

        if (video) {
            video.srcObject = null;
        }

        if (cameraBtn) {
            cameraBtn.classList.remove("active");
            cameraBtn.innerHTML = "📷 Camera";
        }

        if (micBtn) {
            micBtn.classList.remove("active");
            micBtn.innerHTML = "🎙️ Microphone";
        }
    }


    // =========================================
    // CAMERA BUTTON
    // =========================================

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

                cameraBtn.classList.toggle(
                    "active",
                    cameraOn
                );

                cameraBtn.innerHTML =
                    cameraOn
                        ? "📷 Camera"
                        : "📷 Camera Off";
            }
        });
    }


    // =========================================
    // MICROPHONE BUTTON
    // =========================================

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

                micBtn.classList.toggle(
                    "active",
                    micOn
                );

                micBtn.innerHTML =
                    micOn
                        ? "🎙️ Microphone"
                        : "🎙️ Microphone Off";
            }
        });
    }


    // =========================================
    // START STREAMING
    // =========================================

    async function startStreaming() {

        if (!stream) {
            await startMedia();
        }

        if (!stream) {
            return;
        }

        if (!cameraOn && !micOn) {

            alert(
                "Turn on your camera or microphone first."
            );

            return;
        }

        if (isStreaming) {
            return;
        }

        try {

            startBtn.disabled = true;
            startBtn.innerHTML = "Starting...";


            // =====================================
            // CONTACT CANVAS BACKEND
            // =====================================

            const response = await fetch(
                `${BACKEND_URL}/api/streams/start`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type": "application/json"
                    },

                    body: JSON.stringify({
                        title: "Canvas Live Stream"
                    })
                }
            );


            const data = await response.json();


            if (!response.ok) {

                throw new Error(
                    data.message ||
                    "Unable to start stream."
                );
            }


            // =====================================
            // STREAM CREATED
            // =====================================

            streamId =
                data.streamId ||
                data.id ||
                null;

            isStreaming = true;


            console.log(
                "Canvas stream started:",
                data
            );


            // Change button to STOP

            startBtn.disabled = false;

            startBtn.innerHTML =
                "⏹ Stop Streaming";

            startBtn.classList.add("live");


        } catch (error) {

            console.error(
                "Canvas streaming error:",
                error
            );

            startBtn.disabled = false;

            startBtn.innerHTML =
                "Start Streaming";

            alert(
                "Could not connect to the Canvas streaming server."
            );
        }
    }


    // =========================================
    // STOP STREAMING
    // =========================================

    async function stopStreaming() {

        if (!isStreaming) {
            return;
        }

        try {

            startBtn.disabled = true;

            startBtn.innerHTML =
                "Stopping...";


            // =====================================
            // TELL CANVAS BACKEND TO STOP STREAM
            // =====================================

            const response = await fetch(
                `${BACKEND_URL}/api/streams/stop`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type": "application/json"
                    },

                    body: JSON.stringify({
                        streamId: streamId
                    })
                }
            );


            const data = await response.json();


            if (!response.ok) {

                throw new Error(
                    data.message ||
                    "Unable to stop stream."
                );
            }


            console.log(
                "Canvas stream stopped:",
                data
            );


            // =====================================
            // RESET STREAMING STATE
            // =====================================

            isStreaming = false;
            streamId = null;


            stopMedia();


            startBtn.disabled = false;

            startBtn.innerHTML =
                "Start Streaming";

            startBtn.classList.remove("live");


            alert(
                "Your Canvas stream has ended."
            );


        } catch (error) {

            console.error(
                "Canvas stop-stream error:",
                error
            );

            startBtn.disabled = false;

            startBtn.innerHTML =
                "⏹ Stop Streaming";


            alert(
                "Could not stop the stream on the Canvas server."
            );
        }
    }


    // =========================================
    // START / STOP BUTTON
    // =========================================

    if (startBtn) {

        startBtn.addEventListener(
            "click",
            async () => {

                if (isStreaming) {

                    await stopStreaming();

                } else {

                    await startStreaming();

                }

            }
        );
    }


    // =========================================
    // PAGE EXIT / CLEANUP
    // =========================================

    window.addEventListener(
        "beforeunload",
        () => {

            if (stream) {

                stream.getTracks().forEach(track => {
                    track.stop();
                });

            }

        }
    );


    // =========================================
    // AUTOMATIC CAMERA + MICROPHONE
    // =========================================

    startMedia();

});
