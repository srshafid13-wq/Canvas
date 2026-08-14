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


            // CAMERA BUTTON

            if (cameraBtn) {

                cameraBtn.classList.add("active");

                cameraBtn.innerHTML = "📷 Camera";
            }


            // MICROPHONE BUTTON

            if (micBtn) {

                micBtn.classList.add("active");

                micBtn.innerHTML = "🎙️ Microphone";
            }


            console.log(
                "Canvas camera and microphone ready."
            );

        } catch (error) {

            console.error(
                "Media permission error:",
                error
            );

            alert(
                "Camera or microphone permission was denied. " +
                "Please allow camera and microphone access in your browser."
            );
        }
    }


    // =========================================
    // CAMERA BUTTON
    // =========================================

    if (cameraBtn) {

        cameraBtn.addEventListener(
            "click",
            async () => {

                if (!stream) {

                    await startMedia();

                    return;
                }


                const track =
                    stream.getVideoTracks()[0];


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

            }
        );
    }


    // =========================================
    // MICROPHONE BUTTON
    // =========================================

    if (micBtn) {

        micBtn.addEventListener(
            "click",
            async () => {

                if (!stream) {

                    await startMedia();

                    return;
                }


                const track =
                    stream.getAudioTracks()[0];


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

            }
        );
    }


    // =========================================
    // START STREAMING
    // =========================================

    if (startBtn) {

        startBtn.addEventListener(
            "click",
            async () => {

                // Make sure camera/mic exists

                if (!stream) {

                    await startMedia();

                    return;
                }


                // Require at least one media source

                if (!cameraOn && !micOn) {

                    alert(
                        "Turn on your camera or microphone first."
                    );

                    return;
                }


                // Prevent duplicate streams

                if (isStreaming) {

                    return;
                }


                try {

                    startBtn.disabled = true;

                    startBtn.innerHTML =
                        "Starting...";


                    // =================================
                    // CONNECT TO CANVAS BACKEND
                    // =================================

                    const response = await fetch(
                        `${BACKEND_URL}/api/streams/start`,
                        {
                            method: "POST",

                            headers: {
                                "Content-Type":
                                    "application/json"
                            },

                            body: JSON.stringify({

                                title:
                                    "Canvas Live Stream"

                            })
                        }
                    );


                    const data =
                        await response.json();


                    // Backend returned an error

                    if (!response.ok) {

                        throw new Error(
                            data.message ||
                            "Unable to start stream."
                        );
                    }


                    // =================================
                    // STREAM CREATED
                    // =================================

                    isStreaming = true;


                    streamId =
                        data.streamId ||
                        data.id ||
                        null;


                    console.log(
                        "Canvas stream started:",
                        data
                    );


                    startBtn.innerHTML =
                        "🔴 Live";


                    alert(
                        "Your Canvas stream has started!"
                    );


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
        );
    }


    // =========================================
    // PAGE EXIT / CLEANUP
    // =========================================

    window.addEventListener(
        "beforeunload",
        () => {

            if (stream) {

                stream
                    .getTracks()
                    .forEach(track => {
                        track.stop();
                    });
            }

        }
    );


    // =========================================
    // AUTOMATICALLY REQUEST CAMERA + MIC
    // =========================================

    startMedia();

});
