document.addEventListener("DOMContentLoaded", () => {

    // =========================================
    // CANVAS - STREAMING SYSTEM
    // =========================================

    const video =
        document.getElementById("preview");

    const cameraBtn =
        document.getElementById("cameraBtn");

    const micBtn =
        document.getElementById("micBtn");

    const startBtn =
        document.querySelector(".start-btn");


    let stream = null;
    let cameraOn = false;
    let micOn = false;
    let isStreaming = false;
    let streamId = null;


    // =========================================
    // CANVAS BACKEND
    // =========================================

    const BACKEND_URL =
        "https://canvas-kh9p.onrender.com";


    // =========================================
    // START CAMERA + MICROPHONE
    // =========================================

    async function startMedia() {

        try {

            if (
                !navigator.mediaDevices ||
                !navigator.mediaDevices.getUserMedia
            ) {

                alert(
                    "Camera and microphone are not supported by this browser."
                );

                return;

            }


            stream =
                await navigator.mediaDevices.getUserMedia({

                    video: true,

                    audio: true

                });


            if (video) {

                video.srcObject =
                    stream;

                video.muted =
                    true;

                video.playsInline =
                    true;

                video.play().catch(
                    () => {}
                );

            }


            cameraOn =
                stream.getVideoTracks().length > 0;

            micOn =
                stream.getAudioTracks().length > 0;


            updateCameraButton();

            updateMicButton();


            console.log(
                "Canvas camera and microphone ready."
            );


        } catch (error) {

            console.error(
                "Media permission error:",
                error
            );


            stream = null;

            cameraOn = false;

            micOn = false;


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

            stream
                .getTracks()
                .forEach(track => {

                    track.stop();

                });

        }


        stream = null;

        cameraOn = false;

        micOn = false;


        if (video) {

            video.srcObject = null;

        }


        updateCameraButton();

        updateMicButton();

    }


    // =========================================
    // UPDATE CAMERA BUTTON
    // =========================================

    function updateCameraButton() {

        if (!cameraBtn) {

            return;

        }


        cameraBtn.classList.toggle(
            "active",
            cameraOn
        );


        cameraBtn.innerHTML =
            cameraOn
                ? "📷 Camera"
                : "📷 Camera Off";

    }


    // =========================================
    // UPDATE MICROPHONE BUTTON
    // =========================================

    function updateMicButton() {

        if (!micBtn) {

            return;

        }


        micBtn.classList.toggle(
            "active",
            micOn
        );


        micBtn.innerHTML =
            micOn
                ? "🎙️ Microphone"
                : "🎙️ Microphone Off";

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


                if (!track) {

                    return;

                }


                cameraOn =
                    !cameraOn;


                track.enabled =
                    cameraOn;


                updateCameraButton();

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


                if (!track) {

                    return;

                }


                micOn =
                    !micOn;


                track.enabled =
                    micOn;


                updateMicButton();

            }
        );

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

            if (startBtn) {

                startBtn.disabled =
                    true;

                startBtn.innerHTML =
                    "Starting...";

            }


            // =====================================
            // CREATE STREAM ON CANVAS SERVER
            // =====================================

            const response =
                await fetch(

                    `${BACKEND_URL}/api/streams/start`,

                    {

                        method:
                            "POST",

                        headers: {

                            "Content-Type":
                                "application/json"

                        },

                        body:
                            JSON.stringify({

                                title:
                                    "Canvas Live Stream"

                            })

                    }

                );


            const data =
                await response.json();


            if (!response.ok) {

                throw new Error(

                    data.message ||
                    "Unable to start stream."

                );

            }


            // =====================================
            // GET STREAM ID
            // =====================================

            streamId =
                data.streamId ||
                data.id ||
                (
                    data.stream &&
                    data.stream.id
                ) ||
                null;


            if (!streamId) {

                throw new Error(
                    "Canvas server did not return a stream ID."
                );

            }


            isStreaming =
                true;


            console.log(
                "Canvas stream started:",
                data
            );


            // =====================================
            // CHANGE BUTTON TO STOP
            // =====================================

            if (startBtn) {

                startBtn.disabled =
                    false;

                startBtn.innerHTML =
                    "⏹ Stop Streaming";

                startBtn.classList.add(
                    "live"
                );

            }


        } catch (error) {

            console.error(
                "Canvas streaming error:",
                error
            );


            isStreaming =
                false;

            streamId =
                null;


            if (startBtn) {

                startBtn.disabled =
                    false;

                startBtn.innerHTML =
                    "Start Streaming";

                startBtn.classList.remove(
                    "live"
                );

            }


            alert(
                error.message ||
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


        if (!streamId) {

            console.error(
                "No stream ID available."
            );


            stopMedia();

            isStreaming =
                false;

            return;

        }


        try {

            if (startBtn) {

                startBtn.disabled =
                    true;

                startBtn.innerHTML =
                    "Stopping...";

            }


            // =====================================
            // END STREAM ON CANVAS SERVER
            // =====================================

            const response =
                await fetch(

                    `${BACKEND_URL}/api/streams/stop`,

                    {

                        method:
                            "POST",

                        headers: {

                            "Content-Type":
                                "application/json"

                        },

                        body:
                            JSON.stringify({

                                streamId:
                                    streamId

                            })

                    }

                );


            const data =
                await response.json();


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

            isStreaming =
                false;

            streamId =
                null;


            stopMedia();


            if (startBtn) {

                startBtn.disabled =
                    false;

                startBtn.innerHTML =
                    "Start Streaming";

                startBtn.classList.remove(
                    "live"
                );

            }


            alert(
                "Your Canvas stream has ended."
            );


        } catch (error) {

            console.error(
                "Canvas stop-stream error:",
                error
            );


            if (startBtn) {

                startBtn.disabled =
                    false;

                startBtn.innerHTML =
                    "⏹ Stop Streaming";

            }


            alert(
                error.message ||
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

                stream
                    .getTracks()
                    .forEach(track => {

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
